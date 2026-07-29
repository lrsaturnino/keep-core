package participation

import (
	"encoding/json"
	"math/big"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/keep-network/keep-core/pkg/protocol/group"
)

// recordingRegistry captures what the production registration path registers,
// so a test reads back exactly the source names and payloads a diagnostics
// scrape would.
type recordingRegistry struct {
	sources map[string]func() string
	order   []string
}

func newRecordingRegistry() *recordingRegistry {
	return &recordingRegistry{sources: make(map[string]func() string)}
}

func (r *recordingRegistry) RegisterDiagnosticSource(
	name string,
	source func() string,
) {
	if _, seen := r.sources[name]; !seen {
		r.order = append(r.order, name)
	}
	r.sources[name] = source
}

// scrape invokes the named source the way the client-info server does and
// decodes its JSON object.
func (r *recordingRegistry) scrape(
	t *testing.T,
	name string,
) map[string]interface{} {
	t.Helper()

	source, ok := r.sources[name]
	if !ok {
		t.Fatalf(
			"diagnostics source [%v] was never registered; registered: %v",
			name,
			r.order,
		)
	}

	raw := source()
	if raw == "" {
		t.Fatalf("diagnostics source [%v] produced an empty payload", name)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf(
			"diagnostics source [%v] produced undecodable JSON [%v]: [%v]",
			name,
			raw,
			err,
		)
	}

	return decoded
}

// stubChainIdentity stands in for the connected chain handle. It counts reads
// so a test can prove the emitted chain id comes from the connected endpoint
// on every scrape rather than from a value captured elsewhere.
type stubChainIdentity struct {
	chainID *big.Int
	reads   int
}

func (s *stubChainIdentity) ChainID() *big.Int {
	s.reads++
	if s.chainID == nil {
		return nil
	}
	return new(big.Int).Set(s.chainID)
}

func TestRegisterDiagnosticSources_RegistersBothSources(t *testing.T) {
	gate, _, _ := newTestGate(
		t,
		Schedule{CutoverBlock: 1000},
		900,
		inertPollInterval,
	)
	roster, _, _ := newTestRoster(t, 900, 100)
	registry := newRecordingRegistry()

	RegisterDiagnosticSources(
		registry,
		gate,
		roster,
		&stubChainIdentity{chainID: big.NewInt(1)},
		"release_baked",
	)

	registered := append([]string(nil), registry.order...)
	sort.Strings(registered)

	expected := []string{
		DiagnosticsSourceCutoverLegacyPeers,
		DiagnosticsSourceProtocolParticipation,
	}
	if !reflect.DeepEqual(registered, expected) {
		t.Errorf(
			"unexpected diagnostics sources\nactual:   %v\nexpected: %v",
			registered,
			expected,
		)
	}
}

func TestRegisterDiagnosticSources_EmitsConnectedChainID(t *testing.T) {
	// A chain id that no configuration default and no test schedule value
	// could coincidentally produce, so the assertion can only pass if the
	// emitted value was read from the connected chain handle.
	const connectedChainID = 424242

	gate, _, _ := newTestGate(
		t,
		Schedule{CutoverBlock: 1000},
		900,
		inertPollInterval,
	)
	roster, _, _ := newTestRoster(t, 900, 100)
	chainIdentity := &stubChainIdentity{
		chainID: big.NewInt(connectedChainID),
	}
	registry := newRecordingRegistry()

	RegisterDiagnosticSources(
		registry,
		gate,
		roster,
		chainIdentity,
		"release_baked",
	)

	decoded := registry.scrape(t, DiagnosticsSourceProtocolParticipation)

	actual, ok := decoded["ethereum_chain_id"]
	if !ok {
		t.Fatalf(
			"participation diagnostics omit the connected chain id: %v",
			decoded,
		)
	}
	if actual != "424242" {
		t.Errorf(
			"unexpected chain id\nactual:   %v\nexpected: %v",
			actual,
			"424242",
		)
	}
	if chainIdentity.reads == 0 {
		t.Errorf("the connected chain handle was never read")
	}
}

func TestRegisterDiagnosticSources_RereadsChainIDPerScrape(t *testing.T) {
	gate, _, _ := newTestGate(
		t,
		Schedule{CutoverBlock: 1000},
		900,
		inertPollInterval,
	)
	roster, _, _ := newTestRoster(t, 900, 100)
	chainIdentity := &stubChainIdentity{chainID: big.NewInt(11155111)}
	registry := newRecordingRegistry()

	RegisterDiagnosticSources(
		registry,
		gate,
		roster,
		chainIdentity,
		"non_mainnet_override",
	)

	registry.scrape(t, DiagnosticsSourceProtocolParticipation)
	firstReads := chainIdentity.reads

	registry.scrape(t, DiagnosticsSourceProtocolParticipation)
	if chainIdentity.reads <= firstReads {
		t.Errorf(
			"the chain id was captured once instead of read per scrape "+
				"[reads after first scrape=%v] [reads after second=%v]",
			firstReads,
			chainIdentity.reads,
		)
	}
}

func TestRegisterDiagnosticSources_RefusesPayloadWithoutChainID(t *testing.T) {
	gate, _, _ := newTestGate(
		t,
		Schedule{CutoverBlock: 1000},
		900,
		inertPollInterval,
	)
	roster, _, _ := newTestRoster(t, 900, 100)
	registry := newRecordingRegistry()

	RegisterDiagnosticSources(
		registry,
		gate,
		roster,
		&stubChainIdentity{chainID: nil},
		"release_baked",
	)

	// A payload that silently dropped the chain id would still decode and
	// would read as a healthy scrape, so the source refuses to compose one.
	if payload := registry.sources[DiagnosticsSourceProtocolParticipation](); payload != "" {
		t.Errorf(
			"participation diagnostics were composed without a chain id: %v",
			payload,
		)
	}
}

func TestRegisterDiagnosticSources_EmitsGateStateContract(t *testing.T) {
	gate, blockCounter, _ := newTestGate(
		t,
		Schedule{CutoverBlock: 1000},
		1200,
		inertPollInterval,
	)
	roster, _, _ := newTestRoster(t, 1200, 100)
	registry := newRecordingRegistry()

	RegisterDiagnosticSources(
		registry,
		gate,
		roster,
		&stubChainIdentity{chainID: big.NewInt(1)},
		"release_baked",
	)

	// Hold one live security-v2 permit so the active counters describe real
	// gate state rather than an idle zero that any broken payload would match.
	// It is identity-bound because the emitted permit list is only useful to an
	// observer if it names the work each permit was issued for.
	permit, err := gate.Begin(
		TBTCSigning,
		1100,
		PermitIdentity{WorkID: strings.Repeat("a", 64), PermitID: "1"},
	)
	if err != nil {
		t.Fatalf("failed to begin a ceremony: [%v]", err)
	}
	defer permit.Close()

	decoded := registry.scrape(t, DiagnosticsSourceProtocolParticipation)

	snapshot := gate.State()
	expected := map[string]interface{}{
		"protocol_epoch":                CompiledEpoch.String(),
		"ethereum_chain_id":             "1",
		"cutover_block":                 float64(snapshot.CutoverBlock),
		"cutover_block_source":          "release_baked",
		"gate_state":                    snapshot.State.String(),
		"current_block":                 float64(snapshot.CurrentBlock),
		"clock_available":               snapshot.ClockAvailable,
		"allowed":                       snapshot.Allowed,
		"quiescing":                     snapshot.Quiescing,
		"active_ceremonies":             float64(snapshot.ActiveCeremonies),
		"active_legacy_ceremonies":      float64(snapshot.ActiveLegacyCeremonies),
		"active_security_v2_ceremonies": float64(snapshot.ActiveSecurityV2Ceremonies),
		"active_permits": []interface{}{
			map[string]interface{}{
				"ceremony":              string(TBTCSigning),
				"mode":                  ModeSecurityV2.String(),
				"canonical_start_block": float64(1100),
				"work_id":               strings.Repeat("a", 64),
				"permit_id":             "1",
				"identity_bound":        true,
			},
		},
		"recent_terminal_outcomes": []interface{}{},
	}

	if !reflect.DeepEqual(decoded, expected) {
		t.Errorf(
			"unexpected participation diagnostics\nactual:   %v\nexpected: %v",
			decoded,
			expected,
		)
	}

	// The held permit must be visible; a payload hard-coding zeros would
	// otherwise satisfy the comparison above on an idle gate.
	if snapshot.ActiveSecurityV2Ceremonies != 1 {
		t.Errorf(
			"unexpected active security-v2 ceremonies\n"+
				"actual:   %v\nexpected: %v",
			snapshot.ActiveSecurityV2Ceremonies,
			1,
		)
	}

	// Guard the chain-clock field against a stale capture the same way the
	// chain id is guarded: it must follow the counter the gate reads.
	blockCounter.set(1300, nil)
	if _, err := gate.Begin(TBTCHeartbeat, 1250); err != nil {
		t.Fatalf("failed to begin a second ceremony: [%v]", err)
	}
	if current := registry.scrape(
		t,
		DiagnosticsSourceProtocolParticipation,
	)["current_block"]; current != float64(1300) {
		t.Errorf(
			"unexpected current block\nactual:   %v\nexpected: %v",
			current,
			float64(1300),
		)
	}
}

// TestRegisterDiagnosticSources_NamesWhatBecameOfClosedPermits asserts a scrape
// can follow a permit past the point it stops being held.
//
// The held-permit list names work while the node has it. The moment the work
// finishes, the permit leaves that list and the scrape says nothing further —
// so an observer watching work cross the cutover can see it held and then has
// to take some other party's report for how it ended. A report about a ceremony
// is not evidence about a ceremony. The emitted record is the node's own, and
// carries the same permit identity the held list does, so the two readings join.
func TestRegisterDiagnosticSources_NamesWhatBecameOfClosedPermits(t *testing.T) {
	gate, _, _ := newTestGate(
		t,
		Schedule{CutoverBlock: 1000},
		1200,
		inertPollInterval,
	)
	roster, _, _ := newTestRoster(t, 1200, 100)
	registry := newRecordingRegistry()

	RegisterDiagnosticSources(
		registry,
		gate,
		roster,
		&stubChainIdentity{chainID: big.NewInt(1)},
		"release_baked",
	)

	permit, err := gate.Begin(
		TBTCSigning,
		1100,
		PermitIdentity{WorkID: strings.Repeat("a", 64), PermitID: "1"},
	)
	if err != nil {
		t.Fatalf("failed to begin a ceremony: [%v]", err)
	}
	if err := permit.RecordTerminalOutcome(
		TerminalOutcomeCompleted,
		TerminalEvidence{
			Kind:      TerminalEvidenceBitcoinTransaction,
			Reference: "signed-transaction-hash",
			Contribution: &TranscriptContribution{
				IncorporatedMembers: []group.MemberIndex{1, 4, 9},
				LocalMembers:        []group.MemberIndex{4},
			},
		},
	); err != nil {
		t.Fatalf("failed to record a terminal outcome: [%v]", err)
	}
	permit.Close()

	decoded := registry.scrape(t, DiagnosticsSourceProtocolParticipation)

	if held, _ := decoded["active_permits"].([]interface{}); len(held) != 0 {
		t.Fatalf("a closed permit is still emitted as held: %v", held)
	}

	outcomes, _ := decoded["recent_terminal_outcomes"].([]interface{})
	if len(outcomes) != 1 {
		t.Fatalf(
			"expected the closed permit to be accounted for, got: %v",
			decoded["recent_terminal_outcomes"],
		)
	}
	record, _ := outcomes[0].(map[string]interface{})
	if record["outcome"] != string(TerminalOutcomeCompleted) {
		t.Errorf("unexpected emitted outcome: %v", record["outcome"])
	}

	// The permit identity is the join to the held reading; a disposition that
	// named no permit would say only that something somewhere finished.
	emittedPermit, _ := record["permit"].(map[string]interface{})
	if emittedPermit["work_id"] != strings.Repeat("a", 64) ||
		emittedPermit["permit_id"] != "1" ||
		emittedPermit["ceremony"] != string(TBTCSigning) ||
		emittedPermit["mode"] != ModeSecurityV2.String() {
		t.Errorf("the closed permit is not identified: %v", record["permit"])
	}

	evidence, _ := record["evidence"].(map[string]interface{})
	if evidence["kind"] != string(TerminalEvidenceBitcoinTransaction) ||
		evidence["reference"] != "signed-transaction-hash" {
		t.Errorf("the owner's evidence is not emitted: %v", record["evidence"])
	}

	// Who was in the transcript, and which of them this node was. Without both
	// lists a scrape can see that a result exists and that this node recorded
	// it, and still cannot tell a ceremony several parties produced together
	// from one this node produced alone — which is the entire question a
	// mixed-release reading asks.
	contribution, _ := evidence["contribution"].(map[string]interface{})
	if !emittedMemberIndexesEqual(
		contribution["incorporated_members"],
		[]group.MemberIndex{1, 4, 9},
	) || !emittedMemberIndexesEqual(
		contribution["local_members"],
		[]group.MemberIndex{4},
	) {
		t.Errorf(
			"the transcript behind the result is not emitted: %v",
			evidence["contribution"],
		)
	}
}

// emittedMemberIndexesEqual reports whether a decoded JSON member-index list
// holds exactly the expected indexes in order. JSON numbers decode as float64,
// so the comparison has to go through the emitted representation rather than
// through the typed slice the gate was given.
func emittedMemberIndexesEqual(
	emitted interface{},
	expected []group.MemberIndex,
) bool {
	indexes, ok := emitted.([]interface{})
	if !ok || len(indexes) != len(expected) {
		return false
	}
	for i, index := range indexes {
		number, ok := index.(float64)
		if !ok || group.MemberIndex(number) != expected[i] {
			return false
		}
	}

	return true
}

// The emitted permit list is what lets an observer name the work a node is
// holding rather than compare fleet-wide totals, and totals are precisely what
// cannot distinguish two permits on opposite sides of the cutover from any
// other pair.
func TestRegisterDiagnosticSources_NamesEachHeldPermit(t *testing.T) {
	gate, _, _ := newTestGate(
		t,
		Schedule{CutoverBlock: 1000},
		1200,
		inertPollInterval,
	)
	roster, _, _ := newTestRoster(t, 1200, 100)
	registry := newRecordingRegistry()

	RegisterDiagnosticSources(
		registry,
		gate,
		roster,
		&stubChainIdentity{chainID: big.NewInt(1)},
		"release_baked",
	)

	// An idle gate emits an empty array rather than a null. A scrape that
	// cannot tell "this node holds nothing" from "this build has no such
	// field" would read a missing contract as an idle node.
	idle := registry.scrape(t, DiagnosticsSourceProtocolParticipation)
	held, ok := idle["active_permits"].([]interface{})
	if !ok || len(held) != 0 {
		t.Fatalf(
			"unexpected idle permit list\nactual:   %#v\nexpected: []",
			idle["active_permits"],
		)
	}

	legacyWorkID := strings.Repeat("b", 64)
	securityWorkID := strings.Repeat("c", 64)

	// One permit anchored below the cutover and one above it, held at the same
	// time. Their count is what any other pair of permits would produce; only
	// the identities say which side of C each one was issued on.
	legacy, err := gate.Begin(
		TBTCSigning,
		900,
		PermitIdentity{WorkID: legacyWorkID, PermitID: "1"},
	)
	if err != nil {
		t.Fatalf("failed to begin the legacy-anchored ceremony: [%v]", err)
	}
	defer legacy.Close()

	securityV2, err := gate.Begin(
		BeaconDKG,
		1100,
		PermitIdentity{WorkID: securityWorkID, PermitID: "2"},
	)
	if err != nil {
		t.Fatalf("failed to begin the security-v2 ceremony: [%v]", err)
	}
	defer securityV2.Close()

	decoded := registry.scrape(t, DiagnosticsSourceProtocolParticipation)
	emitted, ok := decoded["active_permits"].([]interface{})
	if !ok || len(emitted) != 2 {
		t.Fatalf(
			"unexpected permit list\nactual:   %#v\nexpected: 2 permits",
			decoded["active_permits"],
		)
	}

	modes := make(map[string]string, len(emitted))
	anchors := make(map[string]float64, len(emitted))
	for _, entry := range emitted {
		permit, ok := entry.(map[string]interface{})
		if !ok {
			t.Fatalf("unexpected permit entry: %#v", entry)
		}
		workID, _ := permit["work_id"].(string)
		modes[workID], _ = permit["mode"].(string)
		anchors[workID], _ = permit["canonical_start_block"].(float64)
	}

	expectedModes := map[string]string{
		legacyWorkID:   ModeLegacy.String(),
		securityWorkID: ModeSecurityV2.String(),
	}
	if !reflect.DeepEqual(modes, expectedModes) {
		t.Errorf(
			"unexpected permit modes\nactual:   %v\nexpected: %v",
			modes,
			expectedModes,
		)
	}

	expectedAnchors := map[string]float64{
		legacyWorkID:   float64(900),
		securityWorkID: float64(1100),
	}
	if !reflect.DeepEqual(anchors, expectedAnchors) {
		t.Errorf(
			"unexpected permit anchors\nactual:   %v\nexpected: %v",
			anchors,
			expectedAnchors,
		)
	}

	// A closed permit leaves the list, so an observer reading it after the
	// crossing sees what is still held rather than everything ever issued.
	legacy.Close()

	after := registry.scrape(t, DiagnosticsSourceProtocolParticipation)
	remaining, ok := after["active_permits"].([]interface{})
	if !ok || len(remaining) != 1 {
		t.Fatalf(
			"unexpected permit list after close\nactual:   %#v\n"+
				"expected: 1 permit",
			after["active_permits"],
		)
	}
	if permit, ok := remaining[0].(map[string]interface{}); !ok ||
		permit["work_id"] != securityWorkID {
		t.Errorf(
			"unexpected surviving permit\nactual:   %#v\nexpected: %v",
			remaining[0],
			securityWorkID,
		)
	}
}

func TestRegisterDiagnosticSources_EmitsRosterSnapshot(t *testing.T) {
	gate, _, _ := newTestGate(
		t,
		Schedule{CutoverBlock: 1000},
		900,
		inertPollInterval,
	)
	roster, _, _ := newTestRoster(t, 900, 100)
	registry := newRecordingRegistry()

	RegisterDiagnosticSources(
		registry,
		gate,
		roster,
		&stubChainIdentity{chainID: big.NewInt(1)},
		"release_baked",
	)

	observeStraggler(roster, "protocol-1", 1, validAddress(1))

	decoded := registry.scrape(t, DiagnosticsSourceCutoverLegacyPeers)

	peers, ok := decoded["peers"].([]interface{})
	if !ok {
		t.Fatalf("roster diagnostics omit the peer list: %v", decoded)
	}
	if len(peers) != 1 {
		t.Fatalf(
			"unexpected observed peer count\nactual:   %v\nexpected: %v",
			len(peers),
			1,
		)
	}

	// The snapshot must be re-taken per scrape; a captured one would keep
	// reporting the roster as it stood at registration.
	observeStraggler(roster, "protocol-2", 2, validAddress(2))

	peers, ok = registry.scrape(
		t,
		DiagnosticsSourceCutoverLegacyPeers,
	)["peers"].([]interface{})
	if !ok {
		t.Fatalf("roster diagnostics omit the peer list on re-scrape")
	}
	if len(peers) != 2 {
		t.Errorf(
			"unexpected observed peer count after a new sighting\n"+
				"actual:   %v\nexpected: %v",
			len(peers),
			2,
		)
	}
}
