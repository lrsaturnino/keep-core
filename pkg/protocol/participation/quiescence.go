package participation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"time"
)

const (
	// QuiescenceSnapshotSchemaVersion is the schema of the node-authored gate
	// snapshot persisted at the quiescence transition.
	QuiescenceSnapshotSchemaVersion = uint32(1)

	// QuiescenceSnapshotStorageDirectory and
	// QuiescenceSnapshotStorageFile identify the record inside the encrypted
	// work/participation persistence namespace. The rollback audit reads this
	// exact record from the stopped node's storage snapshot.
	QuiescenceSnapshotStorageDirectory = "quiescence"
	QuiescenceSnapshotStorageFile      = "gate-snapshot.json"
)

// PermitIdentity binds one local permit to the chain-native work it performs
// and to the stable local membership or action identity that owns it. Neither
// component may contain raw seeds, messages, session IDs, keys, hostnames, or
// network addresses.
type PermitIdentity struct {
	WorkID   string `json:"work_id"`
	PermitID string `json:"permit_id"`
}

const maxPermitIdentityComponentLength = 256

func validatePermitIdentity(identity PermitIdentity) error {
	for _, component := range []struct {
		name  string
		value string
	}{
		{name: "work ID", value: identity.WorkID},
		{name: "permit ID", value: identity.PermitID},
	} {
		name := component.name
		value := component.value
		if value == "" {
			return fmt.Errorf("%s is empty", name)
		}
		if len(value) > maxPermitIdentityComponentLength {
			return fmt.Errorf(
				"%s exceeds [%d] bytes",
				name,
				maxPermitIdentityComponentLength,
			)
		}
		for i, character := range []byte(value) {
			if (character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') ||
				(i > 0 && (character == '_' ||
					character == '.' ||
					character == ':' ||
					character == '-')) {
				continue
			}
			return fmt.Errorf(
				"%s contains an unsupported character at byte [%d]",
				name,
				i,
			)
		}
	}

	return nil
}

// PermitSnapshot is the immutable, nonsecret identity and cutover
// classification of one live permit.
type PermitSnapshot struct {
	Ceremony            Ceremony `json:"ceremony"`
	Mode                string   `json:"mode"`
	CanonicalStartBlock uint64   `json:"canonical_start_block"`
	WorkID              string   `json:"work_id"`
	PermitID            string   `json:"permit_id"`
	// IdentityBound is true only when the ceremony owner supplied the
	// chain-work and local-permit identity at issuance. The source-compatible
	// unbound path exists only for test gates without a persistence recorder;
	// production issuance and the rollback audit both refuse it.
	IdentityBound bool `json:"identity_bound"`
}

// QuiescenceSnapshot is the node-authored, immutable record captured under
// the gate lock at the instant the first Quiesce call makes the transition.
// It binds the real active-permit registry to the exact artifact and one-value
// cutover schedule that were running. Later terminal outcomes are external
// reconciliation data; they must cover this inventory one-to-one.
type QuiescenceSnapshot struct {
	SchemaVersion uint32    `json:"schema_version"`
	CapturedAt    time.Time `json:"captured_at"`

	ReleaseVersion  string `json:"release_version"`
	ReleaseRevision string `json:"release_revision"`
	ReleaseEpoch    string `json:"release_epoch"`

	CutoverBlock   uint64 `json:"cutover_block"`
	CurrentBlock   uint64 `json:"current_block"`
	ClockAvailable bool   `json:"clock_available"`
	State          string `json:"state"`
	QuiesceCause   string `json:"quiesce_cause"`

	ActiveCeremonies           uint64           `json:"active_ceremonies"`
	ActiveLegacyCeremonies     uint64           `json:"active_legacy_ceremonies"`
	ActiveSecurityV2Ceremonies uint64           `json:"active_security_v2_ceremonies"`
	ActivePermits              []PermitSnapshot `json:"active_permits"`
}

// QuiescenceSnapshotRecorder persists the node-authored snapshot while the
// gate is making its one-way quiescence transition.
type QuiescenceSnapshotRecorder interface {
	Record(snapshot QuiescenceSnapshot) error
}

// quiescencePersistence is the narrow persistence handle used by the
// recorder. persistence.BasicHandle satisfies it without coupling the gate to
// the rest of the storage API.
type quiescencePersistence interface {
	Save(data []byte, directory string, name string) error
	Delete(directory string, name string) error
}

type persistenceQuiescenceSnapshotRecorder struct {
	persistence quiescencePersistence
}

// NewPersistenceQuiescenceSnapshotRecorder constructs the production
// recorder for the encrypted work/participation namespace.
func NewPersistenceQuiescenceSnapshotRecorder(
	persistence quiescencePersistence,
) (QuiescenceSnapshotRecorder, error) {
	if persistence == nil {
		return nil, fmt.Errorf("quiescence snapshot persistence is required")
	}

	// A snapshot authorizes only the process run that produced it. Clear any
	// prior run's record before the gate becomes available; if the node exits
	// or a later write fails, the offline audit then sees a missing or malformed
	// record instead of accepting stale inventory.
	if err := persistence.Delete(
		QuiescenceSnapshotStorageDirectory,
		QuiescenceSnapshotStorageFile,
	); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf(
			"cannot invalidate the prior quiescence snapshot: [%w]",
			err,
		)
	}

	return &persistenceQuiescenceSnapshotRecorder{
		persistence: persistence,
	}, nil
}

func (r *persistenceQuiescenceSnapshotRecorder) Record(
	snapshot QuiescenceSnapshot,
) error {
	content, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode the quiescence snapshot: [%w]", err)
	}

	if err := r.persistence.Save(
		content,
		QuiescenceSnapshotStorageDirectory,
		QuiescenceSnapshotStorageFile,
	); err != nil {
		return fmt.Errorf("cannot persist the quiescence snapshot: [%w]", err)
	}

	return nil
}
