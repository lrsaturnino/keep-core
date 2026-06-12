package dkgtest

// Determinism probe for Tier-2 (Byzantine deterministic-simulation testing)
// work-package 0. Before building a Byzantine-strategy sweep on top of
// dkgtest.RunTest, we must know whether an honest run produces a STABLE VERDICT
// across repetitions. DST only yields trustworthy pass/fail signals if the
// honest baseline is stable; an unstable baseline means every "failure" is
// ambiguous.
//
// What this probe does and does NOT measure:
//
//   - It does NOT check value-identity (identical group public key bytes).
//     GJKR draws every polynomial coefficient from crypto/rand
//     (pkg/beacon/gjkr/protocol.go:265), so the group public key differs on
//     every run BY DESIGN, even at a fixed seed (the `seed` arg only becomes a
//     session/channel id, not protocol randomness). A seeded DKG would be a
//     vulnerability, not a feature. Value-level reproducers are therefore out
//     of scope and would require an injected RNG seam.
//
//   - It DOES check verdict stability: across N honest runs at a fixed seed,
//     does every run reach the same structural end-state (all members succeed,
//     zero misbehaving, zero failures, a valid group public key agreed by all
//     signers)?
//
// Every run is bucketed into one of three outcomes and the DISTRIBUTION is the
// result (we do not t.Fatal inside the loop):
//
//	(a) clean        - full success, all structural invariants hold
//	(b) timeout-miss - result.dkgResult == nil: the async OnDKGResultSubmitted
//	                   handler missed the 5s wall-clock window in
//	                   executeDKG (line ~190). This is a HARNESS wall-clock
//	                   artifact, amplified by -race and load, NOT protocol
//	                   nondeterminism. RunTest returns a nil error on this path,
//	                   so it must be detected via the nil dkgResult, not err.
//	(c) instability  - a run that published a result but with a non-clean
//	                   verdict (misbehaving members, member failures, or
//	                   disagreeing/invalid public key). ONLY (c) blocks DST.
//
// Run it explicitly (it is skipped in normal `go test ./...`):
//
//	DETERMINISM_PROBE=1 go test ./pkg/internal/dkgtest/ -run TestDeterminismProbe -v -timeout 60m
//	DETERMINISM_PROBE=1 DETERMINISM_PROBE_N=200 go test -race ./pkg/internal/dkgtest/ -run TestDeterminismProbe -v -timeout 120m
//
// Compare the (b) timeout-miss rate with and without -race: a large shift
// confirms the timeout (not the protocol) is the nondeterminism source.

import (
	"encoding/hex"
	"math/big"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/keep-network/keep-core/pkg/altbn128"
	"github.com/keep-network/keep-core/pkg/net"
)

func TestDeterminismProbe(t *testing.T) {
	if os.Getenv("DETERMINISM_PROBE") == "" {
		t.Skip("set DETERMINISM_PROBE=1 to run the Tier-2 work-package-0 determinism probe")
	}

	const (
		groupSize       = 10
		honestThreshold = 6
	)

	n := 100
	if v := os.Getenv("DETERMINISM_PROBE_N"); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil || parsed < 1 {
			t.Fatalf("invalid DETERMINISM_PROBE_N=%q: %v", v, err)
		}
		n = parsed
	}

	// Fixed seed for every iteration: the whole point is to vary nothing the
	// caller controls and observe what the protocol/harness still varies.
	seed := big.NewInt(0x5EED)

	// Honest interceptor: identity, no message modification or dropping. This is
	// the baseline the Byzantine sweep will perturb.
	honest := func(msg net.TaggedMarshaler) net.TaggedMarshaler { return msg }

	var (
		clean       int
		timeoutMiss int
		runError    int
		instability int
	)
	// Track distinct group public keys to confirm value-nondeterminism is real
	// (we expect ~all distinct), and instability detail for the failing bucket.
	pubKeys := make(map[string]struct{})
	var instabilityDetail []string

	t.Logf("probe: %d honest runs, groupSize=%d, honestThreshold=%d, fixed seed=0x%x",
		n, groupSize, honestThreshold, seed)

	start := time.Now()
	for i := 0; i < n; i++ {
		result, err := RunTest(groupSize, honestThreshold, seed, honest)

		switch {
		case err != nil:
			runError++
			instabilityDetail = append(instabilityDetail,
				"run "+strconv.Itoa(i)+": RunTest error: "+err.Error())

		case result.dkgResult == nil:
			// Bucket (b): wall-clock timeout-miss. Harness artifact, not a
			// protocol-determinism finding.
			timeoutMiss++

		default:
			// Result published; classify the verdict.
			successCount := len(result.signers)
			failures := len(result.memberFailures)
			misbehaved := len(result.dkgResult.Misbehaved)

			pkValid := true
			if _, derr := altbn128.DecompressToG2(result.dkgResult.GroupPublicKey); derr != nil {
				pkValid = false
			}
			pubKeys[hex.EncodeToString(result.dkgResult.GroupPublicKey)] = struct{}{}

			// All successful signers must agree on the published group key.
			agreed := true
			for _, s := range result.signers {
				if hex.EncodeToString(s.GroupPublicKeyBytes()) !=
					hex.EncodeToString(result.dkgResult.GroupPublicKey) {
					agreed = false
					break
				}
			}

			isClean := successCount == groupSize &&
				failures == 0 &&
				misbehaved == 0 &&
				pkValid &&
				agreed

			if isClean {
				clean++
			} else {
				instability++
				instabilityDetail = append(instabilityDetail,
					"run "+strconv.Itoa(i)+": signers="+strconv.Itoa(successCount)+
						" failures="+strconv.Itoa(failures)+
						" misbehaved="+strconv.Itoa(misbehaved)+
						" pkValid="+strconv.FormatBool(pkValid)+
						" agreed="+strconv.FormatBool(agreed))
			}
		}
	}
	elapsed := time.Since(start)

	t.Logf("=== determinism probe distribution (n=%d, %s, %.2fs/run avg) ===",
		n, elapsed.Round(time.Second), elapsed.Seconds()/float64(n))
	t.Logf("  (a) clean success     : %d", clean)
	t.Logf("  (b) timeout-miss      : %d   (harness wall-clock artifact; not a protocol finding)", timeoutMiss)
	t.Logf("      RunTest error     : %d", runError)
	t.Logf("  (c) verdict instability: %d   (BLOCKS DST if > 0)", instability)
	t.Logf("  distinct group pubkeys: %d / %d published (expected ~all distinct: crypto/rand)",
		len(pubKeys), clean+instability)

	for _, d := range instabilityDetail {
		t.Logf("    ! %s", d)
	}

	// The gate: only genuine verdict instability (c) or hard errors fail the
	// probe. Timeout-misses (b) are reported but do not fail; they characterize
	// the harness wall-clock margin, not protocol determinism.
	if instability > 0 || runError > 0 {
		t.Errorf("honest baseline is NOT verdict-stable: %d instability + %d errors over %d runs; "+
			"DST verdicts would be ambiguous until this is pinned down", instability, runError, n)
	}
}
