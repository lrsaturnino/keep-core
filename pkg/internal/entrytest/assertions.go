package entrytest

import (
	"slices"
	"testing"

	"github.com/keep-network/keep-core/pkg/protocol/group"
)

// AssertEntryPublished checks if relay entry has been published to the chain.
// It does not inspect the entry.
func AssertEntryPublished(t *testing.T, testResult *Result) {
	if testResult.entry == nil {
		t.Fatal("expected relay entry to be published")
	}
}

// AssertEntryNotPublished checks if no relay entry has been published to
// the chain.
func AssertEntryNotPublished(t *testing.T, testResult *Result) {
	if testResult.entry != nil {
		t.Fatalf(
			"expected relay entry not to be published; is: [%v]",
			testResult.entry,
		)
	}
}

// AssertNoSignerFailures checks there were no signer failures during the
// protocol execution.
func AssertNoSignerFailures(
	t *testing.T,
	testResult *Result,
) {
	if len(testResult.signerFailures) != 0 {
		t.Errorf(
			"expected no signer failures; has [%v]",
			len(testResult.signerFailures),
		)
	}
}

// AssertSignerFailuresCount checks the number of signers who failed the
// protocol execution. It does not check which particular signers failed.
func AssertSignerFailuresCount(
	t *testing.T,
	testResult *Result,
	expectedCount int,
) {
	if len(testResult.signerFailures) != expectedCount {
		t.Errorf(
			"unexpected number of signer failures\nexpected: [%v]\nactual:   [%v]",
			expectedCount,
			len(testResult.signerFailures),
		)
	}
}

// AssertIncorporatedPopulations checks the transcript each signer that
// recovered the entry reported behind it: the memberships whose authenticated
// signature shares it combined.
//
// That population is the whole of what distinguishes a threshold entry several
// parties produced from one a single party recovered among its own kind — a
// relay entry is deterministic for a given previous entry, so every member of a
// finished round names the same result whoever supplied the shares — and it is
// what the release evidence records as the parties to the ceremony. It is
// checked here rather than only where it is written, because only a real round
// establishes that the population comes out of the shares that were actually
// combined.
func AssertIncorporatedPopulations(
	t *testing.T,
	testResult *Result,
	threshold int,
	groupSize int,
) {
	if len(testResult.populations) == 0 {
		t.Fatal("expected at least one signer to report a transcript")
	}

	for memberIndex, population := range testResult.populations {
		if len(population) != threshold {
			t.Errorf(
				"signer [%v] combined [%d] memberships into the entry, "+
					"expected the honest threshold of [%d]",
				memberIndex,
				len(population),
				threshold,
			)
		}

		if !slices.Contains(population, memberIndex) {
			t.Errorf(
				"signer [%v] left its own share out of the transcript it "+
					"reported: [%v]",
				memberIndex,
				population,
			)
		}

		// One population must have exactly one rendering, or two members'
		// records of the same round would not compare equal and a reader could
		// be shown one seat twice.
		previous := group.MemberIndex(0)
		for _, seat := range population {
			if seat <= previous || int(seat) > groupSize {
				t.Errorf(
					"signer [%v] reported [%v], which is not an ascending set "+
						"of memberships of a group of [%d]",
					memberIndex,
					population,
					groupSize,
				)
				break
			}
			previous = seat
		}
	}
}
