//go:build ruleguard

// Package gorules holds ruleguard rules enforced via gocritic in
// .golangci.yml. These are lint rules, not compiled into the project (the
// ruleguard build tag keeps them out of normal builds).
package gorules

import "github.com/quasilyte/go-ruleguard/dsl"

// txBoundsCheckedIndexing forbids raw index access on a transaction's
// Outputs/Inputs slices and steers callers to the bounds-checked accessors
// Transaction.OutputAt(i) / Transaction.InputAt(i).
//
// A variable index derived from one transaction used to index a separately
// fetched (untrusted) transaction's slice with no bounds check is the
// out-of-bounds panic class that crashes the client. Matching the index
// expression specifically (not len()/range/assignment of the field) keeps this
// precise; safe call sites (guarded constant indices, the accessor bodies
// themselves) carry a //nolint:gocritic with a one-line rationale.
func txBoundsCheckedIndexing(m dsl.Matcher) {
	// Only variable (non-constant) indices are flagged: a constant index
	// (e.g. Outputs[0]) is paired with an explicit len() guard at its call
	// site and is not the OOB class. The findings were all variable indices
	// derived from one transaction applied to a separately fetched one.
	//
	// The receiver is type-constrained to bitcoin.Transaction (value and
	// pointer) so unrelated types that happen to have an Outputs/Inputs
	// slice field — including regenerated gen/ code, where a //nolint
	// cannot survive — do not trip the rule.
	//
	// Known, accepted limitations: the rule guards against accidental
	// reintroduction, not adversarial code. Aliasing the slice first
	// (outs := tx.Outputs; outs[i]) bypasses the pattern, as does any
	// helper that returns the slice. Review remains the backstop for
	// those shapes.
	m.Import(`github.com/keep-network/keep-core/pkg/bitcoin`)

	m.Match(`$tx.Outputs[$i]`).
		Where(!m["i"].Const &&
			(m["tx"].Type.Is(`bitcoin.Transaction`) ||
				m["tx"].Type.Is(`*bitcoin.Transaction`))).
		Report(`use Transaction.OutputAt($i) instead of raw Outputs[$i] indexing to bounds-check untrusted input (OOB crash class)`)

	m.Match(`$tx.Inputs[$i]`).
		Where(!m["i"].Const &&
			(m["tx"].Type.Is(`bitcoin.Transaction`) ||
				m["tx"].Type.Is(`*bitcoin.Transaction`))).
		Report(`use Transaction.InputAt($i) instead of raw Inputs[$i] indexing to bounds-check untrusted input (OOB crash class)`)
}
