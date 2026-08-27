# PR #4109 hardening records

This directory contains machine-readable inputs for incremental hardening of
keep-core PR #4109. The R00 package is a frozen historical-reproduction
inventory; it is deliberately not release authority.

The R00 v1 catalog is an inventory, not an exit-gate assertion. Its schema and
Go validator permanently require a blocked root and blocking case gates.
`baseline_evidence.status` says what was actually executed and retained; even a
structurally complete evidence record is diagnostic and cannot authorize a
release transition. A source anchor never counts as a reproduction. Any future
release-readiness claim requires a new schema/version and verifier rather than
mutating this inventory format.

The immutable identities distinguish:

- the historical R00 baseline, `1bc7edf9965cac43de3bd18060e07ba678670073`;
- the PR head evaluated by this slice,
  `d7bf8c0753f3aac574f8d20d93c75268f350b389`; and
- the exact tss-lib dependency,
  `d847ce0030193ccf5dbec0097571dcce5a2a5cf6`.

The external scenario runner and DigitalOcean harness remain outside this
keep-core release DAG. They may produce evidence consumed by later gates, but
their implementation is not vendored or represented as keep-core hardening.

`r00/verify-source-anchors.sh` is the networked provenance gate for the frozen
keep-core commit relationships, module pins, and every catalog anchor. It
resolves the exact keep-core, tss-lib, and tbtc-v2 Git objects, verifies the
baseline-parent and ancestry relationships, checks the PRIOR tag, structurally
binds both the evaluated candidate and PRIOR source commits to their consumed
module replacements and sums, and requires each recorded symbol to occur in its
anchored blob. The
private external scenario-harness identity is explicitly recorded as an
unverified scope reference; it is not silently treated as release evidence.
The existing required client CI job checks out complete keep-core history and
runs this host-side gate before the image-based tests. Keeping it in that job
ensures a provenance failure is a red required check rather than a skipped
dependent job. The Go test independently rechecks all keep-core catalog anchors
whenever Git metadata is present and fails if a historical object is then
unavailable. The client build image intentionally excludes `.git`, so that test
skips there; neither verifier ever substitutes a current working-tree path for
an immutable anchor.
