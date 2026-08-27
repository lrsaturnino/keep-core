// Package canonical implements the provisional, stateless encoding primitives
// shared by the PR #4109 release-hardening DAG.
//
// This package currently covers the restricted RFC 8785 JSON profile,
// domain-separated SHA-256 identities, canonical scalar spellings, set-like
// JSON arrays, and the selected RFC 8949 core deterministic CBOR subset. It
// does not implement a policy registry, ledger schema, signature envelope,
// trust root, monotonic authority, approval, or release action. Its presence
// therefore cannot authorize R00B or any downstream release transition.
package canonical
