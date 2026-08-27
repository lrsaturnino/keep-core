# PR #4109 canonical encoding foundation

This directory is a provisional, non-gating subset of R00A. It freezes only
stateless encoding mechanics:

- a restricted RFC 8785 JSON profile with no floats and only interoperable bare
  integers;
- `SHA-256(domain || 0x00 || canonical_payload)` identities;
- canonical scalar and set-like-array spellings; and
- the no-float/no-tag RFC 8949 core deterministic CBOR subset selected for
  future ledger records.

The R00A exit gate remains **blocked**. This slice contains no operational
schema registry, ledger contract, signature envelope, trust bundle, root key,
monotonic authority, approval, signer, verifier action, or downstream adoption
claim. Test vectors and interoperability ports will be reviewed separately;
green package tests establish only the behavior of the primitives present here.

The external scenario runner and DigitalOcean evidence project are outside this
package and outside the keep-core release DAG.
