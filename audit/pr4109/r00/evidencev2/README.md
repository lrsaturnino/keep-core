# R00 evidence bundle v2: cases 01–03

This directory contains the additive, diagnostic-only, fail-closed
self-consistency verifier contract for R00-01, R00-02, and R00-03. It does not
contain a runner or generated evidence, does not replace the v1 R00 catalog,
and cannot grant qualification or release authority. The verifier requires v1
to remain `blocked`, with all 18 cases `not_run` and blocking.

Passing `VerifyBundle` means only that the retained bytes are closed,
content-addressed, mutually consistent, and satisfy the independently derived
cryptographic and protocol predicates. It does **not** authenticate that the
retained binaries ran or produced those transcripts. A capturer could create a
self-consistent transcript without executing the retained binaries. Evidence
acceptance therefore also requires external CI execution provenance and
reproducible-build verification. `Report.ExecutionProvenanceVerified` and
`Report.EvidenceAccepted` are intentionally always `false` in this package.

## What the self-consistency verifier derives

`VerifyBundle` accepts only a closed content-addressed directory named
`sha256/<SHA-256(evidence-root.json)>`. The root pins baseline commit
`1bc7edf9965cac43de3bd18060e07ba678670073`, PRIOR commit
`66b187efdbe1cd567950de0efe9728de95886b13`, their canonical tree-manifest
SHA-256 values, the unchanged v1 documents, the evidence-runner source, every
tool binary/build record/module graph/source asset, and every raw artifact.

The verifier does not accept `pass`, `verified`, or `signature_valid` markers:

- It parses fixed-width secp256k1 proof material and independently evaluates
  both the historical three-block `HashToN` equation and the candidate tagged
  SHA-512/256 equation. The archived exact-binary result must agree with that
  independent result.
- It reconstructs the library's raw `SignatureData` fields, pins the 11-party
  public key and requested message 42, checks historical versus candidate
  message-width encoding, enforces canonical low-S, verifies ECDSA, verifies
  the recovery byte, and requires all 11 homogeneous workers to emit
  byte-identical valid signatures.
- It parses each worker's strict stdout JSONL, matches it to the hashed worker
  record, globally pairs every emitted delivery with exactly one received
  delivery, requires exactly one protocol result in the penultimate event and
  a drained/waited stop as the final event, and rejects all post-terminal
  traffic. The mixed transcript must contain complete directed 11-by-10
  matrices for exactly `SignRound1Message1`, `SignRound1Message2`, and
  `SignRound2Message`; each sender's ten expanded `SignRound1Message2`
  deliveries must share one broadcast payload hash. Every worker must receive
  both complete round-1 matrices before emitting round 2. A candidate worker's
  structured round-3 Alice-end refusal must follow all ten round-2 receives,
  bind the final trigger delivery, and contain the exact historical-party
  culprit multiset while preserving its raw order. The retained mixed
  transcript must contain zero `SignatureData` events; other workers may
  terminate as `quiesced_no_result`.
- It requires the exact offline execution environment (`go1.25.10`, Linux
  amd64, CGO disabled, `GOTOOLCHAIN=local`, `GOWORK=off`, `GOENV=off`,
  `GOPROXY=off`, `GOSUMDB=off`, and read-only module mode), exact argv/input
  roles, closed stdin, drained stdout/stderr, successful wait/exit, and no
  timeout, signal, or panic.

All file paths are canonical relative paths. The verifier rejects extra files,
directories, symlinks, non-regular files, path traversal, duplicate roles or
paths, unreferenced artifacts, and hash/size drift. Empty `text/plain` logs are
valid so an honestly empty stderr remains empty. It caps individual JSON
artifacts at 8 MiB, text artifacts at 16 MiB, binary artifacts at 64 MiB, and
all referenced artifacts together at 512 MiB before retaining them in memory.
Directory enumeration is streamed in bounded batches. The verifier pins the
bundle root, each traversed directory, and each opened file by filesystem
identity, then repeats the closed-layout and root-identity checks before
success. This is not an atomic filesystem snapshot: verification must run over
a private, read-only artifact directory with no concurrent writers or mount
changes.

## Fixture identity

The non-secret fixture manifest digest
`7b934fd6db3a109e1c3c70ec2be50aab3af3f955951d02f18841331eb988c42c`
is SHA-256 over 11 UTF-8 lines in numeric order 0 through 10:

```text
<sha256><two spaces>keygen_data_<N>.json\n
```

The raw private-share fixture JSON is not copied into evidence. Historical and
candidate fixture files 0–10 must produce this identical manifest. The pinned
group public key is encoded in `model.go`.

## Next slice

The next implementation commit may add a deterministic outer packager and
child runner that emit exactly these records, then run `VerifyBundle` over the
generated content-addressed directory. The packager must re-exec and wait for
each per-case `evidence-runner` child so its process record is internally
consistent. That runner alone does not establish execution provenance. Before
evidence acceptance, CI must independently attest the isolated checkout,
reproducible tool builds, invoked commands, and captured output artifacts.
The runner must also collect all 110 round-2 outbounds behind a phase barrier
before dispatch, record a receipt only after the worker consumes that delivery,
and drain every worker after the first refusal. A runner-issued summary such as
`delivery_count=330` is not evidence. That runner and CI-attestation work are
intentionally outside this verifier-only commit.

Run the focused verifier suite with:

```sh
go test ./audit/pr4109/r00/evidencev2
```
