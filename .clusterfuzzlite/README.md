# Continuous fuzzing

This directory wires keep-core's native Go fuzz targets (the `Fuzz*` functions
under `pkg/**/fuzz_test.go`) into **ClusterFuzzLite** — OSS-Fuzz's self-hosted
variant that runs in this repo's own GitHub Actions and **works on private
repos**. That last property is why ClusterFuzzLite, not OSS-Fuzz, is the right
tool for this fork (OSS-Fuzz only fuzzes public projects).

## Files

| file | purpose |
|---|---|
| `Dockerfile` | build image (`base-builder-go`) |
| `build.sh` | compiles every `Fuzz*` target into a libFuzzer binary (path-qualified output names — several `Fuzz*` funcs share a name across packages) |
| `project.yaml` | `language: go` |
| `../.github/workflows/cflite_pr.yml` | per-PR fuzzing of changed code (fast, exits on first crash) |
| `../.github/workflows/cflite_batch.yml` | scheduled longer run over all targets |

## Adding / regenerating targets

`build.sh` must list one `compile_native_go_fuzzer` line per `Fuzz*` target.
CI enforces this (`check_targets.sh` runs on every PR and fails on drift).
Regenerate after adding targets:

```sh
for f in $(grep -rln "func Fuzz.*testing.F" pkg/ --include="*_test.go" | sort); do
  d=$(dirname "$f"); p="github.com/keep-network/keep-core/$d"
  pref=$(echo "$d" | sed 's#^pkg/##; s#/#_#g')
  grep -oE "func (Fuzz[A-Za-z0-9_]+)\(" "$f" | sed -E 's/func (Fuzz[A-Za-z0-9_]+)\(/\1/' \
    | while read fn; do echo "compile_native_go_fuzzer $p $fn ${pref}_${fn}"; done
done
```

## Enabling corpus persistence (batch mode)

Batch fuzzing benefits from carrying the corpus between runs — without it
every nightly run restarts from the in-tree seeds and the 1800s budget is a
smoke test, not coverage-accumulating fuzzing. To enable:

1. Create a private storage repo, e.g. `tlabs-xyz/keep-core-security-fuzz-corpus`.
2. Add a `PERSONAL_ACCESS_TOKEN` repo secret. It MUST be a **fine-grained
   PAT scoped to the storage repo only**, with `Contents: Read and write`
   as its only permission. Never use a classic PAT here: the token is
   interpolated into a clone URL inside a job that executes
   repo-controlled build code (`build.sh`, `Dockerfile`), so an
   over-scoped token would hand that code access to everything it can
   reach. Set an expiry and rotate it.
3. Uncomment the `storage-repo*` lines in `cflite_batch.yml` (and
   `upload-build`). Keep persistence OUT of `cflite_pr.yml`: PR jobs run
   proposed code and must not see the token at all.

Until then, each batch run starts from the in-tree seed corpus.

## Fork-lifecycle policy (why this exists)

This is a **private fork** of the public `github.com/keep-network/keep-core`.
Fuzzing finds bugs in code; whether a finding is fork-relevant depends on how
far the fork has diverged. Two facts drive the policy:

- **Fixes do not flow back automatically.** A bug fixed upstream stays open in
  this fork until deliberately back-merged (this engagement already hit exactly
  that: upstream's OOB fix was incomplete and had to be back-merged by hand).
- **Fork-divergent code gets no upstream coverage.** OSS-Fuzz on the upstream
  cannot see code that only exists here.

Policy:

1. **Run ClusterFuzzLite here** (this directory) so the fork's own code —
   including divergent paths — is fuzzed in its own CI.
2. **Track upstream `main`**: reconcile within a bounded window (e.g. N commits
   or one release) so shared-parser fixes found upstream reach the fork.
3. **Contribute the fuzz targets upstream** (below) so the shared parsers get
   continuous OSS-Fuzz coverage at Google's scale, and so this fork inherits
   that coverage on the shared code after each reconcile.

## OSS-Fuzz for the public upstream

The same `Dockerfile` / `build.sh` / targets work for OSS-Fuzz once the
`Fuzz*` targets are merged into `github.com/keep-network/keep-core`. To enroll
the upstream, open a PR to `google/oss-fuzz` adding `projects/keep-core/` with:

- `project.yaml`:

  ```yaml
  homepage: "https://github.com/keep-network/keep-core"
  language: go
  primary_contact: "<security contact email>"
  main_repo: "https://github.com/keep-network/keep-core"
  fuzzing_engines:
    - libfuzzer
  sanitizers:
    - address
  ```

- a `Dockerfile` that `git clone`s the upstream repo (instead of `COPY .`):

  ```dockerfile
  FROM gcr.io/oss-fuzz-base/base-builder-go
  RUN git clone --depth 1 https://github.com/keep-network/keep-core $SRC/keep-core
  WORKDIR $SRC/keep-core
  COPY build.sh $SRC/
  ```

- the same `build.sh` from this directory.
