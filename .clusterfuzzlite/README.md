# Continuous fuzzing

This directory wires keep-core's native Go fuzz targets (the `Fuzz*` functions
under `pkg/**/fuzz_test.go`) into two complementary runners: Go's native fuzz
engine for required pull-request checks and **ClusterFuzzLite** for scheduled
batch runs. ClusterFuzzLite is OSS-Fuzz's self-hosted variant and works on
private repositories; OSS-Fuzz itself only fuzzes public projects.

## Files

| file | purpose |
|---|---|
| `Dockerfile` | build image (`base-builder-go`) |
| `build.sh` | compiles every `Fuzz*` target into a libFuzzer binary (path-qualified output names — several `Fuzz*` funcs share a name across packages) |
| `project.yaml` | `language: go` |
| `run_native_go_fuzzers.sh` | runs every registered target with native Go coverage and ASAN under the PR budget |
| `../.github/workflows/cflite_pr.yml` | required CFLite build validation plus native-Go PR fuzzing over every registered target |
| `../.github/workflows/cflite_batch.yml` | scheduled longer run over all targets |

Every `build_fuzzers` and `run_fuzzers` step must set `language: go`; the
actions have independent inputs and otherwise default to `c++`. That is a
configuration contract, not a workaround for libFuzzer's intermittent
native-Go inline-counter startup failure. The PR workflow retains the pinned
ClusterFuzzLite build action, then avoids the failing run path by using
`go test -asan -fuzz` directly. CI enforces these choices with
`check_workflow_contract.sh`.

The PR runner accounts for cold hosted workers explicitly. Before starting
the bounded phase, it compiles one fuzz-instrumented ASAN test binary for each
unique package; every target in that package then reuses the warmed build
cache. This keeps machine-dependent compilation outside the 300-second phase
cap while preserving the eight-second-per-target fuzz budget and the tight
per-target runtime deadline.

## Adding / regenerating targets

`build.sh` must list one `compile_native_go_fuzzer` line per `Fuzz*` target.
CI enforces this (`check_targets.sh` runs on every relevant PR and fails on
drift).
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

Security release branches and downstream forks can diverge from public
`github.com/keep-network/keep-core`. Fuzzing finds bugs in code; whether a
finding applies depends on how far the tested branch has diverged. Two facts
drive the policy:

- **Fixes do not flow back automatically.** A bug fixed upstream stays open in
  a divergent branch until deliberately back-merged.
- **Branch-divergent code gets no upstream coverage.** OSS-Fuzz on the public
  upstream cannot see code that only exists on another branch or fork.

Policy:

1. **Run native Go PR fuzzing and scheduled ClusterFuzzLite here** (this
   directory) so this repository's code — including divergent paths — is
   fuzzed in its own CI.
2. **Track upstream `main`**: reconcile within a bounded window (e.g. N commits
   or one release) so shared-parser fixes reach downstream branches.
3. **Contribute the fuzz targets upstream** (below) so the shared parsers get
   continuous OSS-Fuzz coverage at Google's scale, and so downstream branches
   inherit that coverage on shared code after each reconcile.

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
