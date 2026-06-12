#!/bin/bash -eu
#
# Drift guard: fails when the set of native Fuzz* targets under pkg/
# diverges from the compile_native_go_fuzzer registration list in
# build.sh. Without this, a new Fuzz* function compiles fine under
# `go test` but silently receives zero ClusterFuzzLite coverage.
#
# Compares exact (package, function) pairs — not counts — because
# several Fuzz functions share a name across packages.

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
module="github.com/keep-network/keep-core"

expected="$(
	grep -rn --include='*_test.go' -E '^func Fuzz[A-Za-z0-9_]+\(f \*testing\.F\)' "$repo_root/pkg" |
		sed -E "s|^$repo_root/(.+)/[^/]+\.go:[0-9]+:func (Fuzz[A-Za-z0-9_]+)\(.*$|$module/\1 \2|" |
		sort -u
)"

registered="$(
	grep -E '^compile_native_go_fuzzer ' "$repo_root/.clusterfuzzlite/build.sh" |
		awk '{print $2, $3}' |
		sort -u
)"

if ! diff <(echo "$expected") <(echo "$registered") >&2; then
	echo >&2
	echo "Fuzz target drift detected:" >&2
	echo "  < targets found in pkg/ but not registered in .clusterfuzzlite/build.sh" >&2
	echo "  > targets registered in build.sh but missing from pkg/" >&2
	echo "Add/remove the matching compile_native_go_fuzzer line(s)." >&2
	exit 1
fi

echo "OK: $(echo "$expected" | wc -l) fuzz targets, build.sh registration list in sync."
