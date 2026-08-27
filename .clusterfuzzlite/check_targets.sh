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

# Work from the repo root so grep emits relative paths: the absolute path
# never enters the sed pattern, where regex metacharacters in a checkout
# location could otherwise misparse the target list.
cd "$repo_root"

expected="$(
	grep -rn --include='*_test.go' -E '^func Fuzz[A-Za-z0-9_]+\(f \*testing\.F\)' pkg |
		sed -E "s|^(.+)/[^/]+\.go:[0-9]+:func (Fuzz[A-Za-z0-9_]+)\(.*$|$module/\1 \2|" |
		sort -u
)"

malformed_registrations="$(
	awk '
		$1 == "compile_native_go_fuzzer" && NF != 4 {
			print NR ":" $0
		}
	' .clusterfuzzlite/build.sh
)"
if [[ -n "$malformed_registrations" ]]; then
	echo "Malformed fuzz target registration(s); expected exactly four fields:" >&2
	printf '  %s\n' "$malformed_registrations" >&2
	exit 1
fi

registered_raw="$(
	awk '$1 == "compile_native_go_fuzzer" {print $2, $3}' \
		.clusterfuzzlite/build.sh
)"

duplicate_registrations="$(printf '%s\n' "$registered_raw" | sort | uniq -d)"
if [[ -n "$duplicate_registrations" ]]; then
	echo "Duplicate fuzz target registration(s) in .clusterfuzzlite/build.sh:" >&2
	printf '  %s\n' "$duplicate_registrations" >&2
	exit 1
fi

duplicate_outputs="$(
	awk '$1 == "compile_native_go_fuzzer" {print $4}' \
		.clusterfuzzlite/build.sh |
		sort |
		uniq -d
)"
if [[ -n "$duplicate_outputs" ]]; then
	echo "Duplicate fuzz target output name(s) in .clusterfuzzlite/build.sh:" >&2
	printf '  %s\n' "$duplicate_outputs" >&2
	exit 1
fi

registered="$(printf '%s\n' "$registered_raw" | sort)"

if ! diff <(printf '%s\n' "$expected") <(printf '%s\n' "$registered") >&2; then
	echo >&2
	echo "Fuzz target drift detected:" >&2
	echo "  < targets found in pkg/ but not registered in .clusterfuzzlite/build.sh" >&2
	echo "  > targets registered in build.sh but missing from pkg/" >&2
	echo "Add/remove the matching compile_native_go_fuzzer line(s)." >&2
	exit 1
fi

echo "OK: $(printf '%s\n' "$expected" | wc -l) fuzz targets, build.sh registration list in sync."
