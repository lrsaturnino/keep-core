#!/bin/bash -eu
#
# Drift guard: ClusterFuzzLite's build_fuzzers and run_fuzzers actions each
# have an independent `language` input whose default is `c++`. Native Go
# fuzzers therefore require every action step to repeat the language declared
# in project.yaml. The PR workflow retains ClusterFuzzLite build validation but
# deliberately replaces its flaky run path with Go's native fuzz runner.

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

project_language="$(
	awk '
		/^[[:space:]]*language:[[:space:]]*/ {
			value = $0
			sub(/^[[:space:]]*language:[[:space:]]*/, "", value)
			sub(/[[:space:]]*(#.*)?$/, "", value)
			print value
		}
	' .clusterfuzzlite/project.yaml
)"

if [[ -z "$project_language" || "$project_language" == *$'\n'* ]]; then
	echo "project.yaml must declare exactly one language" >&2
	exit 1
fi

project_toolchain="$(
	awk '
		$1 == "toolchain" {
			value = $2
			sub(/^go/, "", value)
			print value
		}
	' go.mod
)"

if [[ -z "$project_toolchain" || "$project_toolchain" == *$'\n'* ]]; then
	echo "go.mod must declare exactly one Go toolchain" >&2
	exit 1
fi

action_input() {
	local workflow="$1"
	local action_path="$2"
	local action_label="$3"
	local input_name="$4"
	local expected_count="$5"

	awk \
		-v action_path="$action_path" \
		-v action_label="$action_label" \
		-v input_name="$input_name" \
		-v expected_count="$expected_count" \
		-v workflow="$workflow" '
		function indentation(line) {
			match(line, /[^ ]/)
			return RSTART - 1
		}

		function missing_input() {
			active = 0
			printf "%s: %s action is missing a direct with.%s input\n", \
				workflow, action_label, input_name > "/dev/stderr"
			exit 1
		}

		{
			stripped = $0
			sub(/^[[:space:]]*/, "", stripped)
		}

		$0 ~ "^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*[\"\047]?" action_path {
			if (active) {
				missing_input()
			}
			found++
			active = 1
			in_with = 0
			property_indent = indentation($0)
			if (stripped ~ /^-[[:space:]]+uses:/) {
				property_indent += 2
			}
			next
		}

		active && stripped !~ /^(#|$)/ &&
			indentation($0) < property_indent {
			missing_input()
		}

		active && in_with && stripped !~ /^(#|$)/ &&
			indentation($0) <= property_indent {
			missing_input()
		}

		active && indentation($0) == property_indent &&
			stripped ~ /^with:[[:space:]]*(#.*)?$/ {
			in_with = 1
			next
		}

		active && in_with && indentation($0) == property_indent + 2 &&
			stripped ~ ("^" input_name ":[[:space:]]*") {
			value = stripped
			sub("^" input_name ":[[:space:]]*", "", value)
			sub(/[[:space:]]*(#.*)?$/, "", value)
			sub(/^\"/, "", value)
			sub(/\"$/, "", value)
			sub(/^\047/, "", value)
			sub(/\047$/, "", value)
			print value
			active = 0
			in_with = 0
		}

		END {
			if (active) {
				missing_input()
			}
			if (found != expected_count) {
				printf "%s: expected %d %s actions, found %d\n", \
					workflow, expected_count, action_label, found > "/dev/stderr"
				exit 1
			}
		}
	' "$workflow"
}

pr_workflow=.github/workflows/cflite_pr.yml
batch_workflow=.github/workflows/cflite_batch.yml

# The required PR job must continue proving that the scheduled ClusterFuzzLite
# build works, but must not reintroduce its flaky native-Go/libFuzzer run path.
pr_build_language="$(action_input \
	"$pr_workflow" \
	'google/clusterfuzzlite/actions/build_fuzzers@' \
	build_fuzzers \
	language \
	1)"
action_input \
	"$pr_workflow" \
	'google/clusterfuzzlite/actions/run_fuzzers@' \
	run_fuzzers \
	language \
	0 >/dev/null

if [[ "$pr_build_language" != "$project_language" ]]; then
	echo "$pr_workflow: ClusterFuzzLite build language mismatch" >&2
	echo "  project.yaml: $project_language" >&2
	echo "  build_fuzzers: $pr_build_language" >&2
	exit 1
fi

native_runner_count="$(
	awk '
		/^[[:space:]]*run:[[:space:]]*\.\/\.clusterfuzzlite\/run_native_go_fuzzers\.sh[[:space:]]*(#.*)?$/ {
			found++
		}
		END { print found + 0 }
	' "$pr_workflow"
)"
if [[ "$native_runner_count" -ne 1 ]]; then
	echo "$pr_workflow: expected exactly one native Go fuzz runner step" >&2
	exit 1
fi

native_runner_test_count="$(
	awk '
		/^[[:space:]]*run:[[:space:]]*\.\/\.clusterfuzzlite\/test_native_go_fuzzers\.sh[[:space:]]*(#.*)?$/ {
			found++
		}
		END { print found + 0 }
	' "$pr_workflow"
)"
if [[ "$native_runner_test_count" -ne 1 ]]; then
	echo "$pr_workflow: expected exactly one native Go runner contract-test step" >&2
	exit 1
fi

native_go_version="$(
	action_input \
		"$pr_workflow" \
		'actions/setup-go@' \
		setup-go \
		go-version \
		1
)"
if [[ "$native_go_version" != "$project_toolchain" ]]; then
	echo "$pr_workflow: native fuzz Go version does not match go.mod toolchain" >&2
	echo "  go.mod toolchain: $project_toolchain" >&2
	echo "  setup-go version: $native_go_version" >&2
	exit 1
fi

build_language="$(
	action_input \
		"$batch_workflow" \
		'google/clusterfuzzlite/actions/build_fuzzers@' \
		build_fuzzers \
		language \
		1
)"
run_language="$(
	action_input \
		"$batch_workflow" \
		'google/clusterfuzzlite/actions/run_fuzzers@' \
		run_fuzzers \
		language \
		1
)"

if [[ "$build_language" != "$project_language" ||
	"$run_language" != "$project_language" ]]; then
	echo "$batch_workflow: ClusterFuzzLite language mismatch" >&2
	echo "  project.yaml: $project_language" >&2
	echo "  build_fuzzers: $build_language" >&2
	echo "  run_fuzzers: $run_language" >&2
	exit 1
fi

echo "OK: PR build and batch build/run use $project_language; native PR runner uses Go $project_toolchain."
