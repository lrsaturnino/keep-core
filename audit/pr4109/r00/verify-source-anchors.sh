#!/usr/bin/env bash

set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to verify R00 source anchors" >&2
  exit 1
fi

repository_root=$(git rev-parse --show-toplevel)
frozen_inputs="$repository_root/audit/pr4109/r00/frozen-inputs.json"
catalog="$repository_root/audit/pr4109/r00/reproduction-catalog.json"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/pr4109-r00-sources.XXXXXX")
trap 'rm -rf "$scratch"' EXIT

input_field() {
  local input_name=$1
  local field_name=$2

  jq -er \
    --arg input_name "$input_name" \
    --arg field_name "$field_name" \
    '.inputs[] | select(.name == $input_name) | .[$field_name]' \
    "$frozen_inputs"
}

require_commit() {
  local source_root=$1
  local source_repository=$2
  local source_commit=$3

  if ! git -C "$source_root" cat-file -e "$source_commit^{commit}"; then
    echo "missing immutable source commit: $source_repository@$source_commit" >&2
    exit 1
  fi
}

require_module_pin() {
	local module_json=$1
	local module_sum_file=$2
	local consumed_path=$3
	local consumed_version=$4
	local replacement_path=$5
	local replacement_version=$6
	local replacement_sum=$7

	local require_count
	require_count=$(
		jq -r \
			--arg path "$consumed_path" \
			--arg version "$consumed_version" \
			'[.Require[] | select(.Path == $path and .Version == $version)] | length' \
			"$module_json"
	)
	if [[ $require_count -ne 1 ]]; then
		echo "go.mod does not consume exactly $consumed_path@$consumed_version" >&2
		exit 1
	fi

	local replacement_count
	replacement_count=$(
		jq -r \
			--arg consumed "$consumed_path" \
			--arg replacement "$replacement_path" \
			--arg version "$replacement_version" \
			'[
			  .Replace[] |
			  select(
			    .Old.Path == $consumed and
			    (.Old.Version // "") == "" and
			    .New.Path == $replacement and
			    .New.Version == $version
			  )
			] | length' \
			"$module_json"
	)
	local consumed_replacement_count
	consumed_replacement_count=$(
		jq -r \
			--arg consumed "$consumed_path" \
			'[.Replace[] | select(.Old.Path == $consumed)] | length' \
			"$module_json"
	)
	if [[ $replacement_count -ne 1 || $consumed_replacement_count -ne 1 ]]; then
		echo \
			"go.mod does not replace exactly $consumed_path with $replacement_path@$replacement_version" \
			>&2
		exit 1
	fi
	if ! grep -F -x \
		"$replacement_path $replacement_version $replacement_sum" \
		"$module_sum_file" >/dev/null; then
		echo \
			"go.sum does not pin $replacement_path@$replacement_version to $replacement_sum" \
			>&2
		exit 1
	fi
}

prepare_repository() {
  local destination=$1
  local remote=$2
  shift 2

  git init -q "$destination"
  git -C "$destination" remote add origin "$remote"
  for source_commit in "$@"; do
    git -C "$destination" fetch -q --depth=1 --filter=blob:none origin "$source_commit"
  done
}

prepare_repository \
  "$scratch/tss-lib" \
  https://github.com/threshold-network/tss-lib.git \
  d847ce0030193ccf5dbec0097571dcce5a2a5cf6 \
  2e712689cfbeefede15f95a0ec7112227d86f702
prepare_repository \
  "$scratch/tbtc-v2" \
  https://github.com/threshold-network/tbtc-v2.git \
  280da5c4ca6aa066f0ea7291076e4c70085723a9

baseline_source=$(jq -er '.baseline_source_commit' "$frozen_inputs")
baseline_parent=$(jq -er '.baseline_parent_commit' "$frozen_inputs")
evaluated_candidate=$(jq -er '.evaluated_candidate_commit' "$frozen_inputs")
evaluated_base=$(jq -er '.evaluated_candidate_base' "$frozen_inputs")
independently_tested_r1=$(input_field independently_tested_r1 identity)
prior_keep_core=$(input_field prior_keep_core identity)
prior_keep_core_tag=$(input_field prior_keep_core version)

# The PR owner fork does not necessarily mirror every canonical upstream tag.
# Resolve PRIOR from the repository named by the frozen input instead of
# trusting whatever tag set happens to be present in the pull-request checkout.
if ! git check-ref-format "refs/tags/$prior_keep_core_tag" >/dev/null; then
  echo "invalid frozen PRIOR tag: $prior_keep_core_tag" >&2
  exit 1
fi
prior_keep_core_root="$scratch/prior-keep-core"
git init -q "$prior_keep_core_root"
git -C "$prior_keep_core_root" remote add origin \
  https://github.com/threshold-network/keep-core.git
git -C "$prior_keep_core_root" fetch -q --depth=1 --filter=blob:none origin \
  "refs/tags/$prior_keep_core_tag:refs/tags/$prior_keep_core_tag"
require_commit \
  "$prior_keep_core_root" \
  threshold-network/keep-core \
  "$prior_keep_core"

for keep_core_commit in \
  "$baseline_source" \
  "$baseline_parent" \
  "$evaluated_candidate" \
  "$evaluated_base" \
  "$independently_tested_r1"
do
  require_commit \
    "$repository_root" \
    threshold-network/keep-core \
    "$keep_core_commit"
done

if [[ $(git -C "$repository_root" rev-parse "$baseline_source^") != \
  "$baseline_parent" ]]; then
  echo "baseline parent relation is not exact" >&2
  exit 1
fi
if ! git -C "$repository_root" merge-base --is-ancestor \
  "$independently_tested_r1" "$baseline_source"; then
  echo "independently tested R1 is not an ancestor of the frozen baseline" >&2
  exit 1
fi
if ! git -C "$repository_root" merge-base --is-ancestor \
  "$baseline_source" "$evaluated_candidate"; then
  echo "frozen baseline is not an ancestor of the evaluated candidate" >&2
  exit 1
fi
if ! git -C "$repository_root" merge-base --is-ancestor \
  "$evaluated_base" "$evaluated_candidate"; then
  echo "evaluated candidate base is not an ancestor of the candidate" >&2
  exit 1
fi
if [[ $(git -C "$prior_keep_core_root" rev-parse "$prior_keep_core_tag^{commit}") != \
  "$prior_keep_core" ]]; then
  echo "$prior_keep_core_tag does not resolve to the frozen PRIOR commit" >&2
  exit 1
fi

evaluated_go_mod="$scratch/evaluated-candidate.mod"
evaluated_go_sum="$scratch/evaluated-candidate.sum"
evaluated_go_mod_json="$scratch/evaluated-candidate.mod.json"
prior_go_mod="$scratch/prior.mod"
prior_go_sum="$scratch/prior.sum"
prior_go_mod_json="$scratch/prior.mod.json"
git -C "$repository_root" show "$evaluated_candidate:go.mod" >"$evaluated_go_mod"
git -C "$repository_root" show "$evaluated_candidate:go.sum" >"$evaluated_go_sum"
git -C "$prior_keep_core_root" show "$prior_keep_core:go.mod" >"$prior_go_mod"
git -C "$prior_keep_core_root" show "$prior_keep_core:go.sum" >"$prior_go_sum"
go mod edit -json "$evaluated_go_mod" >"$evaluated_go_mod_json"
go mod edit -json "$prior_go_mod" >"$prior_go_mod_json"

candidate_tss_commit=$(input_field candidate_tss_lib identity)
candidate_tss_version=$(input_field candidate_tss_lib version)
candidate_tss_sum=$(input_field candidate_tss_lib checksum)
prior_tss_commit=$(input_field prior_tss_lib identity)
prior_tss_version=$(input_field prior_tss_lib version)
prior_tss_sum=$(input_field prior_tss_lib checksum)
keep_common_version=$(input_field candidate_keep_common version)
keep_common_sum=$(input_field candidate_keep_common checksum)
tbtc_v2_commit=$(input_field tbtc_v2_lifecycle_reference identity)

require_commit "$scratch/tss-lib" threshold-network/tss-lib "$candidate_tss_commit"
require_commit "$scratch/tss-lib" threshold-network/tss-lib "$prior_tss_commit"
require_commit "$scratch/tbtc-v2" threshold-network/tbtc-v2 "$tbtc_v2_commit"
require_module_pin \
	"$evaluated_go_mod_json" \
	"$evaluated_go_sum" \
	github.com/bnb-chain/tss-lib \
	v1.3.5 \
	github.com/threshold-network/tss-lib \
	"$candidate_tss_version" \
	"$candidate_tss_sum"
require_module_pin \
	"$evaluated_go_mod_json" \
	"$evaluated_go_sum" \
	github.com/keep-network/keep-common \
	v1.7.1-0.20240424094333-bd36cd25bb74 \
	github.com/threshold-network/keep-common \
	"$keep_common_version" \
	"$keep_common_sum"
require_module_pin \
	"$prior_go_mod_json" \
	"$prior_go_sum" \
	github.com/bnb-chain/tss-lib \
	v1.3.5 \
	github.com/threshold-network/tss-lib \
	"$prior_tss_version" \
	"$prior_tss_sum"

if [[ $(input_field external_do_harness_reference verification) != \
  "unverified_external_scope_reference" ]]; then
  echo "private external harness must remain explicitly unverified here" >&2
  exit 1
fi

anchor_count=0
while IFS=$'\t' read -r source_repository source_commit source_path source_symbol; do
  case "$source_repository" in
    threshold-network/keep-core)
      if [[ $source_commit == "$prior_keep_core" ]]; then
        source_root=$prior_keep_core_root
      else
        source_root=$repository_root
      fi
      ;;
    threshold-network/tss-lib)
      source_root="$scratch/tss-lib"
      ;;
    threshold-network/tbtc-v2)
      source_root="$scratch/tbtc-v2"
      ;;
    *)
      echo "unsupported R00 source repository: $source_repository" >&2
      exit 1
      ;;
  esac

  require_commit "$source_root" "$source_repository" "$source_commit"
  if ! git -C "$source_root" cat-file -e "$source_commit:$source_path"; then
    echo "missing immutable source path: $source_repository@$source_commit:$source_path" >&2
    exit 1
  fi
  if ! git -C "$source_root" show "$source_commit:$source_path" |
    grep -F -- "$source_symbol" >/dev/null; then
    echo "source symbol does not resolve: $source_repository@$source_commit:$source_path: $source_symbol" >&2
    exit 1
  fi

  anchor_count=$((anchor_count + 1))
done < <(
  jq -r '
    (.cases[].source_anchors[] |
      [.repository, .commit, .path, .symbol]),
    (.cases[].head_assessment.evidence_refs[] |
      ["threshold-network/keep-core", .commit, .path, .symbol]) |
    @tsv
  ' "$catalog"
)

if [[ $anchor_count -ne 31 ]]; then
  echo "R00 source-anchor inventory changed: got $anchor_count, want 31" >&2
  exit 1
fi

printf \
  'verified frozen input relations and %d immutable R00 source anchors\n' \
  "$anchor_count"
