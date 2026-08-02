#!/usr/bin/env bash

# Resolves the exact tag that triggered a release workflow run. The release
# identity must come from the triggering ref, never from repository tag
# discovery: multiple stable and prerelease tags may legitimately point at the
# same commit, and git describe cannot say which one caused the run.

set -euo pipefail

if (($# != 2)); then
  echo "usage: $0 <trigger-ref> <trigger-ref-name>" >&2
  exit 2
fi

trigger_ref="$1"
trigger_ref_name="$2"

if [[ "${trigger_ref}" != refs/tags/* ]]; then
  echo "release workflow was not triggered by a tag ref [${trigger_ref}]" >&2
  exit 2
fi

if [[ "${trigger_ref_name}" != v* ]]; then
  echo "release tag must begin with v [${trigger_ref_name}]" >&2
  exit 2
fi

if [[ "${trigger_ref}" != "refs/tags/${trigger_ref_name}" ]]; then
  echo "trigger ref [${trigger_ref}] does not match trigger ref name [${trigger_ref_name}]" >&2
  exit 2
fi

# Docker tags are limited to 128 ASCII characters and this is the same shape
# release-docker-tags.sh accepts. Keeping the release identity within that
# shape makes every later versioned image name representable; semantic stable
# release classification remains the Docker-tag selector's responsibility.
if [[ ! "${trigger_ref_name}" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
  echo "triggering release tag is not a valid Docker tag [${trigger_ref_name}]" >&2
  exit 2
fi

printf '%s\n' "${trigger_ref_name}"
