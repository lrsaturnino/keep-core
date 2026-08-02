#!/usr/bin/env bash

# Selects the Docker tags published for one release tag. Every release gets a
# versioned image. Only an exact stable vMAJOR.MINOR.PATCH release may move the
# mutable latest and mainnet aliases; a prerelease or any unrecognized version
# shape is isolated to its versioned tag.

set -euo pipefail

if (($# != 2)); then
  echo "usage: $0 <dockerhub-namespace> <release-version>" >&2
  exit 2
fi

dockerhub_namespace="$1"
release_version="$2"

if [[ ! "${dockerhub_namespace}" =~ ^[a-z0-9]+([._-][a-z0-9]+)*$ ]]; then
  echo "invalid Docker Hub namespace [${dockerhub_namespace}]" >&2
  exit 2
fi

if [[ ! "${release_version}" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
  echo "invalid Docker tag [${release_version}]" >&2
  exit 2
fi

repository="${dockerhub_namespace}/keep-client"
printf '%s:%s\n' "${repository}" "${release_version}"

if [[ "${release_version}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  printf '%s:latest\n' "${repository}"
  printf '%s:mainnet\n' "${repository}"
fi
