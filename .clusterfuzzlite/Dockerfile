# ClusterFuzzLite / OSS-Fuzz build image for keep-core's native Go fuzz targets.
# base-builder-go provides the Go toolchain plus the compile_native_go_fuzzer
# helper used by build.sh.
#
# Digest-pinned: the :latest tag floats and the image is rebuilt upstream
# continuously; an unpinned base silently changes the build environment (and
# is a supply-chain vector) on every CI run. Bump the digest deliberately —
# resolve the current one with:
#   curl -s "https://gcr.io/v2/oss-fuzz-base/base-builder-go/manifests/latest" \
#     -H "Authorization: Bearer $(curl -s 'https://gcr.io/v2/token?service=gcr.io&scope=repository:oss-fuzz-base/base-builder-go:pull' | jq -r .token)" \
#     -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" -I | grep -i docker-content-digest
FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:cf761fd9baac42fff453259755067a7ad8ad70dbbe7db5027211e9fabc5cac40

# The ClusterFuzzLite build_fuzzers action supplies the checked-out repo as the
# Docker build context; copy it in and build from there.
COPY . $SRC/keep-core
WORKDIR $SRC/keep-core
COPY .clusterfuzzlite/build.sh $SRC/
