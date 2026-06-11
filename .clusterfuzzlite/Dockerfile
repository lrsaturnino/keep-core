# ClusterFuzzLite / OSS-Fuzz build image for keep-core's native Go fuzz targets.
# base-builder-go provides the Go toolchain plus the compile_native_go_fuzzer
# helper used by build.sh.
FROM gcr.io/oss-fuzz-base/base-builder-go

# The ClusterFuzzLite build_fuzzers action supplies the checked-out repo as the
# Docker build context; copy it in and build from there.
COPY . $SRC/keep-core
WORKDIR $SRC/keep-core
COPY .clusterfuzzlite/build.sh $SRC/
