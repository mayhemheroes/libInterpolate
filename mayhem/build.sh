#!/usr/bin/env bash
#
# mayhem/build.sh — build the fuzz harness (sanitized) + the upstream Catch2 test suite.
# libInterpolate is a header-only C++17 library (Boost + Eigen3), so compiling the harness
# with $SANITIZER_FLAGS instruments the library code itself.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

CXXFLAGS_COMMON="-std=c++17 -O1 -I$SRC/src -isystem /usr/include/eigen3"

# 1+2) Fuzzer + standalone reproducer (header-only lib — harness build IS the project build).
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $CXXFLAGS_COMMON $LIB_FUZZING_ENGINE \
    "$SRC/mayhem/fuzz_interpolate.cpp" -o /mayhem/fuzz_interpolate

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $CXXFLAGS_COMMON \
    "$SRC/mayhem/fuzz_interpolate.cpp" /tmp/standalone_main.o -o /mayhem/fuzz_interpolate-standalone

# 3) Upstream Catch2 test suite, NORMAL flags (what upstream CI runs via ctest).
#    TEST_WITH_WERROR=OFF: upstream pins gcc-13; newer clang warnings would false-fail the suite.
cmake -S . -B build-tests \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS:BOOL=ON \
    -DTEST_WITH_WERROR:BOOL=OFF \
    -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
    -DlibInterpolate_FULL_VERSION="$(git -C "$SRC" describe --tags --always 2>/dev/null || echo 0.0.0-mayhem)"
cmake --build build-tests -j"$MAYHEM_JOBS"

test -x build-tests/testing/libInterpolate_CatchTests
