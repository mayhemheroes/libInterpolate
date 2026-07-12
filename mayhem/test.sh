#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the upstream Catch2 test suite built by mayhem/build.sh.
# This is the full suite upstream CI runs (cmake --build build --target test → ctest →
# libInterpolate_CatchTests). The 2 CramTests (build.t, interp-cli.t) are SKIPPED: they
# require a network `git clone` + conan install and are not run by upstream CI either.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

RUNNER="$SRC/build-tests/testing/libInterpolate_CatchTests"
if [ ! -x "$RUNNER" ]; then
  echo "FATAL: test runner missing — mayhem/build.sh must build it" >&2
  emit_ctrf "catch2" 0 1 0
  exit 1
fi

# Run from the testing build dir (test data is copied there); Catch2 asserts known-answer
# interpolation values internally.
out="$(cd "$SRC/build-tests/testing" && "$RUNNER" 2>&1)"
rc=$?
echo "$out" | tail -20

# Catch2 v3 console summary:
#   "All tests passed (N assertions in M test cases)"       — all green
#   "test cases: T | P passed | F failed"                   — with failures
passed=0; failed=0; skipped=0
if line="$(echo "$out" | grep -Eo 'All tests passed \([0-9]+ assertions in [0-9]+ test cases?\)')" && [ -n "$line" ]; then
  passed="$(echo "$line" | grep -Eo 'in [0-9]+ test' | grep -Eo '[0-9]+')"
elif line="$(echo "$out" | grep -E '^test cases:' | tail -1)" && [ -n "$line" ]; then
  passed="$(echo "$line" | grep -Eo '[0-9]+ passed' | grep -Eo '[0-9]+' || echo 0)"
  failed="$(echo "$line" | grep -Eo '[0-9]+ failed' | grep -Eo '[0-9]+' || echo 0)"
  skipped="$(echo "$line" | grep -Eo '[0-9]+ skipped' | grep -Eo '[0-9]+' || echo 0)"
else
  echo "FATAL: could not parse Catch2 summary (runner rc=$rc)" >&2
  emit_ctrf "catch2" 0 1 0
  exit 1
fi

emit_ctrf "catch2" "$passed" "$failed" "$skipped"
