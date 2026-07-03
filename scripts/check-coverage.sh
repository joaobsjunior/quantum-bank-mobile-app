#!/usr/bin/env bash
set -euo pipefail

# Deterministic numeric formatting regardless of the host locale.
export LC_ALL=C

# Enforces the mobile line-coverage gate (test-coverage-enforcement capability).
# Parses coverage/lcov.info (produced by `flutter test --coverage`) and fails
# when total line coverage is below the required threshold. Uses awk so it needs
# no external lcov binary.
#
# Usage: scripts/check-coverage.sh [threshold] [lcov_file]
#   threshold  minimum line coverage percentage (default: 100)
#   lcov_file  path to lcov report (default: coverage/lcov.info)

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"

threshold="${1:-100}"
lcov_file="${2:-${repo_dir}/coverage/lcov.info}"

if [[ ! -f "${lcov_file}" ]]; then
  echo "missing coverage report: ${lcov_file}" >&2
  echo "run: flutter test --coverage" >&2
  exit 1
fi

awk -v threshold="${threshold}" '
  /^LF:/ { found += substr($0, 4) }
  /^LH:/ { hit   += substr($0, 4) }
  END {
    if (found == 0) {
      print "no lines found in coverage report" > "/dev/stderr"
      exit 1
    }
    pct = (hit / found) * 100
    printf "line coverage: %.2f%% (%d/%d lines) threshold: %s%%\n", pct, hit, found, threshold
    if (pct + 1e-9 < threshold) {
      printf "coverage %.2f%% is below threshold %s%%\n", pct, threshold > "/dev/stderr"
      exit 1
    }
  }
' "${lcov_file}"

echo "coverage-ok"
