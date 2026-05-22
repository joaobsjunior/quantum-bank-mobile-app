#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/.." && pwd)"

config_file="$repo_dir/config/api.env.example"
expected_bootstrap_origin="GATEWAY_BOOTSTRAP_BASE_URL=https://localhost:8080"
expected_protected_origin="GATEWAY_BASE_URL=https://localhost:8443"

if [[ ! -f "$config_file" ]]; then
  echo "missing mobile gateway config: $config_file" >&2
  exit 1
fi

if ! grep -Fxq "$expected_bootstrap_origin" "$config_file"; then
  echo "mobile gateway config must contain exactly: $expected_bootstrap_origin" >&2
  exit 1
fi

if ! grep -Fxq "$expected_protected_origin" "$config_file"; then
  echo "mobile gateway config must contain exactly: $expected_protected_origin" >&2
  exit 1
fi

config_lines="$(grep -Ev '^[[:space:]]*(#|$)' "$config_file" | wc -l | tr -d '[:space:]')"
if [[ "$config_lines" != "2" ]]; then
  echo "mobile gateway config must expose only gateway-named origins" >&2
  exit 1
fi

search_dirs=()
for dir in config lib test integration_test android ios web; do
  if [[ -d "$repo_dir/$dir" ]]; then
    search_dirs+=("$repo_dir/$dir")
  fi
done

for pattern in BACKEND_BASE_URL PKI_BASE_URL "backend:" "localhost:8081" "http://backend"; do
  if [[ ${#search_dirs[@]} -gt 0 ]] && grep -RIn --exclude-dir=scripts --exclude-dir=docs -- "$pattern" "${search_dirs[@]}"; then
    echo "forbidden protected API origin found: $pattern" >&2
    exit 1
  fi
done

echo "gateway-only-ok"
