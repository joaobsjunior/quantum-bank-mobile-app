#!/usr/bin/env bash
set -euo pipefail

# Proves that the CSRs the app generates are accepted by the PKI toolchain,
# one per device key family:
#   * ML-DSA-65 (pure Dart, pqcrypto): OpenSSL >= 3.5 verifies the proof of
#     possession, reads an ML-DSA-65 public key, and the seed-only PKCS#8
#     private key (RFC 9881) re-derives the same public key;
#   * ECDSA P-256 (pointycastle): OpenSSL verifies the ecdsa-with-SHA256 proof
#     of possession, reads a P-256 key, and the PKCS#8 key matches.
# Needs Dart (or the Flutter Docker image) and OpenSSL >= 3.5 (or Docker for
# alpine/openssl).

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
flutter_image="${FLUTTER_IMAGE:-ghcr.io/cirruslabs/flutter:3.41.0}"
openssl_image="${QUANTUM_BANK_PQC_OPENSSL_IMAGE:-alpine/openssl:3.5.8}"
out_dir="${1:-$(mktemp -d "${TMPDIR:-/tmp}/quantum-bank-mobile-csr.XXXXXX")}"
mkdir -p "${out_dir}"

emit() {
  local name="$1"
  local family="$2"
  if command -v dart >/dev/null 2>&1; then
    (cd "${repo_dir}" && dart pub get >/dev/null && dart run tool/emit_ml_dsa_csr.dart "${out_dir}/${name}.csr" "${out_dir}/${name}.key" 00000000-0000-0000-0000-000000000001 "${family}")
  else
    docker run --rm -v "${repo_dir}:/app" -v "${out_dir}:/out" -w /app "${flutter_image}" \
      sh -c "dart pub get >/dev/null && dart run tool/emit_ml_dsa_csr.dart /out/${name}.csr /out/${name}.key 00000000-0000-0000-0000-000000000001 ${family}"
  fi
}

run_openssl() {
  if [[ -n "${QUANTUM_BANK_PQC_OPENSSL:-}" ]]; then
    (cd "${out_dir}" && "${QUANTUM_BANK_PQC_OPENSSL}" "$@")
  elif command -v openssl >/dev/null 2>&1 && openssl version | awk '{split($2,v,"."); exit !(v[1]>3 || (v[1]==3 && v[2]>=5))}'; then
    (cd "${out_dir}" && openssl "$@")
  else
    docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "${out_dir}:/work" -w /work "${openssl_image}" "$@"
  fi
}

# verify NAME "Public Key Algorithm line" "Signature Algorithm line" [extra grep]
verify() {
  local name="$1"
  local key_line="$2"
  local sig_line="$3"
  local extra="${4:-}"
  run_openssl req -in "${name}.csr" -noout -verify >/dev/null
  # Capture once so an early-closing grep can never SIGPIPE the openssl process.
  local csr_text
  csr_text="$(run_openssl req -in "${name}.csr" -noout -text)"
  for expected in "${key_line}" "${sig_line}" "URI:urn:quantum-bank:subject:" ${extra:+"${extra}"}; do
    if ! printf '%s\n' "${csr_text}" | grep -q "${expected}"; then
      echo "${name} CSR is missing '${expected}'" >&2
      exit 1
    fi
  done
  run_openssl req -in "${name}.csr" -noout -pubkey > "${out_dir}/${name}-csr.pub"
  run_openssl pkey -in "${name}.key" -pubout > "${out_dir}/${name}-key.pub"
  cmp -s "${out_dir}/${name}-csr.pub" "${out_dir}/${name}-key.pub" || { echo "${name}: PKCS#8 key does not match the CSR public key" >&2; exit 1; }
}

emit mobile ML-DSA-65
verify mobile "Public Key Algorithm: ML-DSA-65" "Signature Algorithm: ML-DSA-65"
# The ML-DSA key is stored seed-only (RFC 9881), the form BoringSSL accepts.
# Captured first so an early-closing grep can never SIGPIPE openssl.
key_text="$(run_openssl pkey -in mobile.key -noout -text)"
if ! printf '%s\n' "${key_text}" | grep -q '^ *seed:'; then
  echo "mobile.key is not a seed-only ML-DSA PKCS#8 key" >&2
  exit 1
fi

emit mobile-compat ECDSA-P256
verify mobile-compat "Public Key Algorithm: id-ecPublicKey" "Signature Algorithm: ecdsa-with-SHA256" "NIST CURVE: P-256"

echo "pqc-csr-interop-ok (${out_dir})"
