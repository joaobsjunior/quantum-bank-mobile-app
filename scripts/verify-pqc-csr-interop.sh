#!/usr/bin/env bash
set -euo pipefail

# Proves that the CSR the app generates (pure-Dart ML-DSA-65) is accepted by
# the PKI toolchain: OpenSSL >= 3.5 verifies the proof-of-possession
# signature, reads an ML-DSA-65 public key, and the PKCS#8 private key
# re-derives the same public key. Needs Dart (or the Flutter Docker image) and
# OpenSSL >= 3.5 (or Docker for alpine/openssl).

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
flutter_image="${FLUTTER_IMAGE:-ghcr.io/cirruslabs/flutter:3.41.0}"
openssl_image="${QUANTUM_BANK_PQC_OPENSSL_IMAGE:-alpine/openssl:3.5.8}"
out_dir="${1:-$(mktemp -d "${TMPDIR:-/tmp}/quantum-bank-mobile-csr.XXXXXX")}"
mkdir -p "${out_dir}"

if command -v dart >/dev/null 2>&1; then
  (cd "${repo_dir}" && dart pub get >/dev/null && dart run tool/emit_ml_dsa_csr.dart "${out_dir}/mobile.csr" "${out_dir}/mobile.key")
else
  docker run --rm -v "${repo_dir}:/app" -v "${out_dir}:/out" -w /app "${flutter_image}" \
    sh -c 'dart pub get >/dev/null && dart run tool/emit_ml_dsa_csr.dart /out/mobile.csr /out/mobile.key'
fi

run_openssl() {
  if command -v openssl >/dev/null 2>&1 && openssl version | awk '{split($2,v,"."); exit !(v[1]>3 || (v[1]==3 && v[2]>=5))}'; then
    (cd "${out_dir}" && openssl "$@")
  else
    docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "${out_dir}:/work" -w /work "${openssl_image}" "$@"
  fi
}

run_openssl req -in mobile.csr -noout -verify >/dev/null
# Capture once so an early-closing grep can never SIGPIPE the openssl process.
csr_text="$(run_openssl req -in mobile.csr -noout -text)"
for expected in "Public Key Algorithm: ML-DSA-65" "Signature Algorithm: ML-DSA-65" "URI:urn:quantum-bank:subject:"; do
  if ! printf '%s\n' "${csr_text}" | grep -q "${expected}"; then
    echo "mobile CSR is missing '${expected}'" >&2
    exit 1
  fi
done
run_openssl req -in mobile.csr -noout -pubkey > "${out_dir}/csr.pub"
run_openssl pkey -in mobile.key -pubout > "${out_dir}/key.pub"
cmp -s "${out_dir}/csr.pub" "${out_dir}/key.pub" || { echo "PKCS#8 key does not match the CSR public key" >&2; exit 1; }

echo "pqc-csr-interop-ok (${out_dir})"
