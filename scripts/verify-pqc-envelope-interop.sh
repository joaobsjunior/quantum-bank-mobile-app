#!/usr/bin/env bash
set -euo pipefail

# Proves that the application envelope's primitives interoperate with an
# independent implementation (feature 012):
#   * the ML-KEM-768 ciphertext the app produces (pqcrypto) decapsulates with
#     OpenSSL >= 3.5 to the same shared secret;
#   * the X25519 ephemeral key the app produces (package:cryptography) derives
#     the same shared secret with OpenSSL;
#   * the PKCS#8 encodings the fixture uses are readable by OpenSSL.
# The AEAD/KDF half is covered by the backend test suite, which opens the same
# fixture with BouncyCastle (`backend/src/test/resources/pqc/envelope-fixture.json`).
# Needs Dart (or the Flutter Docker image) and OpenSSL >= 3.5 (or Docker for
# alpine/openssl).

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
flutter_image="${FLUTTER_IMAGE:-ghcr.io/cirruslabs/flutter:3.41.0}"
openssl_image="${QUANTUM_BANK_PQC_OPENSSL_IMAGE:-alpine/openssl:3.5.8}"
out_dir="${1:-$(mktemp -d "${TMPDIR:-/tmp}/quantum-bank-envelope.XXXXXX")}"
mkdir -p "${out_dir}"

if command -v dart >/dev/null 2>&1; then
  (cd "${repo_dir}" && dart pub get >/dev/null && dart run tool/emit_envelope_fixture.dart "${out_dir}")
else
  docker run --rm -v "${repo_dir}:/app" -v "${out_dir}:/out" -w /app "${flutter_image}" \
    sh -c "dart pub get >/dev/null && dart run tool/emit_envelope_fixture.dart /out"
fi

run_openssl() {
  if [[ -n "${QUANTUM_BANK_PQC_OPENSSL:-}" ]]; then
    (cd "${out_dir}" && "${QUANTUM_BANK_PQC_OPENSSL}" "$@")
  elif command -v openssl >/dev/null 2>&1 && openssl version | awk '{split($2,v,"."); exit !(v[1]>3 || (v[1]==3 && v[2]>=5))}'; then
    (cd "${out_dir}" && openssl "$@")
  else
    docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "${out_dir}:/work" -w /work "${openssl_image}" "$@"
  fi
}

# ML-KEM-768: OpenSSL reads the seed-only PKCS#8 key and decapsulates the
# app's ciphertext to the shared secret the app computed.
run_openssl pkey -in mlkem.key -noout -text | grep -q "ML-KEM-768" || { echo "mlkem.key is not an ML-KEM-768 key" >&2; exit 1; }
run_openssl pkeyutl -decap -inkey mlkem.key -in mlkem-ct.bin -secret mlkem-ss.openssl.bin
cmp -s "${out_dir}/mlkem-ss.bin" "${out_dir}/mlkem-ss.openssl.bin" || { echo "ML-KEM-768 shared secret mismatch between pqcrypto and OpenSSL" >&2; exit 1; }

# X25519: OpenSSL derives the same shared secret from the backend private
# key and the app's ephemeral public key.
run_openssl pkey -in x25519.key -noout -text | grep -q "X25519" || { echo "x25519.key is not an X25519 key" >&2; exit 1; }
run_openssl pkeyutl -derive -inkey x25519.key -peerkey x25519-eph.pub -out x25519-ss.openssl.bin
cmp -s "${out_dir}/x25519-ss.bin" "${out_dir}/x25519-ss.openssl.bin" || { echo "X25519 shared secret mismatch between package:cryptography and OpenSSL" >&2; exit 1; }

echo "envelope-interop-ok ${out_dir}"
