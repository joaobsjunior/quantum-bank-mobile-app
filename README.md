# Quantum Bank Mobile App

Flutter 3.41 mobile application for the Quantum Bank user journeys:

- Pix transfer
- Account statement
- Customer registration data

The app must communicate with backend services through KrakenD and exercise the security onboarding flow before protected API access.

## Phase 1 Contract Ownership

The mobile app owns and consumes these Phase 1 contracts:

- [Client Bootstrap Contract](docs/contracts/client-bootstrap.md) for CONT-01 runtime key generation, CSR creation, OTK use, certificate storage assumptions, and gateway-only bootstrap.
- [API Client Contract](docs/contracts/api-client-contract.md) for CONT-02 gateway-only API usage, client preconditions, Pix scenario submission, and problem-details parsing.

Later mobile implementation must keep protected API calls pointed at KrakenD and must not introduce direct backend origins.

## Phase 2 Gateway-Only Config

Protected API calls use [config/api.env.example](config/api.env.example) with
gateway-named origins only.

Run [scripts/verify-gateway-only.sh](scripts/verify-gateway-only.sh) to check
runtime source and config for forbidden backend origin strings.

## Phase 3 Certificate-Ready Clients

Phase 3 adds runtime key generation, CSR creation, certificate-ready state, and
fail-closed mTLS client setup.

- `lib/features/bootstrap/` creates runtime key material, builds CSR input, and
  submits bootstrap requests through the gateway bootstrap listener.
- `lib/core/tls/secure_context_factory.dart` builds `SecurityContext` with
  explicit trust anchors and client certificate material.
- `lib/core/api/banking_client.dart` requires certificate-ready state before
  protected banking calls.
- Local config now uses `GATEWAY_BOOTSTRAP_BASE_URL=https://localhost:8080` for
  bootstrap and `GATEWAY_BASE_URL=https://localhost:8443` for protected banking.
- `dart test` and `bash scripts/verify-gateway-only.sh` verify certificate-ready
  behavior and gateway-only config; `bash scripts/verify-pqc-csr-interop.sh`
  verifies the ML-DSA CSR with OpenSSL.

## Post-Quantum Identity and Transport

- **Identity is ML-DSA.** `KeypairService` generates an ML-DSA-65 key pair
  (FIPS 204, pure Dart via `pqcrypto`), encodes the private key as PKCS#8 (seed
  and expanded key), and `CsrService` builds a PKCS#10 request whose subject
  key and proof-of-possession signature are ML-DSA-65 with the identity SAN
  URIs. The CSR verifies with OpenSSL >= 3.5 and BouncyCastle:
  `scripts/verify-pqc-csr-interop.sh` proves it and
  `tool/emit_ml_dsa_csr.dart` produces the backend interop fixture.
- **Trust anchor is ML-DSA-87.** `assets/local-ca/root-ca.crt` is the PKI root
  (regenerated together with `pki/local-ca/trust/root-ca.crt`).
- **Transport is post-quantum only and fails closed.** Every issuer and gateway
  listener negotiates TLS 1.3 with `X25519MLKEM768` and ML-DSA signatures.
  `dart:io` delegates TLS to the platform BoringSSL build, which in Dart 3.11
  rejects ML-DSA keys and certificates (`UNSUPPORTED_ALGORITHM`). At startup
  `PqcTlsSupport` probes that capability with the bundled anchor; when the stack
  cannot load ML-DSA material the app keeps protected access closed and shows
  the platform error instead of attempting a classical handshake. The device
  transport therefore waits on a TLS engine with ML-DSA support (a Dart/Flutter
  BoringSSL update or a native TLS plugin); the local runtime's `smoke-tests`
  service (curl + OpenSSL 3.5) exercises the exact mobile role end to end in
  the meantime.

## Phase 5 Flutter Screens

The Flutter app now gates protected screens on authenticated and
certificate-ready state, then exposes:

- Pix success/error simulation screen.
- Statement screen loaded through the gateway API abstraction.
- Customer registration profile screen with `PUT /profile` editing via
  `profile:write`.

## Testing & CI

- Run tests with coverage: `flutter test --coverage` (emits
  `coverage/lcov.info`).
- Enforce the coverage gate: `./scripts/check-coverage.sh 100 coverage/lcov.info`
  fails when line coverage is below **100%**.
- CI (`.github/workflows/ci.yml`) sets up Flutter 3.41, runs `flutter analyze`,
  tests with coverage, and enforces the 100% gate on every push/PR to `main`.

## Runtime Requirements

The mobile app is a Flutter client — it is **not** part of `docker-compose`. It
runs from a developer machine against the local gateway stack.

### Recommended developer setup

| Resource | Recommended |
| --- | --- |
| Toolchain | **Flutter 3.41 / Dart ≥ 3.11** |
| Memory | **8 GB** machine (the Android emulator alone uses 2–4 GB) |
| CPU | **4 vCPU** for smooth builds and the emulator |
| Disk | **~5 GB** (Flutter SDK + Android SDK/emulator + build cache) |

### Good to know

- Needs the Android SDK/emulator, or macOS + Xcode for iOS, in addition to the
  Flutter SDK.
- Point the app at the local gateway:
  `GATEWAY_BOOTSTRAP_BASE_URL=https://localhost:8080` (bootstrap) and
  `GATEWAY_BASE_URL=https://localhost:8443` (protected banking).
