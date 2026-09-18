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
  verifies the ML-DSA-65 and ECDSA P-256 CSRs with OpenSSL.

## Device Identity and Transport (post-quantum first, compatibility fallback)

Every issuer and gateway listener serves a dual identity: the ML-DSA-65
certificate to clients whose TLS stack offers ML-DSA signature schemes, the
ECDSA P-256 compatibility certificate to every other client; both prefer the
`X25519MLKEM768` hybrid key exchange and accept `X25519`. The app follows the
same split, decided once at startup:

- **Probe.** `PqcTlsSupport` tries to load the bundled ML-DSA-87 root anchor
  into a `SecurityContext`. Success selects `TransportMode.postQuantum`;
  failure selects `TransportMode.compatibility`. Nothing fails closed: both
  modes are PKI-issued, mutually authenticated transports, and the gate
  screen shows which one is active (with the platform reason in
  compatibility mode).
- **Identity.** `KeypairService.generateForTransport` produces an ML-DSA-65
  key pair (FIPS 204, pure Dart via `pqcrypto`, PKCS#8 seed-only per RFC 9881,
  the form BoringSSL accepts) in post-quantum mode, or an ECDSA P-256 key pair
  (`pointycastle`, PKCS#8 wrapping RFC 5915, deterministic RFC 6979
  signatures) in compatibility mode. `CsrService` builds the PKCS#10 request
  from either key pair (ML-DSA or `ecdsa-with-SHA256` proof of possession, same
  subject and SAN URIs); the PKI issues it under the chain of the key family.
  `scripts/verify-pqc-csr-interop.sh` proves both CSRs and both PKCS#8 keys
  with OpenSSL >= 3.5, and `tool/emit_ml_dsa_csr.dart` produces the backend
  interop fixtures.
- **Trust anchors.** `assets/local-ca/root-ca.crt` (ML-DSA-87) and
  `assets/local-ca/root-ca-compat.crt` (ECDSA P-384) are the PKI roots. The
  compatibility root is always trusted (a dual-identity listener may serve
  that chain to any ECDSA-capable client); the ML-DSA root is added in
  post-quantum mode only, because loading it on an unsupported stack throws.
- **Platform status.** `dart:io` delegates TLS to the platform BoringSSL
  build. Dart 3.11 rejects ML-DSA keys and certificates
  (`UNSUPPORTED_ALGORITHM`); Dart 3.13 parses them and verifies ML-DSA X.509
  signatures, but its BoringSSL still does not offer ML-DSA in
  `signature_algorithms` nor `X25519MLKEM768` in its default groups, and
  `SecurityContext` exposes neither setting. Until a Dart/Flutter release
  enables them, the app runs in compatibility mode on real devices (ECDSA
  P-256 identity, ECDSA server chain, X25519), and the local runtime's
  `smoke-tests`/`pqc-handshake-tests` services prove the post-quantum path
  the app will take automatically once the probe succeeds.

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
