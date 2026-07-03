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
  behavior and gateway-only config.

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
