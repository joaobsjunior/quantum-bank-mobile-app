# Client Bootstrap Contract

Requirement: CONT-01, PKI-01

Owner: Quantum Bank Mobile App

This contract defines how the mobile app starts secure communication with
Quantum Bank APIs using OAuth2, runtime key generation, CSR submission, OTK
consumption, and gateway-only API access.

## Bootstrap Preconditions

The mobile app may begin certificate bootstrap only after:

- The user has completed the required OAuth2 authentication flow.
- The app has an `oauth2Subject` from the authenticated session.
- The app has a local `appInstanceId`.
- The app can provide a `deviceId` for local v1 binding.
- The app has selected the expected certificate profile.
- The app can reach KrakenD public bootstrap endpoints.

The expected local v1 certificate profile is
`quantum-bank-mobile-client-v1`.

## Runtime Key Material

The mobile app generates its client keypair at runtime.

Private key must not be sent to backend, gateway, or PKI.

Private key material must not be committed to the repository, bundled as an app
asset, logged, exported in diagnostics, or transmitted as part of any API
request. The private key remains under mobile runtime storage responsibility.

The mobile app treats certificate bootstrap as failed if runtime key generation
fails or if the private key cannot be stored according to the platform policy
available in local v1.

## CSR Generation

The mobile app generates a CSR from the runtime keypair.

The CSR must represent the same identity inputs that will be validated by
backend and PKI contracts:

- `oauth2Subject`
- `appInstanceId`
- `deviceId`
- `certificateProfile`
- Target environment, when the API contract requires it.

The CSR may be logged only through safe metadata such as a fingerprint or
correlation id. CSR content should not be printed in normal application logs.

## OTK Use

The mobile app obtains an OTK through the gateway after OAuth2 authentication.

The OTK is a one-time token used for a single CSR submission. The app must not
reuse an OTK after any terminal response, including success, expiration, replay,
or rejection.

The mobile app submits CSR and OTK to `POST /auth/csr` through KrakenD, never
directly to backend.

The submission includes:

- OTK value.
- CSR content.
- `appInstanceId`.
- `deviceId`.
- Requested `certificateProfile`.

The app must treat the issued certificate as bound to the generated private key.

## Phase 3 Runtime Implementation

Phase 3 implements PKI-01 in `lib/features/bootstrap/` and `lib/core/tls/`.

- D-16: Mobile generates the keypair at runtime; no static private keys or client certs are bundled.
- D-17: Mobile uses Dart `dart:io` `HttpClient` and `SecurityContext` for the mTLS-capable client path.
- D-18: Mobile fails closed and never uses `badCertificateCallback` to accept all certificates.
- D-19: Mobile models key, certificate chain, and lifecycle metadata as one certificate-ready state without logging or exporting private key material.
- D-20: Protected banking calls remain gateway-only and use `GATEWAY_BASE_URL`; no backend or PKI origin is added to mobile protected config.
- D-21: Mobile models missing, expired, untrusted, CSR rejected, OTK expired, and OTK replayed states.

Implemented state names:

- `missing`
- `ready`
- `expired`
- `untrusted`
- `csrRejected`
- `otkExpired`
- `otkReplayed`

## Certificate Storage Assumptions

The mobile app stores the issued client certificate and its lifecycle metadata
with the runtime key material.

The app must be able to determine whether a certificate is missing, expired,
untrusted, or otherwise unusable before attempting protected banking API calls.

For local v1, secure storage specifics are implementation details for later
phases, but the ownership boundary is fixed: private key and client certificate
runtime storage belong to the mobile layer.

## Gateway-Only Communication

The mobile app calls KrakenD public paths for bootstrap and protected paths for
banking APIs.

The mobile app must not call backend service hosts directly. Direct backend
access would bypass the gateway boundary, mTLS enforcement, and the OpenAPI
contract used by the other repos.

The mobile layer is responsible for configuring HTTP clients so the issued
certificate is available for mTLS when protected API endpoints require it.

## Failure States

The mobile app must represent these bootstrap failure states:

- `otkExpired`: OTK TTL elapsed before CSR submission completed.
- `otkReplayed`: OTK was already used or reached a terminal state.
- `csrRejected`: backend or PKI rejected the CSR.
- `untrusted`: certificate chain or trust anchor is not accepted.
- `missing`: protected API access was attempted without a usable client certificate.
- `expired`: certificate metadata says the certificate is no longer usable.

Failure states must preserve enough detail for troubleshooting while avoiding
token values, private key material, and sensitive CSR internals in UI text or
logs.
