# API Client Contract

Requirement: CONT-02

Additional requirement: GATE-01

Owner: Quantum Bank Mobile App

This contract defines how the Flutter mobile app consumes Quantum Bank APIs
through the gateway.

KrakenD is the only protected API origin.

Phase 2 protected API configuration uses only
`GATEWAY_BASE_URL=http://localhost:8080`.

The app must not configure backend service hosts as protected API origins. All
app-facing routes come from `api-gateway/openapi/quantum-bank-v1.yaml`.

## Preconditions

The mobile API client may call protected banking APIs only when these
preconditions are true:

- `authenticated`: the user has a valid OAuth2 session for gateway requests.
- `certificateReady`: the app has a usable client certificate for mTLS-protected
  calls.
- `gatewayBaseUrlConfigured`: the app has a configured KrakenD base URL.

Bootstrap calls may happen before `certificateReady` when the route contract
allows OAuth2 bearer authentication without mobile client mTLS.

## Gateway Origin

The client base URL points to KrakenD.

The client must call:

- `POST /auth/otk`
- `POST /auth/csr`
- `POST /pix/transfers`
- `GET /statements`
- `GET /profile`

The app must not call backend implementation paths, internal service names,
container network aliases, or backend ports.

Forbidden protected API origin strings include `BACKEND_BASE_URL`, `backend:`,
`localhost:8081`, and `http://backend`.

## Auth Bootstrap Calls

`POST /auth/otk` requests a one-time token after authentication.

`POST /auth/csr` submits the runtime CSR and OTK through KrakenD, never directly
to backend.

The client must treat OTK expiration, replay, CSR rejection, missing
certificate, and untrusted certificate states as explicit bootstrap failures.

## Protected Banking Calls

`POST /pix/transfers`, `GET /statements`, and `GET /profile` require the
authenticated and certificate-ready client state expected by the gateway
contract.

The mobile client attaches the OAuth2 bearer token and uses the runtime client
certificate when protected routes require mTLS.

## Phase 2 Gateway Configuration

The mobile app reads protected API calls from `GATEWAY_BASE_URL` only. The local
example value is `GATEWAY_BASE_URL=http://localhost:8080`, matching the KrakenD
OpenAPI server.

Mobile runtime source and config must pass `scripts/verify-gateway-only.sh` so
protected banking calls cannot bypass KrakenD.

## Pix Simulation Contract

Pix scenario values `SUCCESS` and `ERROR` are sent by the app and interpreted by
backend.

`SUCCESS` is used by the app to exercise the completed transfer flow. `ERROR`
is used by the app to exercise controlled failure UX and problem details
parsing.

The app must not infer Pix errors from random network behavior during local v1
testing.

## Problem Details Handling

The mobile client parses `application/problem+json` responses into a stable
error model.

The model must include:

- `type`
- `title`
- `status`
- `errorCode`
- `correlationId`
- Optional `detail`
- Optional `instance`
- Optional `fieldErrors`

The app may display safe titles and details, but it must not display token
values, private key material, CSR internals, backend hostnames, or PKI internals.

## Ownership Boundary

Mobile owns client state, gateway base URL configuration, request construction,
certificate readiness checks, and problem-details parsing.

KrakenD owns the public route boundary and security enforcement. Backend owns
business behavior. PKI owns certificate lifecycle.
