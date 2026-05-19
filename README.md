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
