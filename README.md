# FountainStoreHostEnrollmentKit

Provider-neutral FCIS-KIT contracts and deterministic lifecycle fixture for Chapter 97 host bootstrap and enrollment.

The package also owns the FCIS-KIT instrument contracts `fountainstore.credential.provision` (v0.2.0) and
`fountainstore.credential.seed` (v0.1.0). The seed instrument defines
the request, terminal receipt, scenario, and Swift URLSession transport for handing an opaque FountainStore
credential to an authenticated remote host-agent. Generation and custody remain host-adapter responsibilities;
credential values are never Codable, MIDI2, receipts, telemetry, or logs.

This package owns typed bootstrap, enrollment, status, rotation, revocation, lifecycle, and refusal contracts. It has
no Reframe, FountainStore schema, provider SDK, SSH, Keychain, TLS, or credential-value dependency.

The deterministic service is a contract fixture only. Its passing tests do not establish Hetzner/AWS authorization,
host-agent readiness, TLS, production deployment, or external security review.

Status: candidate / locally tested; the credential-provisioning contract is declared but not released or publicly
admitted.

The package also defines signed bootstrap descriptors and a provider-neutral `HostAgentTransport` boundary. The
deterministic transports verify signatures, expiry, exact target, host identity, artifact digest, idempotency, and
revocation. The URLSession transport requires an explicitly admitted HTTPS endpoint, authenticates with the enrolled
host credential, and validates a redacted terminal receipt; it performs no provider operation itself.
