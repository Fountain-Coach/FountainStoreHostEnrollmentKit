# FountainStoreHostEnrollmentKit

Provider-neutral FCIS-KIT contracts and deterministic lifecycle fixture for Chapter 97 host bootstrap and enrollment.

The package also owns the FCIS-KIT instrument contract `fountainstore.credential.provision` (v0.1.0). It defines
the request, terminal receipt, and scenario for creating an opaque FountainStore credential. Generation and custody
remain host-adapter responsibilities; this package never receives or returns a credential value.

This package owns typed bootstrap, enrollment, status, rotation, revocation, lifecycle, and refusal contracts. It has
no Reframe, FountainStore schema, provider SDK, SSH, Keychain, TLS, or credential-value dependency.

The deterministic service is a contract fixture only. Its passing tests do not establish Hetzner/AWS authorization,
host-agent readiness, TLS, production deployment, or external security review.

Status: candidate / locally tested; the credential-provisioning contract is declared but not released or publicly
admitted.

The candidate also defines signed bootstrap descriptors and a provider-neutral `HostAgentTransport` boundary. The
deterministic transport verifies signatures, expiry, exact target, host identity, artifact digest, idempotency, and
revocation while performing no network or provider operation.
