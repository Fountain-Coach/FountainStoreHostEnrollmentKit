# FountainStoreHostEnrollmentKit

Provider-neutral FCIS-KIT contracts and deterministic lifecycle fixture for Chapter 97 host bootstrap and enrollment.

This package owns typed bootstrap, enrollment, status, rotation, revocation, lifecycle, and refusal contracts. It has
no Reframe, FountainStore schema, provider SDK, SSH, Keychain, TLS, or credential-value dependency.

The deterministic service is a contract fixture only. Its passing tests do not establish Hetzner/AWS authorization,
host-agent readiness, TLS, production deployment, or external security review.

Status: candidate / locally tested; not released or publicly admitted.
