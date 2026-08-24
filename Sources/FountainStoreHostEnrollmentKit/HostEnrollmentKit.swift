import Foundation

public struct SecretStoreReference: Codable, Equatable, Sendable {
    public let service: String
    public let account: String

    public init(service: String, account: String) {
        self.service = service
        self.account = account
    }
}

public enum HostLifecycleState: String, Codable, Sendable {
    case candidate
    case bootstrapped
    case identityPending = "identity-pending"
    case enrollmentPending = "enrollment-pending"
    case enrolled
    case ready
    case revoked
    case expired
    case refused
    case replayed
    case failed
}

public struct HostBootstrapRequest: Codable, Equatable, Sendable {
    public let provider: String
    public let target: String
    public let artifactVersion: String
    public let artifactDigest: String
    public let bootstrapDescriptorDigest: String
    public let secretReference: SecretStoreReference
    public let idempotencyKey: String
    public let expiresAt: Date

    public init(provider: String, target: String, artifactVersion: String, artifactDigest: String,
                bootstrapDescriptorDigest: String, secretReference: SecretStoreReference,
                idempotencyKey: String, expiresAt: Date) {
        self.provider = provider
        self.target = target
        self.artifactVersion = artifactVersion
        self.artifactDigest = artifactDigest
        self.bootstrapDescriptorDigest = bootstrapDescriptorDigest
        self.secretReference = secretReference
        self.idempotencyKey = idempotencyKey
        self.expiresAt = expiresAt
    }
}

public struct HostBootstrapReceipt: Codable, Equatable, Sendable {
    public let provider: String
    public let target: String
    public let state: HostLifecycleState
    public let hostIdentity: String?
    public let bootstrapDescriptorDigest: String
    public let evidence: [String]

    public init(provider: String, target: String, state: HostLifecycleState, hostIdentity: String? = nil,
                bootstrapDescriptorDigest: String, evidence: [String] = []) {
        self.provider = provider
        self.target = target
        self.state = state
        self.hostIdentity = hostIdentity
        self.bootstrapDescriptorDigest = bootstrapDescriptorDigest
        self.evidence = evidence
    }
}

public struct HostEnrollmentRequest: Codable, Equatable, Sendable {
    public let target: String
    public let hostIdentity: String
    public let enrollmentChallengeReference: String
    public let agentEndpoint: URL
    public let agentPublicKeyFingerprint: String
    public let secretReference: SecretStoreReference
    public let scope: String
    public let idempotencyKey: String
    public let expiresAt: Date

    public init(target: String, hostIdentity: String, enrollmentChallengeReference: String,
                agentEndpoint: URL, agentPublicKeyFingerprint: String,
                secretReference: SecretStoreReference, scope: String,
                idempotencyKey: String, expiresAt: Date) {
        self.target = target
        self.hostIdentity = hostIdentity
        self.enrollmentChallengeReference = enrollmentChallengeReference
        self.agentEndpoint = agentEndpoint
        self.agentPublicKeyFingerprint = agentPublicKeyFingerprint
        self.secretReference = secretReference
        self.scope = scope
        self.idempotencyKey = idempotencyKey
        self.expiresAt = expiresAt
    }
}

public struct HostEnrollmentReceipt: Codable, Equatable, Sendable {
    public let target: String
    public let hostIdentity: String
    public let state: HostLifecycleState
    public let agentPublicKeyFingerprint: String
    public let credentialReference: SecretStoreReference
    public let evidence: [String]

    public init(target: String, hostIdentity: String, state: HostLifecycleState,
                agentPublicKeyFingerprint: String, credentialReference: SecretStoreReference,
                evidence: [String] = []) {
        self.target = target
        self.hostIdentity = hostIdentity
        self.state = state
        self.agentPublicKeyFingerprint = agentPublicKeyFingerprint
        self.credentialReference = credentialReference
        self.evidence = evidence
    }
}

public struct HostStatusRequest: Codable, Equatable, Sendable {
    public let target: String
    public let hostIdentity: String
    public let secretReference: SecretStoreReference
    public let idempotencyKey: String
    public let expiresAt: Date

    public init(target: String, hostIdentity: String, secretReference: SecretStoreReference,
                idempotencyKey: String, expiresAt: Date) {
        self.target = target
        self.hostIdentity = hostIdentity
        self.secretReference = secretReference
        self.idempotencyKey = idempotencyKey
        self.expiresAt = expiresAt
    }
}

public struct HostStatusReceipt: Codable, Equatable, Sendable {
    public let target: String
    public let hostIdentity: String
    public let state: HostLifecycleState
    public let agentBuildDigest: String?
    public let evidence: [String]

    public init(target: String, hostIdentity: String, state: HostLifecycleState,
                agentBuildDigest: String? = nil, evidence: [String] = []) {
        self.target = target
        self.hostIdentity = hostIdentity
        self.state = state
        self.agentBuildDigest = agentBuildDigest
        self.evidence = evidence
    }
}

public struct HostEnrollmentPolicy: Equatable, Sendable {
    public let target: String
    public let hostIdentity: String
    public let agentPublicKeyFingerprint: String
    public let allowedScope: String
    public let credentialReference: SecretStoreReference
    public let agentBuildDigest: String

    public init(target: String, hostIdentity: String, agentPublicKeyFingerprint: String,
                allowedScope: String, credentialReference: SecretStoreReference,
                agentBuildDigest: String) {
        self.target = target
        self.hostIdentity = hostIdentity
        self.agentPublicKeyFingerprint = agentPublicKeyFingerprint
        self.allowedScope = allowedScope
        self.credentialReference = credentialReference
        self.agentBuildDigest = agentBuildDigest
    }
}

public enum HostEnrollmentRefusal: Error, Equatable, Sendable {
    case expired
    case replayed
    case targetMismatch
    case identityMismatch
    case fingerprintMismatch
    case scopeInsufficient
    case notEnrollable
    case revoked
}

/// Deterministic lifecycle authority for contract and fixture tests. It deliberately has no network, provider,
/// Keychain, SSH, TLS, or credential-value access. A real adapter must implement the same boundary outside this kit.
public actor DeterministicHostEnrollmentService {
    private let policy: HostEnrollmentPolicy
    private var consumedChallenges: Set<String> = []
    private var idempotencyKeys: Set<String> = []
    private var state: HostLifecycleState = .candidate

    public init(policy: HostEnrollmentPolicy) {
        self.policy = policy
    }

    public func bootstrap(_ request: HostBootstrapRequest, now: Date) throws -> HostBootstrapReceipt {
        try validateExpiry(request.expiresAt, now: now)
        guard request.target == policy.target else { throw HostEnrollmentRefusal.targetMismatch }
        try reserveIdempotency(request.idempotencyKey)
        state = .bootstrapped
        return HostBootstrapReceipt(
            provider: request.provider,
            target: request.target,
            state: state,
            hostIdentity: policy.hostIdentity,
            bootstrapDescriptorDigest: request.bootstrapDescriptorDigest,
            evidence: ["fixture:exact-target", "fixture:descriptor-digest"])
    }

    public func enroll(_ request: HostEnrollmentRequest, now: Date) throws -> HostEnrollmentReceipt {
        try validateExpiry(request.expiresAt, now: now)
        if consumedChallenges.contains(request.enrollmentChallengeReference) {
            throw HostEnrollmentRefusal.replayed
        }
        guard state == .bootstrapped || state == .enrollmentPending else { throw HostEnrollmentRefusal.notEnrollable }
        guard request.target == policy.target else { throw HostEnrollmentRefusal.targetMismatch }
        guard request.hostIdentity == policy.hostIdentity else { throw HostEnrollmentRefusal.identityMismatch }
        guard request.agentPublicKeyFingerprint == policy.agentPublicKeyFingerprint else { throw HostEnrollmentRefusal.fingerprintMismatch }
        guard request.scope == policy.allowedScope else { throw HostEnrollmentRefusal.scopeInsufficient }
        try reserveIdempotency(request.idempotencyKey)
        consumedChallenges.insert(request.enrollmentChallengeReference)
        state = .enrolled
        return HostEnrollmentReceipt(
            target: request.target,
            hostIdentity: request.hostIdentity,
            state: state,
            agentPublicKeyFingerprint: request.agentPublicKeyFingerprint,
            credentialReference: policy.credentialReference,
            evidence: ["fixture:challenge-consumed", "fixture:identity-match", "fixture:fingerprint-match"])
    }

    public func status(_ request: HostStatusRequest, now: Date) throws -> HostStatusReceipt {
        try validateExpiry(request.expiresAt, now: now)
        guard request.target == policy.target else { throw HostEnrollmentRefusal.targetMismatch }
        guard request.hostIdentity == policy.hostIdentity else { throw HostEnrollmentRefusal.identityMismatch }
        guard state == .enrolled || state == .ready else { throw HostEnrollmentRefusal.notEnrollable }
        state = .ready
        return HostStatusReceipt(
            target: request.target,
            hostIdentity: request.hostIdentity,
            state: state,
            agentBuildDigest: policy.agentBuildDigest,
            evidence: ["fixture:authenticated-status", "fixture:ready"])
    }

    public func revoke() {
        state = .revoked
    }

    public func rotate(to credentialReference: SecretStoreReference) throws -> HostEnrollmentReceipt {
        guard state == .enrolled || state == .ready else { throw HostEnrollmentRefusal.notEnrollable }
        state = .enrolled
        return HostEnrollmentReceipt(
            target: policy.target,
            hostIdentity: policy.hostIdentity,
            state: state,
            agentPublicKeyFingerprint: policy.agentPublicKeyFingerprint,
            credentialReference: credentialReference,
            evidence: ["fixture:credential-rotated"])
    }

    private func validateExpiry(_ expiresAt: Date, now: Date) throws {
        guard expiresAt > now else { throw HostEnrollmentRefusal.expired }
    }

    private func reserveIdempotency(_ key: String) throws {
        guard idempotencyKeys.insert(key).inserted else { throw HostEnrollmentRefusal.replayed }
    }
}
