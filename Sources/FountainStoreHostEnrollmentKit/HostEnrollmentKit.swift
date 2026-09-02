import Foundation
import Crypto

public struct SecretStoreReference: Codable, Equatable, Hashable, Sendable {
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

public struct BootstrapDescriptor: Codable, Equatable, Sendable {
    public let protocolVersion: String
    public let target: String
    public let provider: String
    public let hostIdentity: String
    public let agentArtifactVersion: String
    public let agentArtifactDigest: String
    public let enrollmentEndpoint: URL
    public let enrollmentChallengeReference: String
    public let expiresAt: Date

    public init(protocolVersion: String = "fountainstore-host/1", target: String, provider: String,
                hostIdentity: String, agentArtifactVersion: String, agentArtifactDigest: String,
                enrollmentEndpoint: URL, enrollmentChallengeReference: String, expiresAt: Date) {
        self.protocolVersion = protocolVersion
        self.target = target
        self.provider = provider
        self.hostIdentity = hostIdentity
        self.agentArtifactVersion = agentArtifactVersion
        self.agentArtifactDigest = agentArtifactDigest
        self.enrollmentEndpoint = enrollmentEndpoint
        self.enrollmentChallengeReference = enrollmentChallengeReference
        self.expiresAt = expiresAt
    }

    public func canonicalBytes() throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }
}

public struct SignedBootstrapDescriptor: Codable, Equatable, Sendable {
    public let descriptor: BootstrapDescriptor
    public let signerFingerprint: String
    public let signature: Data

    public init(descriptor: BootstrapDescriptor, signerFingerprint: String, signature: Data) {
        self.descriptor = descriptor
        self.signerFingerprint = signerFingerprint
        self.signature = signature
    }

    public func verify(using publicKey: Curve25519.Signing.PublicKey) throws -> Bool {
        publicKey.isValidSignature(signature, for: try descriptor.canonicalBytes())
    }
}

public struct HostAgentRequest: Codable, Equatable, Sendable {
    public enum Operation: String, Codable, Sendable {
        case status
        case mirrorRead = "mirror-read"
        case install
        case rollback
        case rotate
        case revoke
    }

    public let operation: Operation
    public let operationVersion: String
    public let target: String
    public let hostIdentity: String
    public let artifactDigest: String?
    public let credentialReference: SecretStoreReference
    public let idempotencyKey: String
    public let expiresAt: Date

    public init(operation: Operation, operationVersion: String = "1", target: String, hostIdentity: String,
                artifactDigest: String? = nil, credentialReference: SecretStoreReference,
                idempotencyKey: String, expiresAt: Date) {
        self.operation = operation
        self.operationVersion = operationVersion
        self.target = target
        self.hostIdentity = hostIdentity
        self.artifactDigest = artifactDigest
        self.credentialReference = credentialReference
        self.idempotencyKey = idempotencyKey
        self.expiresAt = expiresAt
    }
}

/// A read-only request for one named mirror entry. `mirrorID` is resolved by the
/// host configuration; `relativePath` is never interpreted as an absolute path.
/// The request carries no filesystem root and cannot select a second authority.
public struct HostMirrorReadRequest: Codable, Equatable, Sendable {
    public let target: String
    public let hostIdentity: String
    public let mirrorID: String
    public let relativePath: String
    public let offset: UInt64
    public let length: UInt64
    public let idempotencyKey: String
    public let expiresAt: Date

    public init(target: String, hostIdentity: String, mirrorID: String, relativePath: String,
                offset: UInt64 = 0, length: UInt64,
                idempotencyKey: String, expiresAt: Date) {
        self.target = target
        self.hostIdentity = hostIdentity
        self.mirrorID = mirrorID
        self.relativePath = relativePath
        self.offset = offset
        self.length = length
        self.idempotencyKey = idempotencyKey
        self.expiresAt = expiresAt
    }
}

public struct HostMirrorReadReceipt: Codable, Equatable, Sendable {
    public let operation: HostAgentRequest.Operation
    public let target: String
    public let hostIdentity: String
    public let mirrorID: String
    public let relativePath: String
    public let offset: UInt64
    public let length: UInt64
    public let totalBytes: UInt64
    public let chunkDigest: String
    public let mirrorDigest: String
    public let bytes: Data
    public let complete: Bool
    public let evidence: [String]

    public init(target: String, hostIdentity: String, mirrorID: String, relativePath: String,
                offset: UInt64, length: UInt64, totalBytes: UInt64,
                chunkDigest: String, mirrorDigest: String, bytes: Data,
                complete: Bool, evidence: [String] = []) {
        self.operation = .mirrorRead
        self.target = target
        self.hostIdentity = hostIdentity
        self.mirrorID = mirrorID
        self.relativePath = relativePath
        self.offset = offset
        self.length = length
        self.totalBytes = totalBytes
        self.chunkDigest = chunkDigest
        self.mirrorDigest = mirrorDigest
        self.bytes = bytes
        self.complete = complete
        self.evidence = evidence
    }
}

/// Host-owned source authority for a named mirror. The host resolves `mirrorID`
/// to its configured storage root and validates the relative path and range.
/// The kit deliberately does not perform filesystem access.
public protocol HostMirrorReader: Sendable {
    func read(_ request: HostMirrorReadRequest) async throws -> HostMirrorReadReceipt
}

public struct HostAgentReceipt: Codable, Equatable, Sendable {
    public let operation: HostAgentRequest.Operation
    public let target: String
    public let hostIdentity: String
    public let state: HostLifecycleState
    public let artifactDigest: String?
    public let evidence: [String]

    public init(operation: HostAgentRequest.Operation, target: String, hostIdentity: String,
                state: HostLifecycleState, artifactDigest: String? = nil, evidence: [String] = []) {
        self.operation = operation
        self.target = target
        self.hostIdentity = hostIdentity
        self.state = state
        self.artifactDigest = artifactDigest
        self.evidence = evidence
    }
}

public protocol HostAgentTransport: Sendable {
    func send(_ request: HostAgentRequest) async throws -> HostAgentReceipt
}

public enum HostAgentTransportRefusal: Error, Equatable, Sendable {
    case expired
    case replayed
    case targetMismatch
    case identityMismatch
    case descriptorInvalid
    case descriptorExpired
    case artifactMismatch
    case unavailable
    case revoked
}

/// Deterministic host-agent boundary. It verifies a signed descriptor and models authenticated operation state;
/// it deliberately performs no HTTP, TLS, provider, SSH, Keychain, or filesystem operation.
public actor DeterministicHostAgentTransport: HostAgentTransport {
    private let descriptor: SignedBootstrapDescriptor
    private let trustedKey: Curve25519.Signing.PublicKey
    private let expectedArtifactDigest: String
    private var idempotencyKeys: Set<String> = []
    private var state: HostLifecycleState = .enrolled

    public init(descriptor: SignedBootstrapDescriptor, trustedKey: Curve25519.Signing.PublicKey,
                expectedArtifactDigest: String) {
        self.descriptor = descriptor
        self.trustedKey = trustedKey
        self.expectedArtifactDigest = expectedArtifactDigest
    }

    public func validateDescriptor(now: Date) throws {
        guard try descriptor.verify(using: trustedKey) else { throw HostAgentTransportRefusal.descriptorInvalid }
        guard descriptor.descriptor.expiresAt > now else { throw HostAgentTransportRefusal.descriptorExpired }
    }

    public func send(_ request: HostAgentRequest) async throws -> HostAgentReceipt {
        try validateDescriptor(now: Date())
        guard request.expiresAt > Date() else { throw HostAgentTransportRefusal.expired }
        guard request.target == descriptor.descriptor.target else { throw HostAgentTransportRefusal.targetMismatch }
        guard request.hostIdentity == descriptor.descriptor.hostIdentity else { throw HostAgentTransportRefusal.identityMismatch }
        guard idempotencyKeys.insert(request.idempotencyKey).inserted else { throw HostAgentTransportRefusal.replayed }

        switch request.operation {
        case .status:
            guard state != .revoked else { throw HostAgentTransportRefusal.revoked }
            state = .ready
        case .mirrorRead:
            guard state != .revoked else { throw HostAgentTransportRefusal.revoked }
            state = .ready
        case .install:
            guard request.artifactDigest == expectedArtifactDigest else { throw HostAgentTransportRefusal.artifactMismatch }
            guard state != .revoked else { throw HostAgentTransportRefusal.revoked }
            state = .ready
        case .rollback:
            guard state != .revoked else { throw HostAgentTransportRefusal.revoked }
            state = .enrolled
        case .rotate:
            guard state != .revoked else { throw HostAgentTransportRefusal.revoked }
            state = .enrolled
        case .revoke:
            state = .revoked
        }
        return HostAgentReceipt(
            operation: request.operation,
            target: request.target,
            hostIdentity: request.hostIdentity,
            state: state,
            artifactDigest: request.artifactDigest,
            evidence: ["fixture:signed-descriptor", "fixture:exact-target", "fixture:agent-operation"])
    }
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
