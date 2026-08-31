import Foundation
import Crypto

/// FCIS-KIT contract for the one-time creation of a host-agent credential.
///
/// The credential value is deliberately absent from every Codable type and from the
/// MIDI2 boundary. A host adapter creates and stores it in its configured SecretStore.
public enum FountainStoreCredentialSeedInstrument {
    public static let identity = "fountainstore.credential.seed"
    public static let semanticVersion = "0.1.0"
    public static let owningOrganization = "Fountain-Coach"
    public static let owningKit = "FountainStoreHostEnrollmentKit"
    public static let operationVersion = "1"
    public static let operation = "fountainstore.credential.seed"
}

public struct FountainStoreCredentialSeedRequest: Codable, Equatable, Sendable {
    public let target: String
    public let hostIdentity: String
    public let secretReference: SecretStoreReference
    public let keyByteCount: Int
    public let idempotencyKey: String
    public let expiresAt: Date

    public init(target: String, hostIdentity: String, secretReference: SecretStoreReference,
                keyByteCount: Int = 32, idempotencyKey: String, expiresAt: Date) {
        self.target = target
        self.hostIdentity = hostIdentity
        self.secretReference = secretReference
        self.keyByteCount = keyByteCount
        self.idempotencyKey = idempotencyKey
        self.expiresAt = expiresAt
    }
}

public enum FountainStoreCredentialSeedState: String, Codable, Sendable {
    case seeded
    case refused
    case failed
}

public struct FountainStoreCredentialSeedReceipt: Codable, Equatable, Sendable {
    public let instrumentIdentity: String
    public let instrumentVersion: String
    public let operation: String
    public let target: String
    public let hostIdentity: String
    public let secretReference: SecretStoreReference
    public let state: FountainStoreCredentialSeedState
    public let credentialFingerprint: String?
    public let evidence: [String]
    public let terminal: Bool

    public init(request: FountainStoreCredentialSeedRequest,
                state: FountainStoreCredentialSeedState,
                credentialFingerprint: String? = nil,
                evidence: [String] = []) {
        self.instrumentIdentity = FountainStoreCredentialSeedInstrument.identity
        self.instrumentVersion = FountainStoreCredentialSeedInstrument.semanticVersion
        self.operation = FountainStoreCredentialSeedInstrument.operation
        self.target = request.target
        self.hostIdentity = request.hostIdentity
        self.secretReference = request.secretReference
        self.state = state
        self.credentialFingerprint = credentialFingerprint
        self.evidence = evidence
        self.terminal = true
    }
}

public enum FountainStoreCredentialSeedError: Error, Equatable, Sendable {
    case invalidRequest
    case expired
    case replayed
    case alreadySeeded
    case generationFailed
    case storageFailed
}

/// Host custody seam for the seed instrument. Implementations must not return the
/// credential value and must not log it; only the fingerprint crosses this boundary.
public protocol FountainStoreCredentialSeedStore: Sendable {
    func contains(_ reference: SecretStoreReference) throws -> Bool
    func storeGeneratedCredential(byteCount: Int, for reference: SecretStoreReference) throws -> String
}

/// Deterministic orchestration for a one-time seed. The actual random generation and
/// SecretStore write remain in the host adapter, never in MIDI2 or a persisted request.
public struct FountainStoreCredentialSeeder: Sendable {
    private let store: any FountainStoreCredentialSeedStore

    public init(store: any FountainStoreCredentialSeedStore) {
        self.store = store
    }

    public func seed(_ request: FountainStoreCredentialSeedRequest, now: Date = Date()) throws
        -> FountainStoreCredentialSeedReceipt {
        guard !request.target.isEmpty, !request.hostIdentity.isEmpty,
              !request.secretReference.service.isEmpty, !request.secretReference.account.isEmpty,
              request.keyByteCount >= 32, request.keyByteCount <= 64,
              !request.idempotencyKey.isEmpty else { throw FountainStoreCredentialSeedError.invalidRequest }
        guard request.expiresAt > now else { throw FountainStoreCredentialSeedError.expired }
        guard try !store.contains(request.secretReference) else { throw FountainStoreCredentialSeedError.alreadySeeded }
        let fingerprint = try store.storeGeneratedCredential(byteCount: request.keyByteCount,
                                                               for: request.secretReference)
        return FountainStoreCredentialSeedReceipt(
            request: request,
            state: .seeded,
            credentialFingerprint: fingerprint,
            evidence: ["secretstore:generated", "secretstore:stored", "credential:value-not-returned"])
    }
}
