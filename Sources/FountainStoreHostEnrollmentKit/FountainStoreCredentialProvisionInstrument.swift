import Foundation

/// The FCIS-KIT instrument that provisions the opaque credential used by a FountainStore session.
///
/// The kit owns identity and protocol semantics. A host adapter owns credential generation and custody;
/// no credential value is present in this contract.
public enum FountainStoreCredentialProvisionInstrument {
    public static let identity = "fountainstore.credential.provision"
    public static let semanticVersion = "0.1.0"
    public static let owningOrganization = "Fountain-Coach"
    public static let owningKit = "FountainStoreHostEnrollmentKit"
    public static let operationVersion = "1"

}

public struct FountainStoreCredentialProvisionRequest: Codable, Equatable, Sendable {
    public let target: String
    public let secretReference: SecretStoreReference
    public let keyByteCount: Int
    public let idempotencyKey: String
    public let expiresAt: Date

    public init(target: String, secretReference: SecretStoreReference, keyByteCount: Int = 32,
                idempotencyKey: String, expiresAt: Date) {
        self.target = target
        self.secretReference = secretReference
        self.keyByteCount = keyByteCount
        self.idempotencyKey = idempotencyKey
        self.expiresAt = expiresAt
    }
}

public enum FountainStoreCredentialProvisionState: String, Codable, Sendable {
    case generatedAndStored = "generated-and-stored"
    case remoteProvisioned = "remote-provisioned"
    case refused
    case failed
}

public struct FountainStoreCredentialProvisionReceipt: Codable, Equatable, Sendable {
    public let instrumentIdentity: String
    public let instrumentVersion: String
    public let target: String
    public let secretReference: SecretStoreReference
    public let state: FountainStoreCredentialProvisionState
    public let credentialFingerprint: String?
    public let evidence: [String]
    public let terminal: Bool

    public init(target: String, secretReference: SecretStoreReference,
                state: FountainStoreCredentialProvisionState,
                credentialFingerprint: String? = nil, evidence: [String] = []) {
        self.instrumentIdentity = FountainStoreCredentialProvisionInstrument.identity
        self.instrumentVersion = FountainStoreCredentialProvisionInstrument.semanticVersion
        self.target = target
        self.secretReference = secretReference
        self.state = state
        self.credentialFingerprint = credentialFingerprint
        self.evidence = evidence
        self.terminal = true
    }
}

/// Host-owned custody boundary for the credential-provisioning instrument.
public protocol FountainStoreCredentialProvisioner: Sendable {
    func provision(_ request: FountainStoreCredentialProvisionRequest) async
        -> FountainStoreCredentialProvisionReceipt
}
