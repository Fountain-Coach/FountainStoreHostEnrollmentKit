import Foundation

/// The FCIS-KIT instrument that provisions the opaque credential used by a FountainStore session.
///
/// The kit owns identity and protocol semantics. A host adapter owns credential generation and custody;
/// no credential value is present in this contract.
public enum FountainStoreCredentialProvisionInstrument {
    public static let identity = "fountainstore.credential.provision"
    public static let semanticVersion = "0.2.0"
    public static let owningOrganization = "Fountain-Coach"
    public static let owningKit = "FountainStoreHostEnrollmentKit"
    public static let operationVersion = "1"
    /// The host-agent operation that securely hands the local opaque credential to the
    /// remote FountainStore SecretStore. The value is intentionally not Codable.
    public static let remoteProvisionOperation = "fountainstore.credential.provision.remote"

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

/// The typed request for the remote leg of credential provisioning. Only references and
/// a non-secret fingerprint cross the FCIS/MIDI2 boundary. The credential itself is
/// supplied to the host-owned transport as an in-memory value.
public struct FountainStoreRemoteCredentialProvisionRequest: Codable, Equatable, Sendable {
    public let target: String
    public let hostIdentity: String
    public let localSecretReference: SecretStoreReference
    public let remoteSecretReference: SecretStoreReference
    public let credentialFingerprint: String
    public let idempotencyKey: String
    public let expiresAt: Date

    public init(target: String, hostIdentity: String,
                localSecretReference: SecretStoreReference,
                remoteSecretReference: SecretStoreReference,
                credentialFingerprint: String,
                idempotencyKey: String, expiresAt: Date) {
        self.target = target
        self.hostIdentity = hostIdentity
        self.localSecretReference = localSecretReference
        self.remoteSecretReference = remoteSecretReference
        self.credentialFingerprint = credentialFingerprint
        self.idempotencyKey = idempotencyKey
        self.expiresAt = expiresAt
    }
}

/// A host adapter's secret custody seam. Implementations must keep the returned value
/// in memory for the duration of the transport call and must never serialize it.
public protocol FountainStoreCredentialValueProvider: Sendable {
    func retrieve(_ reference: SecretStoreReference) async throws -> Data
}

/// A host-agent transport receives the credential out-of-band from the typed request.
/// The transport owns TLS/SSH, peer authentication, remote SecretStore custody, and
/// zeroization policy; the kit owns only the contract and lifecycle result.
public protocol FountainStoreRemoteCredentialProvisionTransport: Sendable {
    func send(_ request: FountainStoreRemoteCredentialProvisionRequest,
              credential: Data) async throws -> FountainStoreCredentialProvisionReceipt
}

/// FCIS-KIT adapter for the two-leg operation: retrieve the local credential through
/// the host SecretStore, hand it to the authenticated host transport, and return only
/// a redacted terminal receipt. It never places the credential in Codable state.
public struct FountainStoreRemoteCredentialProvisionAdapter: Sendable {
    private let valueProvider: any FountainStoreCredentialValueProvider
    private let transport: any FountainStoreRemoteCredentialProvisionTransport

    public init(valueProvider: any FountainStoreCredentialValueProvider,
                transport: any FountainStoreRemoteCredentialProvisionTransport) {
        self.valueProvider = valueProvider
        self.transport = transport
    }

    public func provision(_ request: FountainStoreRemoteCredentialProvisionRequest) async
        -> FountainStoreCredentialProvisionReceipt {
        guard request.expiresAt > Date(), !request.target.isEmpty,
              !request.hostIdentity.isEmpty, !request.credentialFingerprint.isEmpty,
              !request.idempotencyKey.isEmpty else {
            return refusal(request, evidence: ["credential:remote-request-invalid"])
        }
        do {
            let credential = try await valueProvider.retrieve(request.localSecretReference)
            guard !credential.isEmpty else {
                return refusal(request, evidence: ["secretstore:source-empty"])
            }
            return try await transport.send(request, credential: credential)
        } catch {
            return refusal(request, evidence: ["credential:remote-handoff-failed"])
        }
    }

    private func refusal(_ request: FountainStoreRemoteCredentialProvisionRequest,
                         evidence: [String]) -> FountainStoreCredentialProvisionReceipt {
        FountainStoreCredentialProvisionReceipt(
            target: request.target,
            secretReference: request.remoteSecretReference,
            state: .refused,
            credentialFingerprint: request.credentialFingerprint,
            evidence: evidence + ["credential:value-not-returned"])
    }
}
