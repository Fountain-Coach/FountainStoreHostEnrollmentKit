import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

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
    public let hostSecretReference: SecretStoreReference
    public let remoteSecretReference: SecretStoreReference
    public let credentialFingerprint: String
    public let idempotencyKey: String
    public let expiresAt: Date

    public init(target: String, hostIdentity: String,
                localSecretReference: SecretStoreReference,
                hostSecretReference: SecretStoreReference,
                remoteSecretReference: SecretStoreReference,
                credentialFingerprint: String,
                idempotencyKey: String, expiresAt: Date) {
        self.target = target
        self.hostIdentity = hostIdentity
        self.localSecretReference = localSecretReference
        self.hostSecretReference = hostSecretReference
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
              credential: Data,
              hostCredential: Data) async throws -> FountainStoreCredentialProvisionReceipt
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
            let hostCredential = try await valueProvider.retrieve(request.hostSecretReference)
            guard !credential.isEmpty else {
                return refusal(request, evidence: ["secretstore:source-empty"])
            }
            guard !hostCredential.isEmpty else {
                return refusal(request, evidence: ["secretstore:host-credential-empty"])
            }
            return try await transport.send(request, credential: credential, hostCredential: hostCredential)
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

/// Swift URLSession transport for the production FountainStore host-agent boundary.
///
/// The endpoint is supplied by the admitted host configuration; this transport does not
/// discover, construct, or guess a remote route. The typed request is JSON, while both
/// credential values remain transport-only headers and are never Codable, MIDI2, receipts,
/// or telemetry. The host-agent is responsible for authenticating the host credential and
/// storing the store credential under `remoteSecretReference`.
public struct FountainStoreRemoteCredentialProvisionURLSessionTransport: FountainStoreRemoteCredentialProvisionTransport, @unchecked Sendable {
    public static let hostCredentialHeader = "X-Fountain-Host-Credential"
    public static let storeCredentialHeader = "X-Fountain-Store-Credential"

    private let endpoint: URL
    private let session: URLSession
    private let timeout: TimeInterval

    public init(endpoint: URL, session: URLSession = .shared, timeout: TimeInterval = 30) throws {
        guard endpoint.scheme?.lowercased() == "https", endpoint.host != nil else {
            throw FountainStoreRemoteCredentialProvisionTransportError.invalidEndpoint
        }
        guard timeout > 0 else {
            throw FountainStoreRemoteCredentialProvisionTransportError.invalidTimeout
        }
        self.endpoint = endpoint
        self.session = session
        self.timeout = timeout
    }

    public func send(_ request: FountainStoreRemoteCredentialProvisionRequest,
                     credential: Data,
                     hostCredential: Data) async throws -> FountainStoreCredentialProvisionReceipt {
        guard !credential.isEmpty, !hostCredential.isEmpty else {
            throw FountainStoreRemoteCredentialProvisionTransportError.emptyCredential
        }

        var urlRequest = URLRequest(url: endpoint)
        urlRequest.httpMethod = "POST"
        urlRequest.timeoutInterval = timeout
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        urlRequest.setValue(hostCredential.base64EncodedString(), forHTTPHeaderField: Self.hostCredentialHeader)
        urlRequest.setValue(credential.base64EncodedString(), forHTTPHeaderField: Self.storeCredentialHeader)
        urlRequest.httpBody = try JSONEncoder().encode(request)

        let (body, response): (Data, URLResponse)
        do {
            (body, response) = try await session.data(for: urlRequest)
        } catch {
            throw FountainStoreRemoteCredentialProvisionTransportError.requestFailed
        }
        guard let httpResponse = response as? HTTPURLResponse else {
            throw FountainStoreRemoteCredentialProvisionTransportError.invalidResponse
        }
        guard (200..<300).contains(httpResponse.statusCode) else {
            throw FountainStoreRemoteCredentialProvisionTransportError.httpStatus(httpResponse.statusCode)
        }

        let receipt: FountainStoreCredentialProvisionReceipt
        do {
            receipt = try JSONDecoder().decode(FountainStoreCredentialProvisionReceipt.self, from: body)
        } catch {
            throw FountainStoreRemoteCredentialProvisionTransportError.invalidReceipt
        }
        guard receipt.instrumentIdentity == FountainStoreCredentialProvisionInstrument.identity,
              receipt.instrumentVersion == FountainStoreCredentialProvisionInstrument.semanticVersion,
              receipt.target == request.target,
              receipt.secretReference == request.remoteSecretReference,
              receipt.credentialFingerprint == request.credentialFingerprint,
              receipt.state == .remoteProvisioned,
              receipt.terminal,
              receipt.evidence.contains("credential:value-not-returned") else {
            throw FountainStoreRemoteCredentialProvisionTransportError.receiptMismatch
        }
        return receipt
    }
}

public enum FountainStoreRemoteCredentialProvisionTransportError: Error, Equatable, Sendable {
    case invalidEndpoint
    case invalidTimeout
    case emptyCredential
    case requestFailed
    case invalidResponse
    case httpStatus(Int)
    case invalidReceipt
    case receiptMismatch
}
