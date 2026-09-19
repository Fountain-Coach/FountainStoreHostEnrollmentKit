import Foundation
import Crypto

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// The FCIS-KIT instrument for reading an encrypted Golden Key document from an
/// admitted remote SecretStore host. The returned document is ciphertext and is
/// transport data only; the owner unlock material is never part of this contract.
public enum FountainStoreGoldenKeyVaultReadInstrument {
    public static let identity = "fountainstore.golden-key-vault.read"
    public static let semanticVersion = "0.1.0"
    public static let owningOrganization = "Fountain-Coach"
    public static let owningKit = "FountainStoreHostEnrollmentKit"
    public static let operationVersion = "1"
    public static let remoteReadOperation = "fountainstore.golden-key-vault.read.remote"
}

public struct FountainStoreGoldenKeyVaultDocumentReadRequest: Codable, Equatable, Sendable {
    public let target: String
    public let hostIdentity: String
    public let vaultID: String
    public let documentReference: SecretStoreReference
    public let idempotencyKey: String
    public let expiresAt: Date

    public init(target: String, hostIdentity: String, vaultID: String,
                documentReference: SecretStoreReference, idempotencyKey: String,
                expiresAt: Date) {
        self.target = target
        self.hostIdentity = hostIdentity
        self.vaultID = vaultID
        self.documentReference = documentReference
        self.idempotencyKey = idempotencyKey
        self.expiresAt = expiresAt
    }
}

public enum FountainStoreGoldenKeyVaultDocumentReadState: String, Codable, Sendable {
    case remoteRead = "remote-read"
    case refused
    case failed
}

/// Redacted evidence for a Golden Key document read. The encrypted document is
/// deliberately not a receipt field and must not be persisted as Store evidence.
public struct FountainStoreGoldenKeyVaultDocumentReadReceipt: Codable, Equatable, Sendable {
    public let instrumentIdentity: String
    public let instrumentVersion: String
    public let target: String
    public let hostIdentity: String
    public let vaultID: String
    public let documentReference: SecretStoreReference
    public let documentDigest: String
    public let documentByteCount: Int
    public let state: FountainStoreGoldenKeyVaultDocumentReadState
    public let evidence: [String]
    public let terminal: Bool

    public init(target: String, hostIdentity: String, vaultID: String,
                documentReference: SecretStoreReference, documentDigest: String,
                documentByteCount: Int,
                state: FountainStoreGoldenKeyVaultDocumentReadState,
                evidence: [String] = []) {
        self.instrumentIdentity = FountainStoreGoldenKeyVaultReadInstrument.identity
        self.instrumentVersion = FountainStoreGoldenKeyVaultReadInstrument.semanticVersion
        self.target = target
        self.hostIdentity = hostIdentity
        self.vaultID = vaultID
        self.documentReference = documentReference
        self.documentDigest = documentDigest
        self.documentByteCount = documentByteCount
        self.state = state
        self.evidence = evidence
        self.terminal = true
    }
}

public protocol FountainStoreGoldenKeyVaultDocumentReadTransport: Sendable {
    func read(_ request: FountainStoreGoldenKeyVaultDocumentReadRequest,
              hostCredential: Data) async throws
        -> (document: Data, receipt: FountainStoreGoldenKeyVaultDocumentReadReceipt)
}

/// Host adapter boundary for the machine credential. The Golden Key unlock
/// material is intentionally not requested here; it is a separate local owner
/// presence operation after the encrypted document has been received.
public protocol FountainStoreGoldenKeyVaultHostCredentialProvider: Sendable {
    func retrieveHostCredential() async throws -> Data
}

public struct FountainStoreGoldenKeyVaultDocumentReader: Sendable {
    private let hostCredentialProvider: any FountainStoreGoldenKeyVaultHostCredentialProvider
    private let transport: any FountainStoreGoldenKeyVaultDocumentReadTransport

    public init(hostCredentialProvider: any FountainStoreGoldenKeyVaultHostCredentialProvider,
                transport: any FountainStoreGoldenKeyVaultDocumentReadTransport) {
        self.hostCredentialProvider = hostCredentialProvider
        self.transport = transport
    }

    public func read(_ request: FountainStoreGoldenKeyVaultDocumentReadRequest) async
        -> (document: Data?, receipt: FountainStoreGoldenKeyVaultDocumentReadReceipt) {
        guard request.expiresAt > Date(), !request.target.isEmpty, !request.hostIdentity.isEmpty,
              !request.vaultID.isEmpty, !request.idempotencyKey.isEmpty else {
            return (nil, refusal(request, evidence: ["golden-key:remote-request-invalid"]))
        }
        do {
            let hostCredential = try await hostCredentialProvider.retrieveHostCredential()
            guard !hostCredential.isEmpty else {
                return (nil, refusal(request, evidence: ["secretstore:host-credential-empty"]))
            }
            return try await transport.read(request, hostCredential: hostCredential)
        } catch {
            return (nil, refusal(request, evidence: ["golden-key:remote-read-failed"]))
        }
    }

    private func refusal(_ request: FountainStoreGoldenKeyVaultDocumentReadRequest,
                         evidence: [String])
        -> FountainStoreGoldenKeyVaultDocumentReadReceipt {
        FountainStoreGoldenKeyVaultDocumentReadReceipt(
            target: request.target,
            hostIdentity: request.hostIdentity,
            vaultID: request.vaultID,
            documentReference: request.documentReference,
            documentDigest: "",
            documentByteCount: 0,
            state: .refused,
            evidence: evidence + ["golden-key:document-not-returned"])
    }
}

/// URLSession transport for the admitted remote host-agent route. The endpoint
/// is supplied by host configuration; this type never discovers or constructs a
/// route. The host credential is transport-only and the encrypted document is
/// returned as the response payload, never as a redacted receipt field.
public struct FountainStoreGoldenKeyVaultDocumentReadURLSessionTransport: FountainStoreGoldenKeyVaultDocumentReadTransport, @unchecked Sendable {
    public static let hostCredentialHeader = "X-Fountain-Host-Credential"

    private struct ResponseEnvelope: Codable {
        let receipt: FountainStoreGoldenKeyVaultDocumentReadReceipt
        let document: Data
    }

    private let endpoint: URL
    private let session: URLSession
    private let timeout: TimeInterval

    public init(endpoint: URL, session: URLSession = .shared, timeout: TimeInterval = 30) throws {
        guard endpoint.scheme?.lowercased() == "https", endpoint.host != nil else {
            throw FountainStoreGoldenKeyVaultDocumentReadTransportError.invalidEndpoint
        }
        guard timeout > 0 else {
            throw FountainStoreGoldenKeyVaultDocumentReadTransportError.invalidTimeout
        }
        self.endpoint = endpoint
        self.session = session
        self.timeout = timeout
    }

    public func read(_ request: FountainStoreGoldenKeyVaultDocumentReadRequest,
                     hostCredential: Data) async throws
        -> (document: Data, receipt: FountainStoreGoldenKeyVaultDocumentReadReceipt) {
        guard !hostCredential.isEmpty else {
            throw FountainStoreGoldenKeyVaultDocumentReadTransportError.emptyCredential
        }

        var urlRequest = URLRequest(url: endpoint)
        urlRequest.httpMethod = "POST"
        urlRequest.timeoutInterval = timeout
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        urlRequest.setValue(hostCredential.base64EncodedString(), forHTTPHeaderField: Self.hostCredentialHeader)
        urlRequest.httpBody = try JSONEncoder().encode(request)

        let body: Data
        let response: URLResponse
        do {
            (body, response) = try await session.data(for: urlRequest)
        } catch {
            throw FountainStoreGoldenKeyVaultDocumentReadTransportError.requestFailed
        }
        guard let httpResponse = response as? HTTPURLResponse else {
            throw FountainStoreGoldenKeyVaultDocumentReadTransportError.invalidResponse
        }
        guard (200..<300).contains(httpResponse.statusCode) else {
            throw FountainStoreGoldenKeyVaultDocumentReadTransportError.httpStatus(httpResponse.statusCode)
        }

        let envelope: ResponseEnvelope
        do {
            envelope = try JSONDecoder().decode(ResponseEnvelope.self, from: body)
        } catch {
            throw FountainStoreGoldenKeyVaultDocumentReadTransportError.invalidReceipt
        }

        let digest = SHA256.hash(data: envelope.document).map { String(format: "%02x", $0) }.joined()
        let receipt = envelope.receipt
        guard receipt.instrumentIdentity == FountainStoreGoldenKeyVaultReadInstrument.identity,
              receipt.instrumentVersion == FountainStoreGoldenKeyVaultReadInstrument.semanticVersion,
              receipt.target == request.target,
              receipt.hostIdentity == request.hostIdentity,
              receipt.vaultID == request.vaultID,
              receipt.documentReference == request.documentReference,
              receipt.documentDigest == "sha256:\(digest)",
              receipt.documentByteCount == envelope.document.count,
              receipt.state == .remoteRead,
              receipt.terminal,
              receipt.evidence.contains("golden-key:encrypted-document") else {
            throw FountainStoreGoldenKeyVaultDocumentReadTransportError.receiptMismatch
        }
        return (envelope.document, receipt)
    }
}

public enum FountainStoreGoldenKeyVaultDocumentReadTransportError: Error, Equatable, Sendable {
    case invalidEndpoint
    case invalidTimeout
    case emptyCredential
    case requestFailed
    case invalidResponse
    case httpStatus(Int)
    case invalidReceipt
    case receiptMismatch
}
