import Foundation
import Crypto

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// FCIS-KIT instrument for creating one encrypted Golden Key document at one
/// admitted remote SecretStore reference. The document is transport-only data;
/// owner unlock material is never part of the request or receipt.
public enum FountainStoreGoldenKeyVaultSeedInstrument {
    public static let identity = "fountainstore.golden-key-vault.seed"
    public static let semanticVersion = "0.1.0"
    public static let owningOrganization = "Fountain-Coach"
    public static let owningKit = "FountainStoreHostEnrollmentKit"
    public static let operationVersion = "1"
    public static let remoteSeedOperation = "fountainstore.golden-key-vault.seed.remote"
}

public struct FountainStoreGoldenKeyVaultDocumentSeedRequest: Codable, Equatable, Sendable {
    public let target: String
    public let hostIdentity: String
    public let vaultID: String
    public let documentReference: SecretStoreReference
    public let documentDigest: String
    public let documentByteCount: Int
    public let idempotencyKey: String
    public let expiresAt: Date

    public init(target: String, hostIdentity: String, vaultID: String,
                documentReference: SecretStoreReference, documentDigest: String,
                documentByteCount: Int, idempotencyKey: String, expiresAt: Date) {
        self.target = target
        self.hostIdentity = hostIdentity
        self.vaultID = vaultID
        self.documentReference = documentReference
        self.documentDigest = documentDigest
        self.documentByteCount = documentByteCount
        self.idempotencyKey = idempotencyKey
        self.expiresAt = expiresAt
    }
}

public enum FountainStoreGoldenKeyVaultDocumentSeedState: String, Codable, Sendable {
    case seeded
    case refused
    case failed
}

public struct FountainStoreGoldenKeyVaultDocumentSeedReceipt: Codable, Equatable, Sendable {
    public let instrumentIdentity: String
    public let instrumentVersion: String
    public let target: String
    public let hostIdentity: String
    public let vaultID: String
    public let documentReference: SecretStoreReference
    public let documentDigest: String
    public let documentByteCount: Int
    public let state: FountainStoreGoldenKeyVaultDocumentSeedState
    public let evidence: [String]
    public let terminal: Bool

    public init(request: FountainStoreGoldenKeyVaultDocumentSeedRequest,
                state: FountainStoreGoldenKeyVaultDocumentSeedState,
                evidence: [String] = []) {
        self.instrumentIdentity = FountainStoreGoldenKeyVaultSeedInstrument.identity
        self.instrumentVersion = FountainStoreGoldenKeyVaultSeedInstrument.semanticVersion
        self.target = request.target
        self.hostIdentity = request.hostIdentity
        self.vaultID = request.vaultID
        self.documentReference = request.documentReference
        self.documentDigest = request.documentDigest
        self.documentByteCount = request.documentByteCount
        self.state = state
        self.evidence = evidence
        self.terminal = true
    }
}

public protocol FountainStoreGoldenKeyVaultDocumentSeedTransport: Sendable {
    func seed(_ request: FountainStoreGoldenKeyVaultDocumentSeedRequest,
              document: Data, hostCredential: Data) async throws
        -> FountainStoreGoldenKeyVaultDocumentSeedReceipt
}

public protocol FountainStoreGoldenKeyVaultDocumentValueProvider: Sendable {
    func retrieveDocument() async throws -> Data
}

public struct FountainStoreGoldenKeyVaultDocumentSeeder: Sendable {
    private let documentProvider: any FountainStoreGoldenKeyVaultDocumentValueProvider
    private let hostCredentialProvider: any FountainStoreGoldenKeyVaultHostCredentialProvider
    private let transport: any FountainStoreGoldenKeyVaultDocumentSeedTransport

    public init(documentProvider: any FountainStoreGoldenKeyVaultDocumentValueProvider,
                hostCredentialProvider: any FountainStoreGoldenKeyVaultHostCredentialProvider,
                transport: any FountainStoreGoldenKeyVaultDocumentSeedTransport) {
        self.documentProvider = documentProvider
        self.hostCredentialProvider = hostCredentialProvider
        self.transport = transport
    }

    public func seed(_ request: FountainStoreGoldenKeyVaultDocumentSeedRequest) async
        -> FountainStoreGoldenKeyVaultDocumentSeedReceipt {
        do {
            guard request.expiresAt > Date(), !request.target.isEmpty, !request.hostIdentity.isEmpty,
                  !request.vaultID.isEmpty, !request.idempotencyKey.isEmpty,
                  request.documentByteCount > 0 else {
                return refusal(request, evidence: ["golden-key:seed-request-invalid"])
            }
            let document = try await documentProvider.retrieveDocument()
            let digest = SHA256.hash(data: document).map { String(format: "%02x", $0) }.joined()
            guard !document.isEmpty, document.count == request.documentByteCount,
                  request.documentDigest == "sha256:\(digest)" else {
                return refusal(request, evidence: ["golden-key:document-digest-mismatch"])
            }
            let hostCredential = try await hostCredentialProvider.retrieveHostCredential()
            guard !hostCredential.isEmpty else {
                return refusal(request, evidence: ["secretstore:host-credential-empty"])
            }
            return try await transport.seed(request, document: document, hostCredential: hostCredential)
        } catch {
            return refusal(request, evidence: ["golden-key:remote-seed-failed"])
        }
    }

    private func refusal(_ request: FountainStoreGoldenKeyVaultDocumentSeedRequest,
                         evidence: [String]) -> FountainStoreGoldenKeyVaultDocumentSeedReceipt {
        FountainStoreGoldenKeyVaultDocumentSeedReceipt(
            request: request, state: .refused,
            evidence: evidence + ["golden-key:document-value-not-returned", "golden-key:unlock-not-returned"])
    }
}

/// URLSession transport for the admitted host-agent route. The endpoint is
/// supplied by host configuration; this type never discovers or guesses it.
public struct FountainStoreGoldenKeyVaultDocumentSeedURLSessionTransport: FountainStoreGoldenKeyVaultDocumentSeedTransport, @unchecked Sendable {
    public static let hostCredentialHeader = "X-Fountain-Host-Credential"
    public static let documentHeader = "X-Fountain-Golden-Key-Document"

    private let endpoint: URL
    private let session: URLSession
    private let timeout: TimeInterval

    public init(endpoint: URL, session: URLSession = .shared, timeout: TimeInterval = 30) throws {
        guard endpoint.scheme?.lowercased() == "https", endpoint.host != nil else {
            throw FountainStoreGoldenKeyVaultDocumentSeedTransportError.invalidEndpoint
        }
        guard timeout > 0 else {
            throw FountainStoreGoldenKeyVaultDocumentSeedTransportError.invalidTimeout
        }
        self.endpoint = endpoint
        self.session = session
        self.timeout = timeout
    }

    public func seed(_ request: FountainStoreGoldenKeyVaultDocumentSeedRequest,
                     document: Data, hostCredential: Data) async throws
        -> FountainStoreGoldenKeyVaultDocumentSeedReceipt {
        guard !document.isEmpty, !hostCredential.isEmpty else {
            throw FountainStoreGoldenKeyVaultDocumentSeedTransportError.emptyValue
        }
        var urlRequest = URLRequest(url: endpoint)
        urlRequest.httpMethod = "POST"
        urlRequest.timeoutInterval = timeout
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        urlRequest.setValue(hostCredential.base64EncodedString(), forHTTPHeaderField: Self.hostCredentialHeader)
        urlRequest.setValue(document.base64EncodedString(), forHTTPHeaderField: Self.documentHeader)
        urlRequest.httpBody = try JSONEncoder().encode(request)

        let body: Data
        let response: URLResponse
        do {
            (body, response) = try await session.data(for: urlRequest)
        } catch {
            throw FountainStoreGoldenKeyVaultDocumentSeedTransportError.requestFailed
        }
        guard let httpResponse = response as? HTTPURLResponse else {
            throw FountainStoreGoldenKeyVaultDocumentSeedTransportError.invalidResponse
        }
        guard (200..<300).contains(httpResponse.statusCode) else {
            throw FountainStoreGoldenKeyVaultDocumentSeedTransportError.httpStatus(httpResponse.statusCode)
        }
        let receipt: FountainStoreGoldenKeyVaultDocumentSeedReceipt
        do {
            receipt = try JSONDecoder().decode(FountainStoreGoldenKeyVaultDocumentSeedReceipt.self, from: body)
        } catch {
            throw FountainStoreGoldenKeyVaultDocumentSeedTransportError.invalidReceipt
        }
        guard receipt.instrumentIdentity == FountainStoreGoldenKeyVaultSeedInstrument.identity,
              receipt.instrumentVersion == FountainStoreGoldenKeyVaultSeedInstrument.semanticVersion,
              receipt.target == request.target, receipt.hostIdentity == request.hostIdentity,
              receipt.vaultID == request.vaultID, receipt.documentReference == request.documentReference,
              receipt.documentDigest == request.documentDigest,
              receipt.documentByteCount == request.documentByteCount,
              receipt.state == .seeded, receipt.terminal,
              receipt.evidence.contains("golden-key:encrypted-document-stored") else {
            throw FountainStoreGoldenKeyVaultDocumentSeedTransportError.receiptMismatch
        }
        return receipt
    }
}

public enum FountainStoreGoldenKeyVaultDocumentSeedTransportError: Error, Equatable, Sendable {
    case invalidEndpoint
    case invalidTimeout
    case emptyValue
    case requestFailed
    case invalidResponse
    case httpStatus(Int)
    case invalidReceipt
    case receiptMismatch
}
