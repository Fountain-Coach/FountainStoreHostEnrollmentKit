import XCTest
import CryptoKit
@testable import FountainStoreHostEnrollmentKit

final class HostEnrollmentKitTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_000)

    private struct FixtureValueProvider: FountainStoreCredentialValueProvider {
        let value: Data
        func retrieve(_ reference: SecretStoreReference) async throws -> Data { value }
    }

    private actor FixtureRemoteTransport: FountainStoreRemoteCredentialProvisionTransport {
        var received: Data?

        func send(_ request: FountainStoreRemoteCredentialProvisionRequest,
                  credential: Data) async throws -> FountainStoreCredentialProvisionReceipt {
            received = credential
            return FountainStoreCredentialProvisionReceipt(
                target: request.target,
                secretReference: request.remoteSecretReference,
                state: .remoteProvisioned,
                credentialFingerprint: request.credentialFingerprint,
                evidence: ["fixture:authenticated-host", "fixture:remote-secretstore-stored", "credential:value-not-returned"])
        }
    }

    func testCredentialProvisionInstrumentHasStableFCISIdentityAndRedactedReceipt() throws {
        XCTAssertEqual(FountainStoreCredentialProvisionInstrument.identity, "fountainstore.credential.provision")
        XCTAssertEqual(FountainStoreCredentialProvisionInstrument.semanticVersion, "0.2.0")
        XCTAssertEqual(FountainStoreCredentialProvisionInstrument.remoteProvisionOperation, "fountainstore.credential.provision.remote")
        XCTAssertEqual(FountainStoreCredentialProvisionInstrument.owningOrganization, "Fountain-Coach")
        XCTAssertEqual(FountainStoreCredentialProvisionInstrument.owningKit, "FountainStoreHostEnrollmentKit")

        let receipt = FountainStoreCredentialProvisionReceipt(
            target: "https://store.example.test",
            secretReference: SecretStoreReference(service: "com.fountain.store.http", account: "FS_API_KEY"),
            state: .generatedAndStored,
            credentialFingerprint: "sha256:fingerprint",
            evidence: ["secretstore:stored", "credential:value-not-returned"])
        XCTAssertTrue(receipt.terminal)
        XCTAssertEqual(receipt.instrumentIdentity, FountainStoreCredentialProvisionInstrument.identity)
        let encoded = String(decoding: try JSONEncoder().encode(receipt), as: UTF8.self)
        XCTAssertFalse(encoded.localizedCaseInsensitiveContains("credentialValue"))
        XCTAssertFalse(encoded.localizedCaseInsensitiveContains("privateKey"))
        XCTAssertFalse(encoded.contains("secret-value"))
    }

    func testRemoteCredentialProvisionerHandsOffOnlyInMemoryAndReturnsTerminalRedactedReceipt() async throws {
        let credential = Data("opaque-credential-fixture".utf8)
        let transport = FixtureRemoteTransport()
        let adapter = FountainStoreRemoteCredentialProvisionAdapter(
            valueProvider: FixtureValueProvider(value: credential), transport: transport)
        let request = FountainStoreRemoteCredentialProvisionRequest(
            target: "root@65.109.14.71",
            hostIdentity: "fountainstore:production",
            localSecretReference: SecretStoreReference(service: "com.fountain.store.http", account: "FS_API_KEY"),
            remoteSecretReference: SecretStoreReference(service: "com.fountain.store.http", account: "FS_API_KEY"),
            credentialFingerprint: "sha256:fixture",
            idempotencyKey: "remote-provision-1",
            expiresAt: Date().addingTimeInterval(60))

        let receipt = await adapter.provision(request)
        XCTAssertEqual(receipt.state, .remoteProvisioned)
        XCTAssertTrue(receipt.terminal)
        XCTAssertEqual(receipt.credentialFingerprint, "sha256:fixture")
        let encoded = String(decoding: try JSONEncoder().encode(receipt), as: UTF8.self)
        XCTAssertFalse(encoded.contains("opaque-credential-fixture"))
        XCTAssertFalse(encoded.localizedCaseInsensitiveContains("credentialValue"))
        let received = await transport.received
        XCTAssertEqual(received, credential)
    }

    private func makeService() -> DeterministicHostEnrollmentService {
        DeterministicHostEnrollmentService(policy: HostEnrollmentPolicy(
            target: "server:staging-1",
            hostIdentity: "hetzner:server:staging-1",
            agentPublicKeyFingerprint: "SHA256:agent",
            allowedScope: "fountainstore:operate",
            credentialReference: SecretStoreReference(service: "fountain-coach", account: "staging-host"),
            agentBuildDigest: "sha256:agent-build"))
    }

    private func bootstrapRequest(idempotencyKey: String = "bootstrap-1", expiresAt: Date? = nil) -> HostBootstrapRequest {
        HostBootstrapRequest(
            provider: "hetzner-cloud",
            target: "server:staging-1",
            artifactVersion: "0.5.0-staging",
            artifactDigest: "sha256:agent",
            bootstrapDescriptorDigest: "sha256:descriptor",
            secretReference: SecretStoreReference(service: "fountain-coach", account: "provider-api"),
            idempotencyKey: idempotencyKey,
            expiresAt: expiresAt ?? now.addingTimeInterval(100))
    }

    private func enrollmentRequest(challenge: String = "challenge-1", idempotencyKey: String = "enroll-1",
                                   target: String = "server:staging-1", identity: String = "hetzner:server:staging-1",
                                   fingerprint: String = "SHA256:agent", scope: String = "fountainstore:operate") -> HostEnrollmentRequest {
        HostEnrollmentRequest(
            target: target,
            hostIdentity: identity,
            enrollmentChallengeReference: challenge,
            agentEndpoint: URL(string: "https://staging.example.test")!,
            agentPublicKeyFingerprint: fingerprint,
            secretReference: SecretStoreReference(service: "fountain-coach", account: "staging-host"),
            scope: scope,
            idempotencyKey: idempotencyKey,
            expiresAt: now.addingTimeInterval(100))
    }

    func testBootstrapEnrollmentAndReadyAreDistinct() async throws {
        let service = makeService()
        let bootstrap = try await service.bootstrap(bootstrapRequest(), now: now)
        XCTAssertEqual(bootstrap.state, .bootstrapped)
        let enrollment = try await service.enroll(enrollmentRequest(), now: now)
        XCTAssertEqual(enrollment.state, .enrolled)
        let status = try await service.status(HostStatusRequest(
            target: "server:staging-1", hostIdentity: "hetzner:server:staging-1",
            secretReference: enrollment.credentialReference, idempotencyKey: "status-1",
            expiresAt: now.addingTimeInterval(100)), now: now)
        XCTAssertEqual(status.state, .ready)
    }

    func testExpiryReplayTargetIdentityFingerprintAndScopeRefuse() async throws {
        let service = makeService()
        do {
            _ = try await service.bootstrap(bootstrapRequest(expiresAt: now), now: now)
            XCTFail("expired bootstrap must refuse")
        } catch let refusal as HostEnrollmentRefusal {
            XCTAssertEqual(refusal, .expired)
        }
        _ = try await service.bootstrap(bootstrapRequest(), now: now)
        do { _ = try await service.enroll(enrollmentRequest(target: "server:wrong"), now: now); XCTFail("wrong target must refuse") } catch let refusal as HostEnrollmentRefusal { XCTAssertEqual(refusal, .targetMismatch) }
        do { _ = try await service.enroll(enrollmentRequest(idempotencyKey: "enroll-2", identity: "aws:instance:wrong"), now: now); XCTFail("wrong identity must refuse") } catch let refusal as HostEnrollmentRefusal { XCTAssertEqual(refusal, .identityMismatch) }
        do { _ = try await service.enroll(enrollmentRequest(idempotencyKey: "enroll-3", fingerprint: "SHA256:wrong"), now: now); XCTFail("wrong fingerprint must refuse") } catch let refusal as HostEnrollmentRefusal { XCTAssertEqual(refusal, .fingerprintMismatch) }
        do { _ = try await service.enroll(enrollmentRequest(idempotencyKey: "enroll-4", scope: "provider:admin"), now: now); XCTFail("wrong scope must refuse") } catch let refusal as HostEnrollmentRefusal { XCTAssertEqual(refusal, .scopeInsufficient) }
        _ = try await service.enroll(enrollmentRequest(), now: now)
        do { _ = try await service.enroll(enrollmentRequest(idempotencyKey: "enroll-5"), now: now); XCTFail("replayed challenge must refuse") } catch let refusal as HostEnrollmentRefusal { XCTAssertEqual(refusal, .replayed) }
    }

    func testRotationAndRevocationAreObservable() async throws {
        let service = makeService()
        _ = try await service.bootstrap(bootstrapRequest(), now: now)
        _ = try await service.enroll(enrollmentRequest(), now: now)
        let rotated = try await service.rotate(to: SecretStoreReference(service: "fountain-coach", account: "staging-host-v2"))
        XCTAssertEqual(rotated.state, .enrolled)
        await service.revoke()
        do {
            _ = try await service.status(HostStatusRequest(
                target: "server:staging-1", hostIdentity: "hetzner:server:staging-1",
                secretReference: rotated.credentialReference, idempotencyKey: "status-2",
                expiresAt: now.addingTimeInterval(100)), now: now)
            XCTFail("revoked host must refuse status")
        } catch let refusal as HostEnrollmentRefusal {
            XCTAssertEqual(refusal, .notEnrollable)
        }
    }

    func testSerializedBoundaryContainsReferencesButNoCredentialValue() throws {
        let request = HostEnrollmentRequest(
            target: "server:staging-1", hostIdentity: "hetzner:server:staging-1",
            enrollmentChallengeReference: "challenge-ref-1",
            agentEndpoint: URL(string: "https://staging.example.test")!,
            agentPublicKeyFingerprint: "SHA256:agent",
            secretReference: SecretStoreReference(service: "fountain-coach", account: "staging-host"),
            scope: "fountainstore:operate", idempotencyKey: "enroll-1",
            expiresAt: Date(timeIntervalSince1970: 1_100))
        let encoded = String(decoding: try JSONEncoder().encode(request), as: UTF8.self)
        XCTAssertTrue(encoded.contains("secretReference"))
        XCTAssertTrue(encoded.contains("challenge-ref-1"))
        XCTAssertFalse(encoded.localizedCaseInsensitiveContains("privateKey"))
        XCTAssertFalse(encoded.localizedCaseInsensitiveContains("credentialValue"))
        XCTAssertFalse(encoded.localizedCaseInsensitiveContains("ssh"))
    }

    func testSignedBootstrapDescriptorVerifiesCanonicalPayload() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let descriptor = BootstrapDescriptor(
            target: "server:staging-1",
            provider: "hetzner-cloud",
            hostIdentity: "hetzner:server:staging-1",
            agentArtifactVersion: "0.5.0-staging",
            agentArtifactDigest: "sha256:agent",
            enrollmentEndpoint: URL(string: "https://staging.example.test/enroll")!,
            enrollmentChallengeReference: "challenge-ref-1",
            expiresAt: now.addingTimeInterval(100))
        let signed = SignedBootstrapDescriptor(
            descriptor: descriptor,
            signerFingerprint: "SHA256:fixture-signer",
            signature: try privateKey.signature(for: descriptor.canonicalBytes()))
        XCTAssertTrue(try signed.verify(using: privateKey.publicKey))

        let changed = BootstrapDescriptor(
            target: descriptor.target,
            provider: descriptor.provider,
            hostIdentity: descriptor.hostIdentity,
            agentArtifactVersion: descriptor.agentArtifactVersion,
            agentArtifactDigest: "sha256:changed",
            enrollmentEndpoint: descriptor.enrollmentEndpoint,
            enrollmentChallengeReference: descriptor.enrollmentChallengeReference,
            expiresAt: descriptor.expiresAt)
        let tampered = SignedBootstrapDescriptor(
            descriptor: changed,
            signerFingerprint: signed.signerFingerprint,
            signature: signed.signature)
        XCTAssertFalse(try tampered.verify(using: privateKey.publicKey))
    }

    func testHostAgentTransportEnforcesDescriptorTargetArtifactAndRevocation() async throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let current = Date()
        let descriptor = BootstrapDescriptor(
            target: "server:staging-1",
            provider: "hetzner-cloud",
            hostIdentity: "hetzner:server:staging-1",
            agentArtifactVersion: "0.5.0-staging",
            agentArtifactDigest: "sha256:agent",
            enrollmentEndpoint: URL(string: "https://staging.example.test/enroll")!,
            enrollmentChallengeReference: "challenge-ref-1",
            expiresAt: current.addingTimeInterval(100))
        let signed = SignedBootstrapDescriptor(
            descriptor: descriptor,
            signerFingerprint: "SHA256:fixture-signer",
            signature: try privateKey.signature(for: descriptor.canonicalBytes()))
        let transport = DeterministicHostAgentTransport(
            descriptor: signed, trustedKey: privateKey.publicKey, expectedArtifactDigest: "sha256:agent")
        let reference = SecretStoreReference(service: "fountain-coach", account: "staging-host")
        let request = HostAgentRequest(
            operation: .install,
            target: descriptor.target,
            hostIdentity: descriptor.hostIdentity,
            artifactDigest: "sha256:agent",
            credentialReference: reference,
            idempotencyKey: "agent-install-1",
            expiresAt: current.addingTimeInterval(100))
        let receipt = try await transport.send(request)
        XCTAssertEqual(receipt.state, .ready)
        XCTAssertTrue(receipt.evidence.contains("fixture:signed-descriptor"))

        do {
            _ = try await transport.send(HostAgentRequest(
                operation: .install, target: "server:wrong", hostIdentity: descriptor.hostIdentity,
                artifactDigest: "sha256:agent", credentialReference: reference,
                idempotencyKey: "agent-install-2", expiresAt: current.addingTimeInterval(100)))
            XCTFail("wrong target must refuse")
        } catch let refusal as HostAgentTransportRefusal {
            XCTAssertEqual(refusal, .targetMismatch)
        }

        _ = try await transport.send(HostAgentRequest(
            operation: .revoke, target: descriptor.target, hostIdentity: descriptor.hostIdentity,
            credentialReference: reference, idempotencyKey: "agent-revoke-1",
            expiresAt: current.addingTimeInterval(100)))
        do {
            _ = try await transport.send(HostAgentRequest(
                operation: .status, target: descriptor.target, hostIdentity: descriptor.hostIdentity,
                credentialReference: reference, idempotencyKey: "agent-status-1",
                expiresAt: current.addingTimeInterval(100)))
            XCTFail("revoked host must refuse status")
        } catch let refusal as HostAgentTransportRefusal {
            XCTAssertEqual(refusal, .revoked)
        }
    }
}
