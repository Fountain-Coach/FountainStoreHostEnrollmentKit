import XCTest
@testable import FountainStoreHostEnrollmentKit

final class HostEnrollmentKitTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_000)

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
}
