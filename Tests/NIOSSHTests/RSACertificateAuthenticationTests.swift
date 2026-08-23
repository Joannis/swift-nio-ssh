//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import Foundation
import NIOCore
import NIOEmbedded
@testable import NIOSSH
import XCTest

final class RSACertificateAuthenticationTests: XCTestCase {
    override func setUp() {
        super.setUp()
        NIOSSHAlgorithms.unregisterAlgorithms()
        TestRSAAlgorithms.registerSHA256()
    }

    override func tearDown() {
        NIOSSHAlgorithms.unregisterAlgorithms()
        super.tearDown()
    }

    func testRepeatedRegistrationsAndSharedCertificateFormatRemainValid() {
        TestRSAAlgorithms.registerSHA256()
        TestRSAAlgorithms.registerSHA512Parser()
        TestRSAAlgorithms.registerSHA512Parser()
        NIOSSHAlgorithms.register(
            publicKey: TestRSAPublicKey.self,
            signature: TestRSALegacySignature.self
        )
        NIOSSHAlgorithms.register(
            publicKey: TestRSAPublicKey.self,
            signature: TestRSALegacySignature.self
        )

        let registrations = NIOSSHPublicKey.customPublicKeyAlgorithmRegistrations
        XCTAssertEqual(registrations.count, 3)
        XCTAssertEqual(
            Set(registrations.compactMap { $0.userAuthenticationAlgorithm.certificate?.publicKeyPrefix }),
            [TestRSAAlgorithms.certificatePublicKeyPrefix]
        )
        XCTAssertEqual(
            Set(registrations.compactMap { $0.userAuthenticationAlgorithm.certificate?.name }),
            [TestRSAAlgorithms.sha256Certificate, TestRSAAlgorithms.sha512Certificate]
        )
    }

    func testRSACertificateUsesCanonicalBlobWithExponentAndModulusDirectly() throws {
        let privateKey = try TestRSAPrivateKey()
        let certificate = try self.makeCertificate(for: privateKey)
        let publicKey = privateKey.backing

        var encoded = ByteBufferAllocator().buffer(capacity: 1024)
        encoded.writeSSHHostKey(NIOSSHPublicKey(certificate))
        var fields = encoded

        XCTAssertEqual(try XCTUnwrap(fields.readSSHStringAsString()), TestRSAAlgorithms.certificatePublicKeyPrefix)
        XCTAssertEqual(fields.readSSHString(), certificate.nonce)
        XCTAssertEqual(self.unsignedInteger(try XCTUnwrap(fields.readSSHString())), publicKey.exponent)
        XCTAssertEqual(self.unsignedInteger(try XCTUnwrap(fields.readSSHString())), publicKey.modulus)
        XCTAssertEqual(fields.readInteger(as: UInt64.self), certificate.serial)

        let decoded = try XCTUnwrap(encoded.readSSHHostKey())
        XCTAssertEqual(decoded, NIOSSHPublicKey(certificate))
        XCTAssertEqual(encoded.readableBytes, 0)
    }

    func testSignedRSACertificateRequestHasThreeDistinctAlgorithmIdentifiers() throws {
        let privateKey = try TestRSAPrivateKey()
        let certificate = try self.makeCertificate(for: privateKey)
        let sessionID = ByteBuffer(repeating: 0x5a, count: 32)
        let offer = NIOSSHUserAuthenticationOffer(
            username: "rsa-user",
            serviceName: "ssh-connection",
            offer: .privateKey(
                .init(
                    privateKey: .init(custom: privateKey),
                    certifiedKey: certificate
                )
            )
        )
        let request = try SSHMessage.UserAuthRequestMessage(request: offer, sessionID: sessionID)
        let message = SSHMessage.userAuthRequest(request)

        guard case .publicKey(
            .known(
                authenticationAlgorithm: let authenticationAlgorithm,
                key: let publicKey,
                signature: .some(let signature)
            )
        ) = request.method else {
            return XCTFail("expected signed public-key authentication")
        }
        XCTAssertEqual(authenticationAlgorithm, TestRSAAlgorithms.sha256Certificate)
        XCTAssertEqual(String(publicKey.keyPrefix), TestRSAAlgorithms.certificatePublicKeyPrefix)
        XCTAssertEqual(signature.signaturePrefix, TestRSAAlgorithms.sha256)

        let payload = UserAuthSignablePayload(
            sessionIdentifier: sessionID,
            userName: request.username,
            serviceName: request.service,
            authenticationAlgorithm: authenticationAlgorithm,
            publicKey: publicKey
        )
        XCTAssertTrue(publicKey.isValidSignature(signature, for: payload))

        var packet = ByteBufferAllocator().buffer(capacity: 2048)
        packet.writeSSHMessage(message)
        var roundTripPacket = packet
        let roundTripped = try XCTUnwrap(roundTripPacket.readSSHMessage())
        XCTAssertEqual(roundTripped, message)

        XCTAssertEqual(packet.readInteger(as: UInt8.self), SSHMessage.UserAuthRequestMessage.id)
        XCTAssertEqual(packet.readSSHStringAsString(), "rsa-user")
        XCTAssertEqual(packet.readSSHStringAsString(), "ssh-connection")
        XCTAssertEqual(packet.readSSHStringAsString(), "publickey")
        XCTAssertEqual(packet.readSSHBoolean(), true)
        XCTAssertEqual(packet.readSSHStringAsString(), TestRSAAlgorithms.sha256Certificate)

        var keyBlob = try XCTUnwrap(packet.readSSHString())
        XCTAssertEqual(keyBlob.readSSHStringAsString(), TestRSAAlgorithms.certificatePublicKeyPrefix)

        var signatureBlob = try XCTUnwrap(packet.readSSHString())
        XCTAssertEqual(signatureBlob.readSSHStringAsString(), TestRSAAlgorithms.sha256)
        let rawSignature = try XCTUnwrap(signatureBlob.readSSHString())
        XCTAssertEqual(rawSignature.readableBytes, 256)
        XCTAssertEqual(signatureBlob.readableBytes, 0, "signature algorithm must be framed exactly once")
        XCTAssertEqual(packet.readableBytes, 0)
    }

    func testPlainAndCertificateRSARequestsRoundTripIndependently() throws {
        let privateKey = try TestRSAPrivateKey()
        let sessionID = ByteBuffer(repeating: 0x3c, count: 32)
        let plainRequest = try SSHMessage.UserAuthRequestMessage(
            request: .init(
                username: "rsa-user",
                serviceName: "ssh-connection",
                offer: .privateKey(.init(privateKey: .init(custom: privateKey)))
            ),
            sessionID: sessionID
        )
        let certificateRequest = try SSHMessage.UserAuthRequestMessage(
            request: .init(
                username: "rsa-user",
                serviceName: "ssh-connection",
                offer: .privateKey(
                    .init(
                        privateKey: .init(custom: privateKey),
                        certifiedKey: self.makeCertificate(for: privateKey)
                    )
                )
            ),
            sessionID: sessionID
        )

        XCTAssertEqual(plainRequest.authenticationAlgorithm, TestRSAAlgorithms.sha256)
        XCTAssertEqual(certificateRequest.authenticationAlgorithm, TestRSAAlgorithms.sha256Certificate)
        try self.assertMessageRoundTrips(.userAuthRequest(plainRequest))
        try self.assertMessageRoundTrips(.userAuthRequest(certificateRequest))
    }

    func testCustomKeyCanUseDistinctUserAuthenticationAndHostSignatures() throws {
        let privateKey = try ContextAwareTestRSAPrivateKey()
        let request = try SSHMessage.UserAuthRequestMessage(
            request: .init(
                username: "rsa-user",
                serviceName: "ssh-connection",
                offer: .privateKey(.init(privateKey: .init(custom: privateKey)))
            ),
            sessionID: ByteBuffer(repeating: 0x2a, count: 32)
        )

        guard case .publicKey(
            .known(authenticationAlgorithm: let algorithm, key: _, signature: let signature)
        ) = request.method else {
            return XCTFail("expected a signed public-key request")
        }
        XCTAssertEqual(algorithm, TestRSAAlgorithms.sha256)
        XCTAssertEqual(signature?.signaturePrefix, TestRSAAlgorithms.sha256)

        let hostSignature = try NIOSSHPrivateKey(custom: privateKey).sign(
            digest: SHA256.hash(data: Data("host exchange hash".utf8))
        )
        XCTAssertEqual(hostSignature.signaturePrefix, TestRSAAlgorithms.publicKeyPrefix)
    }

    func testUserAuthenticationSignatureDefaultsToExistingSignatureMethod() throws {
        let privateKey = try TestRSAPrivateKey()
        let request = try SSHMessage.UserAuthRequestMessage(
            request: .init(
                username: "rsa-user",
                serviceName: "ssh-connection",
                offer: .privateKey(.init(privateKey: .init(custom: privateKey)))
            ),
            sessionID: ByteBuffer(repeating: 0x17, count: 32)
        )

        guard case .publicKey(
            .known(authenticationAlgorithm: _, key: _, signature: let signature)
        ) = request.method else {
            return XCTFail("expected a signed public-key request")
        }
        XCTAssertEqual(signature?.signaturePrefix, TestRSAAlgorithms.sha256)
    }

    func testLegacyRegistrationPreservesThePublicKeyAuthenticationName() throws {
        NIOSSHAlgorithms.unregisterAlgorithms()
        NIOSSHAlgorithms.register(
            publicKey: TestRSAPublicKey.self,
            signature: TestRSASHA256Signature.self
        )
        let privateKey = LegacyPrefixedRSAPrivateKey(backing: try TestRSAPrivateKey())
        let request = try SSHMessage.UserAuthRequestMessage(
            request: .init(
                username: "rsa-user",
                serviceName: "ssh-connection",
                offer: .privateKey(.init(privateKey: .init(custom: privateKey)))
            ),
            sessionID: ByteBuffer(repeating: 0x19, count: 32)
        )

        XCTAssertEqual(request.authenticationAlgorithm, TestRSAAlgorithms.publicKeyPrefix)
        try self.assertMessageRoundTrips(.userAuthRequest(request))
    }

    func testSignaturePrefixDoesNotSelectUserAuthenticationAlgorithm() throws {
        let authenticationName = "rsa-userauth-sha512"
        let certificateAuthenticationName = "rsa-userauth-sha512-cert-v01@openssh.com"
        NIOSSHAlgorithms.register(
            publicKey: TestRSAPublicKey.self,
            signature: TestRSASHA512Signature.self,
            userAuthenticationAlgorithm: .init(
                name: authenticationName,
                certificate: .init(
                    publicKeyPrefix: TestRSAAlgorithms.certificatePublicKeyPrefix,
                    name: certificateAuthenticationName
                )
            )
        )
        let privateKey = try TestRSAPrivateKey()
        let plainKey = NIOSSHPrivateKey(custom: privateKey).publicKey
        let certificateKey = NIOSSHPublicKey(try self.makeCertificate(for: privateKey))

        XCTAssertNil(
            plainKey.userAuthenticationAlgorithm(
                forAlgorithmIdentifier: TestRSAAlgorithms.sha512
            )
        )
        XCTAssertNil(
            certificateKey.userAuthenticationAlgorithm(
                forAlgorithmIdentifier: TestRSAAlgorithms.sha512
            )
        )

        let plainAlgorithm = try XCTUnwrap(
            plainKey.userAuthenticationAlgorithm(forAlgorithmIdentifier: authenticationName)
        )
        XCTAssertEqual(plainAlgorithm.name, authenticationName)
        XCTAssertEqual(plainAlgorithm.signaturePrefix, TestRSAAlgorithms.sha512)

        let certificateAlgorithm = try XCTUnwrap(
            certificateKey.userAuthenticationAlgorithm(forAlgorithmIdentifier: authenticationName)
        )
        XCTAssertEqual(certificateAlgorithm.name, certificateAuthenticationName)
        XCTAssertEqual(certificateAlgorithm.signaturePrefix, TestRSAAlgorithms.sha512)
    }

    func testProbeAndPKOKPreserveCertificateAuthenticationName() throws {
        let privateKey = try TestRSAPrivateKey()
        let publicKey = NIOSSHPublicKey(try self.makeCertificate(for: privateKey))
        let probe = SSHMessage.userAuthRequest(
            .init(
                username: "rsa-user",
                service: "ssh-connection",
                method: .publicKey(
                    .known(
                        authenticationAlgorithm: TestRSAAlgorithms.sha256Certificate,
                        key: publicKey,
                        signature: nil
                    )
                )
            )
        )
        let response = SSHMessage.userAuthPKOK(
            .init(
                authenticationAlgorithm: TestRSAAlgorithms.sha256Certificate,
                key: publicKey
            )
        )

        try self.assertMessageRoundTrips(probe)
        try self.assertMessageRoundTrips(response)

        var packet = ByteBufferAllocator().buffer(capacity: 1024)
        packet.writeSSHMessage(response)
        XCTAssertEqual(packet.readInteger(as: UInt8.self), SSHMessage.UserAuthPKOKMessage.id)
        XCTAssertEqual(packet.readSSHStringAsString(), TestRSAAlgorithms.sha256Certificate)
        var keyBlob = try XCTUnwrap(packet.readSSHString())
        XCTAssertEqual(keyBlob.readSSHStringAsString(), TestRSAAlgorithms.certificatePublicKeyPrefix)
    }

    func testParserSupportsMultipleRSAAuthenticationNamesForOneKeyFormat() throws {
        TestRSAAlgorithms.registerSHA512Parser()
        TestRSAAlgorithms.registerLegacyParser()
        let privateKey = try TestRSAPrivateKey()
        let certificateKey = NIOSSHPublicKey(try self.makeCertificate(for: privateKey))
        let plainKey = NIOSSHPrivateKey(custom: privateKey).publicKey

        let probes: [(String, NIOSSHPublicKey)] = [
            (TestRSAAlgorithms.sha256, plainKey),
            (TestRSAAlgorithms.sha512, plainKey),
            (TestRSAAlgorithms.publicKeyPrefix, plainKey),
            (TestRSAAlgorithms.sha256Certificate, certificateKey),
            (TestRSAAlgorithms.sha512Certificate, certificateKey),
            (TestRSAAlgorithms.certificatePublicKeyPrefix, certificateKey),
        ]
        for (algorithm, key) in probes {
            try self.assertMessageRoundTrips(
                .userAuthRequest(
                    .init(
                        username: "rsa-user",
                        service: "ssh-connection",
                        method: .publicKey(
                            .known(
                                authenticationAlgorithm: algorithm,
                                key: key,
                                signature: nil
                            )
                        )
                    )
                )
            )
        }

        XCTAssertEqual(
            Set(NIOSSHPublicKey.customSignatures.map { $0.signaturePrefix }),
            [TestRSAAlgorithms.sha256, TestRSAAlgorithms.sha512, TestRSAAlgorithms.publicKeyPrefix]
        )
    }

    func testParserRejectsRSAAlgorithmKeyAndSignatureMismatches() throws {
        TestRSAAlgorithms.registerSHA512Parser()
        let privateKey = try TestRSAPrivateKey()
        let plainKey = NIOSSHPrivateKey(custom: privateKey).publicKey
        let certificateKey = NIOSSHPublicKey(try self.makeCertificate(for: privateKey))

        var wrongKeyPacket = ByteBufferAllocator().buffer(capacity: 1024)
        wrongKeyPacket.writeInteger(SSHMessage.UserAuthRequestMessage.id)
        wrongKeyPacket.writeSSHString("rsa-user".utf8)
        wrongKeyPacket.writeSSHString("ssh-connection".utf8)
        wrongKeyPacket.writeSSHString("publickey".utf8)
        wrongKeyPacket.writeSSHBoolean(false)
        wrongKeyPacket.writeSSHString(TestRSAAlgorithms.sha256Certificate.utf8)
        wrongKeyPacket.writeCompositeSSHString { $0.writeSSHHostKey(plainKey) }
        XCTAssertThrowsError(try wrongKeyPacket.readSSHMessage()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }

        var wrongSignaturePacket = ByteBufferAllocator().buffer(capacity: 2048)
        wrongSignaturePacket.writeInteger(SSHMessage.UserAuthRequestMessage.id)
        wrongSignaturePacket.writeSSHString("rsa-user".utf8)
        wrongSignaturePacket.writeSSHString("ssh-connection".utf8)
        wrongSignaturePacket.writeSSHString("publickey".utf8)
        wrongSignaturePacket.writeSSHBoolean(true)
        wrongSignaturePacket.writeSSHString(TestRSAAlgorithms.sha256Certificate.utf8)
        wrongSignaturePacket.writeCompositeSSHString { $0.writeSSHHostKey(certificateKey) }
        wrongSignaturePacket.writeCompositeSSHString {
            $0.writeSSHSignature(
                .init(
                    backingSignature: .custom(
                        TestRSASHA512Signature(rawRepresentation: Data(repeating: 0x42, count: 256))
                    )
                )
            )
        }
        XCTAssertThrowsError(try wrongSignaturePacket.readSSHMessage()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }
    }

    func testServerStateMachineVerifiesThePreservedCertificateAlgorithm() throws {
        let privateKey = try TestRSAPrivateKey()
        let certificateAndCA = try self.makeCertificateAndCA(for: privateKey)
        let sessionID = ByteBuffer(repeating: 0x7e, count: 32)
        let request = try SSHMessage.UserAuthRequestMessage(
            request: .init(
                username: "rsa-user",
                serviceName: "ssh-connection",
                offer: .privateKey(
                    .init(
                        privateKey: .init(custom: privateKey),
                        certifiedKey: certificateAndCA.certificate
                    )
                )
            ),
            sessionID: sessionID
        )

        var packet = ByteBufferAllocator().buffer(capacity: 2048)
        packet.writeSSHMessage(.userAuthRequest(request))
        guard case .userAuthRequest(let parsedRequest) = try XCTUnwrap(packet.readSSHMessage()) else {
            return XCTFail("expected a parsed user-auth request")
        }
        guard case .publicKey(
            .known(
                authenticationAlgorithm: let authenticationAlgorithm,
                key: let parsedKey,
                signature: .some(let parsedSignature)
            )
        ) = parsedRequest.method else {
            return XCTFail("expected a signed public-key request")
        }
        let parsedCertificate = try XCTUnwrap(NIOSSHCertifiedPublicKey(parsedKey))
        let parsedPayload = UserAuthSignablePayload(
            sessionIdentifier: sessionID,
            userName: parsedRequest.username,
            serviceName: parsedRequest.service,
            authenticationAlgorithm: authenticationAlgorithm,
            publicKey: parsedKey
        )
        XCTAssertTrue(parsedKey.isValidSignature(parsedSignature, for: parsedPayload))
        XCTAssertNoThrow(
            try parsedCertificate.validate(
                principal: "rsa-user",
                type: .user,
                allowedAuthoritySigningKeys: [certificateAndCA.caPublicKey]
            )
        )

        let delegate = AcceptRSACertificateDelegate()
        var configuration = SSHServerConfiguration(
            hostKeys: [.init(ed25519Key: .init())],
            userAuthDelegate: delegate
        )
        configuration.trustedUserCAKeys = [certificateAndCA.caPublicKey]
        let loop = EmbeddedEventLoop()
        var stateMachine = UserAuthenticationStateMachine(
            role: .server(configuration),
            loop: loop,
            sessionID: sessionID
        )
        let serviceAccept = try XCTUnwrap(
            stateMachine.receiveServiceRequest(.init(service: "ssh-userauth"))
        )
        stateMachine.sendServiceAccept(serviceAccept)

        let response = try XCTUnwrap(stateMachine.receiveUserAuthRequest(parsedRequest))
        let succeeded = response.map { result in
            if case .success = result {
                return true
            }
            return false
        }
        loop.run()

        XCTAssertTrue(try succeeded.wait())
        XCTAssertEqual(delegate.receivedCertificate, certificateAndCA.certificate)
    }

    private func makeCertificate(for privateKey: TestRSAPrivateKey) throws -> NIOSSHCertifiedPublicKey {
        try self.makeCertificateAndCA(for: privateKey).certificate
    }

    private func makeCertificateAndCA(
        for privateKey: TestRSAPrivateKey
    ) throws -> (certificate: NIOSSHCertifiedPublicKey, caPublicKey: NIOSSHPublicKey) {
        let caSigningKey = Curve25519.Signing.PrivateKey()
        let caPrivateKey = NIOSSHPrivateKey(ed25519Key: caSigningKey)
        let placeholderSignature = try caPrivateKey.sign(
            digest: SHA256.hash(data: Data("certificate-placeholder".utf8))
        )
        var certificate = try NIOSSHCertifiedPublicKey(
            nonce: ByteBuffer(repeating: 0xa5, count: 32),
            serial: 42,
            type: .user,
            key: NIOSSHPrivateKey(custom: privateKey).publicKey,
            keyID: "rsa-user",
            validPrincipals: ["rsa-user"],
            validAfter: 0,
            validBefore: .max,
            criticalOptions: [:],
            extensions: ["permit-pty": ""],
            signatureKey: caPrivateKey.publicKey,
            signature: placeholderSignature
        )
        let signature = try caSigningKey.signature(
            for: certificate.signableBytes.readableBytesView
        )
        certificate.signature = .init(backingSignature: .ed25519(.data(signature)))
        return (certificate, caPrivateKey.publicKey)
    }

    private func assertMessageRoundTrips(
        _ message: SSHMessage,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        var packet = ByteBufferAllocator().buffer(capacity: 2048)
        packet.writeSSHMessage(message)
        XCTAssertEqual(try packet.readSSHMessage(), message, file: file, line: line)
        XCTAssertEqual(packet.readableBytes, 0, file: file, line: line)
    }

    private func unsignedInteger(_ value: ByteBuffer) -> Data {
        var bytes = Array(value.readableBytesView)
        while bytes.count > 1 && bytes.first == 0 {
            bytes.removeFirst()
        }
        return Data(bytes)
    }
}

private final class AcceptRSACertificateDelegate: NIOSSHServerUserAuthenticationDelegate {
    let supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods = .publicKey
    var receivedCertificate: NIOSSHCertifiedPublicKey?

    func requestReceived(
        request: NIOSSHUserAuthenticationRequest,
        responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>
    ) {
        guard case .publicKey(let publicKey) = request.request else {
            responsePromise.succeed(.failure)
            return
        }
        self.receivedCertificate = publicKey.certifiedKey
        responsePromise.succeed(publicKey.certifiedKey == nil ? .failure : .success)
    }
}

private extension SSHMessage.UserAuthRequestMessage {
    var authenticationAlgorithm: String? {
        guard case .publicKey(
            .known(authenticationAlgorithm: let algorithm, key: _, signature: _)
        ) = self.method else {
            return nil
        }
        return algorithm
    }
}
