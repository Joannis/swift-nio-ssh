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

@testable import NIOSSH
import XCTest

final class UserAuthenticationAlgorithmRegistrationTests: XCTestCase {
    private enum PublicKeyParserA {}
    private enum PublicKeyParserB {}
    private enum SignatureParserA {}
    private enum SignatureParserB {}

    private let unrelatedBinding = UserAuthenticationAlgorithmBinding(
        publicKeyParser: .custom(ObjectIdentifier(PublicKeyParserA.self)),
        publicKeyPrefix: "custom-key",
        publicKeyForm: .plain,
        signatureParser: .custom(ObjectIdentifier(SignatureParserA.self)),
        signaturePrefix: "custom-signature"
    )

    func testBundledAuthenticationNamesRejectCustomCanonicalNamesAndAliases() {
        let bundledNames = [
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "ssh-ed25519-cert-v01@openssh.com",
            "ecdsa-sha2-nistp256-cert-v01@openssh.com",
            "ecdsa-sha2-nistp384-cert-v01@openssh.com",
            "ecdsa-sha2-nistp521-cert-v01@openssh.com",
        ]

        for name in bundledNames {
            XCTAssertNil(
                NIOSSHAlgorithms.validatedUserAuthenticationAlgorithmBindings(
                    customBindings: [.init(names: [name], binding: self.unrelatedBinding)]
                ),
                "custom canonical name should not shadow \(name)"
            )
            XCTAssertNil(
                NIOSSHAlgorithms.validatedUserAuthenticationAlgorithmBindings(
                    customBindings: [.init(names: ["custom-auth", name], binding: self.unrelatedBinding)]
                ),
                "custom alias should not shadow \(name)"
            )
        }
    }

    func testAuthenticationNameCannotSelectDifferentCustomKeyFormats() {
        let first = NamedUserAuthenticationAlgorithmBinding(
            names: ["shared-name"],
            binding: .init(
                publicKeyParser: .custom(ObjectIdentifier(PublicKeyParserA.self)),
                publicKeyPrefix: "custom-key-a",
                publicKeyForm: .plain,
                signatureParser: .custom(ObjectIdentifier(SignatureParserA.self)),
                signaturePrefix: "custom-signature-a"
            )
        )
        let second = NamedUserAuthenticationAlgorithmBinding(
            names: ["shared-name"],
            binding: .init(
                publicKeyParser: .custom(ObjectIdentifier(PublicKeyParserB.self)),
                publicKeyPrefix: "custom-key-b",
                publicKeyForm: .plain,
                signatureParser: .custom(ObjectIdentifier(SignatureParserB.self)),
                signaturePrefix: "custom-signature-b"
            )
        )

        XCTAssertNil(
            NIOSSHAlgorithms.validatedUserAuthenticationAlgorithmBindings(customBindings: [first, second])
        )
        XCTAssertNil(
            NIOSSHAlgorithms.validatedUserAuthenticationAlgorithmBindings(customBindings: [second, first])
        )
    }

    func testAuthenticationNameCannotSelectDifferentParsersBehindTheSamePrefixes() {
        let original = NamedUserAuthenticationAlgorithmBinding(
            names: ["shared-name"],
            binding: self.unrelatedBinding
        )
        var differentPublicKeyParser = self.unrelatedBinding
        differentPublicKeyParser.publicKeyParser = .custom(ObjectIdentifier(PublicKeyParserB.self))
        var differentSignatureParser = self.unrelatedBinding
        differentSignatureParser.signatureParser = .custom(ObjectIdentifier(SignatureParserB.self))

        XCTAssertNil(
            NIOSSHAlgorithms.validatedUserAuthenticationAlgorithmBindings(
                customBindings: [
                    original,
                    .init(names: ["shared-name"], binding: differentPublicKeyParser),
                ]
            )
        )
        XCTAssertNil(
            NIOSSHAlgorithms.validatedUserAuthenticationAlgorithmBindings(
                customBindings: [
                    original,
                    .init(names: ["shared-name"], binding: differentSignatureParser),
                ]
            )
        )
    }

    func testAuthenticationNameCannotSelectPlainAndCertificateForms() {
        let plain = NamedUserAuthenticationAlgorithmBinding(
            names: ["shared-name"],
            binding: .init(
                publicKeyParser: .custom(ObjectIdentifier(PublicKeyParserA.self)),
                publicKeyPrefix: "custom-key",
                publicKeyForm: .plain,
                signatureParser: .custom(ObjectIdentifier(SignatureParserA.self)),
                signaturePrefix: "custom-signature"
            )
        )
        let certificate = NamedUserAuthenticationAlgorithmBinding(
            names: ["shared-name"],
            binding: .init(
                publicKeyParser: .custom(ObjectIdentifier(PublicKeyParserA.self)),
                publicKeyPrefix: "custom-key-cert-v01@example.com",
                publicKeyForm: .certificate,
                signatureParser: .custom(ObjectIdentifier(SignatureParserA.self)),
                signaturePrefix: "custom-signature"
            )
        )

        XCTAssertNil(
            NIOSSHAlgorithms.validatedUserAuthenticationAlgorithmBindings(customBindings: [plain, certificate])
        )
        XCTAssertNil(
            NIOSSHAlgorithms.validatedUserAuthenticationAlgorithmBindings(customBindings: [certificate, plain])
        )
    }

    func testCanonicalNamesAndAliasesUseOneGlobalNamespace() {
        let alias = NamedUserAuthenticationAlgorithmBinding(
            names: ["algorithm-a", "shared-name"],
            binding: .init(
                publicKeyParser: .custom(ObjectIdentifier(PublicKeyParserA.self)),
                publicKeyPrefix: "custom-key-a",
                publicKeyForm: .certificate,
                signatureParser: .custom(ObjectIdentifier(SignatureParserA.self)),
                signaturePrefix: "custom-signature-a"
            )
        )
        let canonical = NamedUserAuthenticationAlgorithmBinding(
            names: ["shared-name"],
            binding: .init(
                publicKeyParser: .custom(ObjectIdentifier(PublicKeyParserB.self)),
                publicKeyPrefix: "custom-key-b",
                publicKeyForm: .plain,
                signatureParser: .custom(ObjectIdentifier(SignatureParserB.self)),
                signaturePrefix: "custom-signature-b"
            )
        )

        XCTAssertNil(
            NIOSSHAlgorithms.validatedUserAuthenticationAlgorithmBindings(customBindings: [alias, canonical])
        )
        XCTAssertNil(
            NIOSSHAlgorithms.validatedUserAuthenticationAlgorithmBindings(customBindings: [canonical, alias])
        )
    }

    func testRegistrationAdapterRejectsTheReportedCrossCategoryCollision() {
        let first = PublicKeyAlgorithmRegistration(
            publicKey: TestRSAPublicKey.self,
            signature: TestRSASHA256Signature.self,
            userAuthenticationAlgorithm: .init(
                name: "algorithm-a",
                certificate: .init(
                    publicKeyPrefix: "algorithm-a-cert",
                    name: "shared-name"
                )
            )
        )
        let second = PublicKeyAlgorithmRegistration(
            publicKey: TestRSAPublicKey.self,
            signature: TestRSASHA512Signature.self,
            userAuthenticationAlgorithm: .init(
                name: "shared-name",
                certificate: .init(
                    publicKeyPrefix: "algorithm-b-cert",
                    name: "algorithm-b-cert"
                )
            )
        )

        XCTAssertNil(NIOSSHAlgorithms.userAuthenticationAlgorithmBindings(for: [first, second]))
        XCTAssertNil(NIOSSHAlgorithms.userAuthenticationAlgorithmBindings(for: [second, first]))
    }

    func testRegistrationAdapterChecksPlainAndCertificateAliasesAgainstBundledNames() {
        let plainAlias = PublicKeyAlgorithmRegistration(
            publicKey: TestRSAPublicKey.self,
            signature: TestRSASHA256Signature.self,
            userAuthenticationAlgorithm: .init(
                name: "custom-auth",
                aliases: ["ssh-ed25519"]
            )
        )
        let certificateAlias = PublicKeyAlgorithmRegistration(
            publicKey: TestRSAPublicKey.self,
            signature: TestRSASHA256Signature.self,
            userAuthenticationAlgorithm: .init(
                name: "custom-auth",
                certificate: .init(
                    publicKeyPrefix: "custom-cert",
                    name: "custom-cert-auth",
                    aliases: ["ssh-ed25519-cert-v01@openssh.com"]
                )
            )
        )

        XCTAssertNil(NIOSSHAlgorithms.userAuthenticationAlgorithmBindings(for: [plainAlias]))
        XCTAssertNil(NIOSSHAlgorithms.userAuthenticationAlgorithmBindings(for: [certificateAlias]))
    }

    func testAuthenticationNameMayBeReusedForTheExactSameBinding() throws {
        let first = NamedUserAuthenticationAlgorithmBinding(
            names: ["algorithm-a", "shared-name"],
            binding: self.unrelatedBinding
        )
        let second = NamedUserAuthenticationAlgorithmBinding(
            names: ["algorithm-b", "shared-name"],
            binding: self.unrelatedBinding
        )

        let bindings = try XCTUnwrap(
            NIOSSHAlgorithms.validatedUserAuthenticationAlgorithmBindings(customBindings: [first, second])
        )
        XCTAssertEqual(bindings["shared-name"], self.unrelatedBinding)
        XCTAssertEqual(bindings["algorithm-a"], self.unrelatedBinding)
        XCTAssertEqual(bindings["algorithm-b"], self.unrelatedBinding)
    }

    func testRSAAlgorithmsMaySharePublicKeyBlobFormats() throws {
        let rsaBindings = [
            NamedUserAuthenticationAlgorithmBinding(
                names: ["rsa-sha2-256"],
                binding: .init(
                    publicKeyParser: .custom(ObjectIdentifier(PublicKeyParserA.self)),
                    publicKeyPrefix: "ssh-rsa",
                    publicKeyForm: .plain,
                    signatureParser: .custom(ObjectIdentifier(SignatureParserA.self)),
                    signaturePrefix: "rsa-sha2-256"
                )
            ),
            NamedUserAuthenticationAlgorithmBinding(
                names: ["rsa-sha2-512"],
                binding: .init(
                    publicKeyParser: .custom(ObjectIdentifier(PublicKeyParserA.self)),
                    publicKeyPrefix: "ssh-rsa",
                    publicKeyForm: .plain,
                    signatureParser: .custom(ObjectIdentifier(SignatureParserB.self)),
                    signaturePrefix: "rsa-sha2-512"
                )
            ),
            NamedUserAuthenticationAlgorithmBinding(
                names: ["rsa-sha2-256-cert-v01@openssh.com"],
                binding: .init(
                    publicKeyParser: .custom(ObjectIdentifier(PublicKeyParserA.self)),
                    publicKeyPrefix: "ssh-rsa-cert-v01@openssh.com",
                    publicKeyForm: .certificate,
                    signatureParser: .custom(ObjectIdentifier(SignatureParserA.self)),
                    signaturePrefix: "rsa-sha2-256"
                )
            ),
            NamedUserAuthenticationAlgorithmBinding(
                names: ["rsa-sha2-512-cert-v01@openssh.com"],
                binding: .init(
                    publicKeyParser: .custom(ObjectIdentifier(PublicKeyParserA.self)),
                    publicKeyPrefix: "ssh-rsa-cert-v01@openssh.com",
                    publicKeyForm: .certificate,
                    signatureParser: .custom(ObjectIdentifier(SignatureParserB.self)),
                    signaturePrefix: "rsa-sha2-512"
                )
            ),
        ]

        let bindings = try XCTUnwrap(
            NIOSSHAlgorithms.validatedUserAuthenticationAlgorithmBindings(customBindings: rsaBindings)
        )
        XCTAssertEqual(bindings["rsa-sha2-256"]?.publicKeyPrefix, "ssh-rsa")
        XCTAssertEqual(bindings["rsa-sha2-512"]?.publicKeyPrefix, "ssh-rsa")
        XCTAssertEqual(
            bindings["rsa-sha2-256-cert-v01@openssh.com"]?.publicKeyPrefix,
            "ssh-rsa-cert-v01@openssh.com"
        )
        XCTAssertEqual(
            bindings["rsa-sha2-512-cert-v01@openssh.com"]?.publicKeyPrefix,
            "ssh-rsa-cert-v01@openssh.com"
        )
    }
}
