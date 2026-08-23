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
@testable import NIOSSH

enum TestRSAAlgorithms {
    static let publicKeyPrefix = "ssh-rsa"
    static let certificatePublicKeyPrefix = "ssh-rsa-cert-v01@openssh.com"
    static let sha256 = "rsa-sha2-256"
    static let sha256Certificate = "rsa-sha2-256-cert-v01@openssh.com"
    static let sha512 = "rsa-sha2-512"
    static let sha512Certificate = "rsa-sha2-512-cert-v01@openssh.com"

    static func registerSHA256() {
        NIOSSHAlgorithms.register(
            publicKey: TestRSAPublicKey.self,
            signature: TestRSASHA256Signature.self,
            userAuthenticationAlgorithm: .init(
                name: self.sha256,
                certificate: .init(
                    publicKeyPrefix: self.certificatePublicKeyPrefix,
                    name: self.sha256Certificate
                )
            )
        )
    }

    static func registerSHA512Parser() {
        NIOSSHAlgorithms.register(
            publicKey: TestRSAPublicKey.self,
            signature: TestRSASHA512Signature.self,
            userAuthenticationAlgorithm: .init(
                name: self.sha512,
                certificate: .init(
                    publicKeyPrefix: self.certificatePublicKeyPrefix,
                    name: self.sha512Certificate
                )
            )
        )
    }

    static func registerLegacyParser() {
        NIOSSHAlgorithms.register(
            publicKey: TestRSAPublicKey.self,
            signature: TestRSALegacySignature.self,
            userAuthenticationAlgorithm: .init(
                name: self.publicKeyPrefix,
                certificate: .init(
                    publicKeyPrefix: self.certificatePublicKeyPrefix,
                    name: self.certificatePublicKeyPrefix
                )
            )
        )
    }
}

struct TestRSAPublicKey: NIOSSHPublicKeyProtocol {
    static let publicKeyPrefix = TestRSAAlgorithms.publicKeyPrefix

    var exponent: Data
    var modulus: Data

    var rawRepresentation: Data {
        var buffer = ByteBufferAllocator().buffer(capacity: self.exponent.count + self.modulus.count + 8)
        buffer.writeSSHString(self.exponent)
        buffer.writeSSHString(self.modulus)
        return Data(buffer.readableBytesView)
    }

    init(exponent: Data, modulus: Data) {
        self.exponent = Self.normalizedUnsignedInteger(exponent)
        self.modulus = Self.normalizedUnsignedInteger(modulus)
    }

    func isValidSignature<D: DataProtocol>(
        _ signature: NIOSSHSignatureProtocol,
        for data: D
    ) -> Bool {
        guard let signature = signature as? TestRSASHA256Signature else {
            return false
        }
        return signature.rawRepresentation == Self.testSignature(for: data)
    }

    func write(to buffer: inout ByteBuffer) -> Int {
        var written = buffer.writePositiveMPInt(self.exponent)
        written += buffer.writePositiveMPInt(self.modulus)
        return written
    }

    static func read(from buffer: inout ByteBuffer) throws -> Self {
        guard let exponent = buffer.readSSHString(), let modulus = buffer.readSSHString() else {
            throw NIOSSHError.invalidSSHMessage(reason: "incomplete RSA public key")
        }
        return .init(
            exponent: exponent.unsignedMPIntBytes,
            modulus: modulus.unsignedMPIntBytes
        )
    }

    static func testSignature<D: DataProtocol>(for data: D) -> Data {
        let digest = SHA256.hash(data: data)
        var signature = Data()
        signature.reserveCapacity(256)
        for _ in 0..<8 {
            signature.append(contentsOf: digest)
        }
        return signature
    }

    private static func normalizedUnsignedInteger(_ value: Data) -> Data {
        var bytes = Array(value)
        while bytes.count > 1 && bytes.first == 0 {
            bytes.removeFirst()
        }
        return Data(bytes)
    }
}

struct TestRSAPrivateKey: NIOSSHPrivateKeyProtocol {
    static let keyPrefix = TestRSAAlgorithms.publicKeyPrefix

    var userAuthenticationAlgorithmIdentifier: String {
        TestRSAAlgorithms.sha256
    }

    var backing: TestRSAPublicKey

    #if os(macOS)
    private var openSSLKeyPath: String?
    #endif

    init() throws {
        self.backing = .init(
            exponent: Data([0x01, 0x00, 0x01]),
            modulus: Data([0x80] + Array(repeating: 0xa5, count: 255))
        )
        #if os(macOS)
        self.openSSLKeyPath = nil
        #endif
    }

    #if os(macOS)
    init(openSSLKeyPath: String, publicKey: TestRSAPublicKey) {
        self.backing = publicKey
        self.openSSLKeyPath = openSSLKeyPath
    }
    #endif

    var publicKey: NIOSSHPublicKeyProtocol {
        self.backing
    }

    func signature<D: DataProtocol>(for data: D) throws -> NIOSSHSignatureProtocol {
        #if os(macOS)
        if let openSSLKeyPath = self.openSSLKeyPath {
            return TestRSASHA256Signature(
                rawRepresentation: try Self.openSSLSignature(for: data, keyPath: openSSLKeyPath)
            )
        }
        #endif
        return TestRSASHA256Signature(rawRepresentation: TestRSAPublicKey.testSignature(for: data))
    }

    #if os(macOS)
    private static func openSSLSignature<D: DataProtocol>(for data: D, keyPath: String) throws -> Data {
        let process = Process()
        let inPipe = Pipe()
        let outPipe = Pipe()
        let errPipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["dgst", "-sha256", "-sign", keyPath]
        process.standardInput = inPipe
        process.standardOutput = outPipe
        process.standardError = errPipe
        try process.run()
        try inPipe.fileHandleForWriting.write(contentsOf: Data(data))
        try inPipe.fileHandleForWriting.close()
        process.waitUntilExit()
        let signature = outPipe.fileHandleForReading.readDataToEndOfFile()
        let diagnostics = errPipe.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationStatus == 0 else {
            throw TestRSAError.externalSigningFailed(
                process.terminationStatus,
                String(decoding: diagnostics, as: UTF8.self)
            )
        }
        return signature
    }
    #endif
}

struct ContextAwareTestRSAPrivateKey: NIOSSHPrivateKeyProtocol {
    static let keyPrefix = TestRSAAlgorithms.publicKeyPrefix

    var userAuthenticationAlgorithmIdentifier: String {
        TestRSAAlgorithms.sha256
    }

    var backing: TestRSAPrivateKey

    init() throws {
        self.backing = try .init()
    }

    var publicKey: NIOSSHPublicKeyProtocol {
        self.backing.publicKey
    }

    func signature<D: DataProtocol>(for data: D) throws -> NIOSSHSignatureProtocol {
        TestRSALegacySignature(rawRepresentation: TestRSAPublicKey.testSignature(for: data))
    }

    func userAuthenticationSignature<D: DataProtocol>(for data: D) throws -> NIOSSHSignatureProtocol {
        try self.backing.signature(for: data)
    }
}

struct LegacyPrefixedRSAPrivateKey: NIOSSHPrivateKeyProtocol {
    static let keyPrefix = "test-rsa-private-key"

    var backing: TestRSAPrivateKey

    var publicKey: NIOSSHPublicKeyProtocol {
        self.backing.publicKey
    }

    func signature<D: DataProtocol>(for data: D) throws -> NIOSSHSignatureProtocol {
        try self.backing.signature(for: data)
    }
}

struct TestRSASHA256Signature: NIOSSHSignatureProtocol {
    static let signaturePrefix = TestRSAAlgorithms.sha256
    var rawRepresentation: Data

    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHString(self.rawRepresentation)
    }

    static func read(from buffer: inout ByteBuffer) throws -> Self {
        guard let bytes = buffer.readSSHString() else {
            throw NIOSSHError.invalidSSHMessage(reason: "incomplete RSA SHA-256 signature")
        }
        return .init(rawRepresentation: Data(bytes.readableBytesView))
    }
}

struct TestRSASHA512Signature: NIOSSHSignatureProtocol {
    static let signaturePrefix = TestRSAAlgorithms.sha512
    var rawRepresentation: Data

    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHString(self.rawRepresentation)
    }

    static func read(from buffer: inout ByteBuffer) throws -> Self {
        guard let bytes = buffer.readSSHString() else {
            throw NIOSSHError.invalidSSHMessage(reason: "incomplete RSA SHA-512 signature")
        }
        return .init(rawRepresentation: Data(bytes.readableBytesView))
    }
}

struct TestRSALegacySignature: NIOSSHSignatureProtocol {
    static let signaturePrefix = TestRSAAlgorithms.publicKeyPrefix
    var rawRepresentation: Data

    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHString(self.rawRepresentation)
    }

    static func read(from buffer: inout ByteBuffer) throws -> Self {
        guard let bytes = buffer.readSSHString() else {
            throw NIOSSHError.invalidSSHMessage(reason: "incomplete legacy RSA signature")
        }
        return .init(rawRepresentation: Data(bytes.readableBytesView))
    }
}

private extension ByteBuffer {
    var unsignedMPIntBytes: Data {
        var bytes = Array(self.readableBytesView)
        while bytes.count > 1 && bytes.first == 0 {
            bytes.removeFirst()
        }
        return Data(bytes)
    }
}

private enum TestRSAError: Error {
    case externalSigningFailed(Int32, String)
}
