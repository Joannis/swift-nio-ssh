//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import NIO

/// A signature is a mathematical scheme for verifying the authenticity of digital messages or documents.
///
/// This protocol can be implemented by a type that represents such a signature to NIOSSH.
///
/// - See: https://en.wikipedia.org/wiki/Digital_signature
public protocol NIOSSHSignatureProtocol {
    /// Identifiers that represent the types of signatures used in an SSH packet.
    /// These identifiers MUST be unique to the signature implementation.
    /// The returned values MUST NOT overlap with other signature implementations or specifications that the signature does not implement.
    static var signaturePrefixes: [String] { get }
    
    /// The raw representation of this signature as a blob.
    var rawRepresentation: Data { get }

    /// Serializes and writes the signature to the buffer. The calling function SHOULD NOT keep track of the size of the written blob.
    /// If the result is not a fixed size, the serialized format SHOULD include a length.
    func write(to buffer: inout ByteBuffer) -> Int

    /// Reads this Signature from the buffer using the same format implemented in `write(to:)`
    static func read(from buffer: inout ByteBuffer) throws -> Self
}

internal extension NIOSSHSignatureProtocol {
    var signaturePrefixes: [String] {
        Self.signaturePrefixes
    }
}

public protocol NIOSSHPublicKeyProtocol {
    /// Identifiers that represent the types of public keys used in an SSH packet.
    /// These identifiers MUST be unique to the public key implementation.
    /// The returned values MUST NOT overlap with other public key implementations or specifications that the public key does not implement.
    static var publicKeyPrefixes: [String] { get }
    
    /// The raw representation of this public key as a blob.
    var rawRepresentation: Data { get }

    /// Verifies that `signature` is the result of signing `data` using the private key that this public key is derived from.
    func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignatureProtocol, for data: D) -> Bool

    /// Serializes and writes the public key to the buffer. The calling function SHOULD NOT keep track of the size of the written blob.
    /// If the result is not a fixed size, the serialized format SHOULD include a length.
    func write(to buffer: inout ByteBuffer) -> Int

    /// Reads this Public Key from the buffer using the same format implemented in `write(to:)`
    static func read(from buffer: inout ByteBuffer) throws -> Self
}

internal extension NIOSSHPublicKeyProtocol {
    var publicKeyPrefixes: [String] {
        Self.publicKeyPrefixes
    }
}

public protocol NIOSSHPrivateKeyProtocol {
    /// Identifiers that represent the types of private keys used in an SSH packet.
    /// These identifiers MUST be unique to the private key implementation.
    /// The returned values MUST NOT overlap with other private key implementations or specifications that the private key does not implement.
    static var keyPrefixes: [String] { get }
    
    /// A public key instance that is able to verify signatures that are created using this private key.
    var publicKey: NIOSSHPublicKeyProtocol { get }

    /// Creates a signature, proving that `data` has been sent by the holder of this private key, and can be verified by `publicKey`.
    func signature<D: DataProtocol>(for data: D) throws -> NIOSSHSignatureProtocol
}

internal extension NIOSSHPrivateKeyProtocol {
    var keyPrefixes: [String] {
        Self.keyPrefixes
    }
}
