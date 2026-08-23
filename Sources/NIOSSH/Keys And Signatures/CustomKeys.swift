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
    /// An identifier that represents the type of signature used in an SSH packet.
    /// This identifier MUST be unique to the signature implementation.
    /// The returned value MUST NOT overlap with other signature implementations or a specifications that the signature does not implement.
    static var signaturePrefix: String { get }

    /// The raw reprentation of this signature as a blob.
    var rawRepresentation: Data { get }

    /// Serializes and writes only the algorithm-specific signature body to the buffer.
    ///
    /// NIOSSH writes `signaturePrefix` before calling this method. Implementations MUST NOT write
    /// that identifier again. If the body is not a fixed size, its serialized format SHOULD include
    /// a length.
    func write(to buffer: inout ByteBuffer) -> Int

    /// Reads the algorithm-specific body after NIOSSH has consumed `signaturePrefix`.
    static func read(from buffer: inout ByteBuffer) throws -> Self
}

internal extension NIOSSHSignatureProtocol {
    var signaturePrefix: String {
        Self.signaturePrefix
    }
}

public protocol NIOSSHPublicKeyProtocol {
    /// An identifier that represents the type of public key used in an SSH packet.
    /// This identifier MUST be unique to the public key implementation.
    /// The returned value MUST NOT overlap with other public key implementations or a specifications that the public key does not implement.
    static var publicKeyPrefix: String { get }

    /// The raw reprentation of this publc key as a blob.
    var rawRepresentation: Data { get }

    /// Verifies that `signature` is the result of signing `data` using the private key that this public key is derived from.
    func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignatureProtocol, for data: D) -> Bool

    /// Serializes and writes only the algorithm-specific public-key body to the buffer.
    /// NIOSSH writes the applicable public-key or certificate identifier before calling this method.
    /// If the body is not a fixed size, its serialized format SHOULD include a length.
    func write(to buffer: inout ByteBuffer) -> Int

    /// Reads the algorithm-specific body after NIOSSH has consumed its identifier.
    static func read(from buffer: inout ByteBuffer) throws -> Self
}

internal extension NIOSSHPublicKeyProtocol {
    var publicKeyPrefix: String {
        Self.publicKeyPrefix
    }
}

public protocol NIOSSHPrivateKeyProtocol {
    /// An identifier that represents the type of private key used in an SSH packet.
    /// This identifier MUST be unique to the private key implementation.
    /// The returned value MUST NOT overlap with other private key implementations or a specifications that the private key does not implement.
    static var keyPrefix: String { get }

    /// The identifier used to select this key's public-key user-authentication algorithm mapping.
    ///
    /// This value is selected before the authentication payload is signed. It is deliberately
    /// separate from the public-key format and is used to resolve the algorithm name carried in
    /// `SSH_MSG_USERAUTH_REQUEST`. It must match the name or an alias of a registered
    /// `NIOSSHUserAuthenticationAlgorithm`; signature identifiers do not select authentication
    /// mappings. The default preserves the legacy behavior of using `publicKey.publicKeyPrefix`;
    /// implementations that need a different authentication name must override it.
    var userAuthenticationAlgorithmIdentifier: String { get }

    /// A public key instance that is able to verify signatures that are created using this private key.
    var publicKey: NIOSSHPublicKeyProtocol { get }

    /// Creates a signature, proving that `data` has been sent by the holder of this private key, and can be verified by `publicKey`.
    func signature<D: DataProtocol>(for data: D) throws -> NIOSSHSignatureProtocol

    /// Creates the signature used for public-key user authentication.
    ///
    /// The default implementation delegates to `signature(for:)`. Custom keys that use a
    /// different signature algorithm for user authentication than for host-key signing can
    /// override this method without wrapping the key or rewriting the authentication payload.
    func userAuthenticationSignature<D: DataProtocol>(for data: D) throws -> NIOSSHSignatureProtocol
}

internal extension NIOSSHPrivateKeyProtocol {
    var keyPrefix: String {
        Self.keyPrefix
    }
}

public extension NIOSSHPrivateKeyProtocol {
    var userAuthenticationAlgorithmIdentifier: String {
        self.publicKey.publicKeyPrefix
    }

    func userAuthenticationSignature<D: DataProtocol>(for data: D) throws -> NIOSSHSignatureProtocol {
        try self.signature(for: data)
    }
}
