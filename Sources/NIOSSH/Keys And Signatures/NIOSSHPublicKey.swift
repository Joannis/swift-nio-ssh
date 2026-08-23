//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
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
import NIOConcurrencyHelpers
import NIOCore
import NIOFoundationCompat

/// An SSH public key.
///
/// This object identifies a single SSH server or user. It is used as part of the SSH handshake and key exchange process,
/// is presented to clients that want to validate that they are communicating with the appropriate server, and is also used
/// to validate users.
///
/// This key is not capable of signing, only verifying.
public struct NIOSSHPublicKey: Hashable {
    /// The actual key structure used to perform the key operations.
    internal var backingKey: BackingKey

    internal init(backingKey: BackingKey) {
        self.backingKey = backingKey
    }

    /// Create a ``NIOSSHPublicKey`` from the OpenSSH public key string.
    public init(openSSHPublicKey: String) throws {
        // The OpenSSH public key format is like this: "algorithm-id base64-encoded-key comments"
        //
        // We split on spaces, no more than twice. We then check if we know about the algorithm identifier and, if we
        // do, we parse the key.
        var components = ArraySlice(openSSHPublicKey.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true))
        guard let keyIdentifier = components.popFirst(), let keyData = components.popFirst() else {
            throw NIOSSHError.invalidOpenSSHPublicKey(reason: "invalid number of sections")
        }
        guard let rawBytes = Data(base64Encoded: String(keyData)) else {
            throw NIOSSHError.invalidOpenSSHPublicKey(reason: "could not base64-decode string")
        }

        var buffer = ByteBufferAllocator().buffer(capacity: rawBytes.count)
        buffer.writeContiguousBytes(rawBytes)
        guard let key = try buffer.readSSHHostKey() else {
            throw NIOSSHError.invalidOpenSSHPublicKey(reason: "incomplete key data")
        }
        guard key.keyPrefix.elementsEqual(keyIdentifier.utf8) else {
            throw NIOSSHError.invalidOpenSSHPublicKey(reason: "inconsistent key type within openssh key format")
        }
        self = key
    }

    /// Encapsulate a ``NIOSSHCertifiedPublicKey`` in a ``NIOSSHPublicKey``.
    ///
    /// This initializer can be used to "wrap" a ``NIOSSHCertifiedPublicKey`` into the interface of ``NIOSSHPublicKey``.
    /// It is typically used in cases where the fact that the key is certified is not relevant.
    public init(_ certifiedKey: NIOSSHCertifiedPublicKey) {
        self.backingKey = .certified(certifiedKey)
    }
}

extension NIOSSHPublicKey {
    /// Verifies that a given `NIOSSHSignature` was created by the holder of the private key associated with this
    /// public key.
    public func isValidSignature<DigestBytes: Digest>(_ signature: NIOSSHSignature, for digest: DigestBytes) -> Bool {
        switch (self.backingKey, signature.backingSignature) {
        case (.ed25519(let key), .ed25519(let sig)):
            return digest.withUnsafeBytes { digestPtr in
                switch sig {
                case .byteBuffer(let buf):
                    return key.isValidSignature(buf.readableBytesView, for: digestPtr)
                case .data(let d):
                    return key.isValidSignature(d, for: digestPtr)
                }
            }
        case (.ecdsaP256(let key), .ecdsaP256(let sig)):
            return digest.withUnsafeBytes { digestPtr in
                key.isValidSignature(sig, for: digestPtr)
            }
        case (.ecdsaP384(let key), .ecdsaP384(let sig)):
            return digest.withUnsafeBytes { digestPtr in
                key.isValidSignature(sig, for: digestPtr)
            }
        case (.ecdsaP521(let key), .ecdsaP521(let sig)):
            return digest.withUnsafeBytes { digestPtr in
                key.isValidSignature(sig, for: digestPtr)
            }
        case (.custom(let key), .custom(let sig)):
            return digest.withUnsafeBytes { digestPtr in
                key.isValidSignature(sig, for: digestPtr)
            }
        case (.certified(let key), _):
            return key.isValidSignature(signature, for: digest)
        case (.ed25519, _),
             (.ecdsaP256, _),
             (.ecdsaP384, _),
             (.ecdsaP521, _),
             (.custom, _):
            return false
        }
    }

    internal func isValidSignature(_ signature: NIOSSHSignature, for bytes: ByteBuffer) -> Bool {
        switch (self.backingKey, signature.backingSignature) {
        case (.ed25519(let key), .ed25519(.byteBuffer(let buf))):
            return key.isValidSignature(buf.readableBytesView, for: bytes.readableBytesView)
        case (.ed25519(let key), .ed25519(.data(let buf))):
            return key.isValidSignature(buf, for: bytes.readableBytesView)
        case (.ecdsaP256(let key), .ecdsaP256(let sig)):
            return key.isValidSignature(sig, for: bytes.readableBytesView)
        case (.ecdsaP384(let key), .ecdsaP384(let sig)):
            return key.isValidSignature(sig, for: bytes.readableBytesView)
        case (.ecdsaP521(let key), .ecdsaP521(let sig)):
            return key.isValidSignature(sig, for: bytes.readableBytesView)
        case (.custom(let key), .custom(let sig)):
            return key.isValidSignature(sig, for: bytes.readableBytesView)
        case (.certified(let key), _):
            return key.isValidSignature(signature, for: bytes)
        case (.ed25519, _),
             (.ecdsaP256, _),
             (.ecdsaP384, _),
             (.ecdsaP521, _),
             (.custom, _):
            return false
        }
    }

    internal func isValidSignature(_ signature: NIOSSHSignature, for payload: UserAuthSignablePayload) -> Bool {
        switch (self.backingKey, signature.backingSignature) {
        case (.ed25519(let key), .ed25519(.byteBuffer(let sig))):
            return key.isValidSignature(sig.readableBytesView, for: payload.bytes.readableBytesView)
        case (.ed25519(let key), .ed25519(.data(let sig))):
            return key.isValidSignature(sig, for: payload.bytes.readableBytesView)
        case (.ecdsaP256(let key), .ecdsaP256(let sig)):
            return key.isValidSignature(sig, for: payload.bytes.readableBytesView)
        case (.ecdsaP384(let key), .ecdsaP384(let sig)):
            return key.isValidSignature(sig, for: payload.bytes.readableBytesView)
        case (.ecdsaP521(let key), .ecdsaP521(let sig)):
            return key.isValidSignature(sig, for: payload.bytes.readableBytesView)
        case (.custom(let key), .custom(let sig)):
            return key.isValidSignature(sig, for: payload.bytes.readableBytesView)
        case (.certified(let key), _):
            return key.isValidSignature(signature, for: payload)
        case (.ed25519, _),
             (.ecdsaP256, _),
             (.ecdsaP384, _),
             (.ecdsaP521, _),
             (.custom, _):
            return false
        }
    }
}

extension NIOSSHPublicKey {
    /// The various key types that can be used with NIOSSH.
    enum BackingKey {
        case ed25519(Curve25519.Signing.PublicKey)
        case ecdsaP256(P256.Signing.PublicKey)
        case ecdsaP384(P384.Signing.PublicKey)
        case ecdsaP521(P521.Signing.PublicKey)
        case custom(NIOSSHPublicKeyProtocol)
        case certified(NIOSSHCertifiedPublicKey) // This case recursively contains `NIOSSHPublicKey`.
    }

    /// The prefix of an Ed25519 public key.
    static let ed25519PublicKeyPrefix = "ssh-ed25519".utf8

    /// The prefix of a P256 ECDSA public key.
    static let ecdsaP256PublicKeyPrefix = "ecdsa-sha2-nistp256".utf8

    /// The prefix of a P384 ECDSA public key.
    static let ecdsaP384PublicKeyPrefix = "ecdsa-sha2-nistp384".utf8

    /// The prefix of a P521 ECDSA public key.
    static let ecdsaP521PublicKeyPrefix = "ecdsa-sha2-nistp521".utf8

    var keyPrefix: String.UTF8View {
        switch self.backingKey {
        case .ed25519:
            return Self.ed25519PublicKeyPrefix
        case .ecdsaP256:
            return Self.ecdsaP256PublicKeyPrefix
        case .ecdsaP384:
            return Self.ecdsaP384PublicKeyPrefix
        case .ecdsaP521:
            return Self.ecdsaP521PublicKeyPrefix
        case .custom(let publicKey):
            return publicKey.publicKeyPrefix.utf8
        case .certified(let base):
            return base.keyPrefix
        }
    }

    static var customPublicKeyAlgorithms: [NIOSSHPublicKeyProtocol.Type] {
        var identifiers = Set<ObjectIdentifier>()
        return customPublicKeyAlgorithmRegistrations.compactMap { registration in
            let identifier = ObjectIdentifier(registration.publicKey)
            return identifiers.insert(identifier).inserted ? registration.publicKey : nil
        }
    }

    static var customSignatures: [NIOSSHSignatureProtocol.Type] {
        var identifiers = Set<ObjectIdentifier>()
        return customPublicKeyAlgorithmRegistrations.compactMap { registration in
            let identifier = ObjectIdentifier(registration.signature)
            return identifiers.insert(identifier).inserted ? registration.signature : nil
        }
    }

    static var customPublicKeyAlgorithmRegistrations: [PublicKeyAlgorithmRegistration] {
        _CustomAlgorithms.publicKeyAlgorithmRegistrationsLock.withLock {
            _CustomAlgorithms.publicKeyAlgorithmRegistrations
        }
    }
}

/// Describes the algorithm identifiers used by a custom public key during SSH user authentication.
///
/// SSH uses three independently-framed identifiers in public-key authentication: the public-key
/// format inside the key blob, the algorithm in `SSH_MSG_USERAUTH_REQUEST`, and the algorithm inside
/// the signature blob. The public-key and signature formats come from `NIOSSHPublicKeyProtocol` and
/// `NIOSSHSignatureProtocol`; this value supplies the user-authentication name and, when supported,
/// the certificate-specific names.
///
/// Canonical names and aliases occupy one global user-authentication namespace. A name may only be
/// reused when it selects the same public-key format, plain or certificate form, and signature
/// procedure.
public struct NIOSSHUserAuthenticationAlgorithm: Hashable {
    /// The certificate form of a user-authentication algorithm.
    public struct Certificate: Hashable {
        /// The canonical identifier written inside a certificate public-key blob.
        public var publicKeyPrefix: String

        /// The algorithm identifier carried in certificate authentication requests.
        public var name: String

        /// Equivalent authentication identifiers accepted while parsing.
        public var aliases: [String]

        public init(
            publicKeyPrefix: String,
            name: String,
            aliases: [String] = []
        ) {
            self.publicKeyPrefix = publicKeyPrefix
            self.name = name
            self.aliases = aliases
        }
    }

    /// The algorithm identifier carried in a non-certificate authentication request.
    public var name: String

    /// Equivalent authentication identifiers accepted while parsing.
    public var aliases: [String]

    /// Certificate-specific identifiers, or `nil` when this registration cannot encode certificates.
    public var certificate: Certificate?

    public init(
        name: String,
        aliases: [String] = [],
        certificate: Certificate? = nil
    ) {
        self.name = name
        self.aliases = aliases
        self.certificate = certificate
    }
}

#if swift(>=5.5)
extension NIOSSHUserAuthenticationAlgorithm: Sendable {}
extension NIOSSHUserAuthenticationAlgorithm.Certificate: Sendable {}
#endif

struct PublicKeyAlgorithmRegistration {
    var publicKey: NIOSSHPublicKeyProtocol.Type
    var signature: NIOSSHSignatureProtocol.Type
    var userAuthenticationAlgorithm: NIOSSHUserAuthenticationAlgorithm
}

enum UserAuthenticationPublicKeyForm: Hashable {
    case plain
    case certificate
}

enum UserAuthenticationAlgorithmParserIdentity: Hashable {
    case bundledEd25519
    case bundledECDSAP256
    case bundledECDSAP384
    case bundledECDSAP521
    case custom(ObjectIdentifier)
}

/// The meaning assigned to a user-authentication algorithm name.
struct UserAuthenticationAlgorithmBinding: Hashable {
    var publicKeyParser: UserAuthenticationAlgorithmParserIdentity
    var publicKeyPrefix: String
    var publicKeyForm: UserAuthenticationPublicKeyForm
    var signatureParser: UserAuthenticationAlgorithmParserIdentity
    var signaturePrefix: String
}

struct NamedUserAuthenticationAlgorithmBinding {
    var names: [String]
    var binding: UserAuthenticationAlgorithmBinding
}

extension PublicKeyAlgorithmRegistration {
    var namedUserAuthenticationAlgorithmBindings: [NamedUserAuthenticationAlgorithmBinding] {
        var bindings = [
            NamedUserAuthenticationAlgorithmBinding(
                names: [self.userAuthenticationAlgorithm.name] + self.userAuthenticationAlgorithm.aliases,
                binding: .init(
                    publicKeyParser: .custom(ObjectIdentifier(self.publicKey)),
                    publicKeyPrefix: self.publicKey.publicKeyPrefix,
                    publicKeyForm: .plain,
                    signatureParser: .custom(ObjectIdentifier(self.signature)),
                    signaturePrefix: self.signature.signaturePrefix
                )
            )
        ]

        if let certificate = self.userAuthenticationAlgorithm.certificate {
            bindings.append(
                .init(
                    names: [certificate.name] + certificate.aliases,
                    binding: .init(
                        publicKeyParser: .custom(ObjectIdentifier(self.publicKey)),
                        publicKeyPrefix: certificate.publicKeyPrefix,
                        publicKeyForm: .certificate,
                        signatureParser: .custom(ObjectIdentifier(self.signature)),
                        signaturePrefix: self.signature.signaturePrefix
                    )
                )
            )
        }
        return bindings
    }
}

struct ResolvedUserAuthenticationAlgorithm {
    var name: String
    var signaturePrefix: String
}

extension NIOSSHPublicKey {
    static func isKnownUserAuthenticationAlgorithm(_ name: String) -> Bool {
        NIOSSHAlgorithms.userAuthenticationAlgorithmBindings(
            for: self.customPublicKeyAlgorithmRegistrations
        )?[name] != nil
    }

    func userAuthenticationAlgorithm(
        forAlgorithmIdentifier algorithmIdentifier: String
    ) -> ResolvedUserAuthenticationAlgorithm? {
        switch self.backingKey {
        case .ed25519:
            return algorithmIdentifier == String(Self.ed25519PublicKeyPrefix)
                ? .init(name: String(Self.ed25519PublicKeyPrefix), signaturePrefix: algorithmIdentifier)
                : nil
        case .ecdsaP256:
            return algorithmIdentifier == String(Self.ecdsaP256PublicKeyPrefix)
                ? .init(name: String(Self.ecdsaP256PublicKeyPrefix), signaturePrefix: algorithmIdentifier)
                : nil
        case .ecdsaP384:
            return algorithmIdentifier == String(Self.ecdsaP384PublicKeyPrefix)
                ? .init(name: String(Self.ecdsaP384PublicKeyPrefix), signaturePrefix: algorithmIdentifier)
                : nil
        case .ecdsaP521:
            return algorithmIdentifier == String(Self.ecdsaP521PublicKeyPrefix)
                ? .init(name: String(Self.ecdsaP521PublicKeyPrefix), signaturePrefix: algorithmIdentifier)
                : nil
        case .custom(let key):
            return Self.registrations(for: key).lazy.compactMap { registration in
                let algorithm = registration.userAuthenticationAlgorithm
                guard algorithm.name == algorithmIdentifier
                    || algorithm.aliases.contains(algorithmIdentifier)
                else {
                    return nil
                }
                return .init(
                    name: algorithm.name,
                    signaturePrefix: registration.signature.signaturePrefix
                )
            }.first
        case .certified(let certificate):
            switch certificate.key.backingKey {
            case .custom(let key):
                return Self.registrations(for: key).lazy.compactMap { registration in
                    let algorithm = registration.userAuthenticationAlgorithm
                    guard algorithm.name == algorithmIdentifier
                        || algorithm.aliases.contains(algorithmIdentifier),
                        let certificateAlgorithm = algorithm.certificate
                    else {
                        return nil
                    }
                    return .init(
                        name: certificateAlgorithm.name,
                        signaturePrefix: registration.signature.signaturePrefix
                    )
                }.first
            case .ed25519:
                return algorithmIdentifier == String(Self.ed25519PublicKeyPrefix)
                    ? .init(name: String(NIOSSHCertifiedPublicKey.ed25519KeyPrefix), signaturePrefix: algorithmIdentifier)
                    : nil
            case .ecdsaP256:
                return algorithmIdentifier == String(Self.ecdsaP256PublicKeyPrefix)
                    ? .init(name: String(NIOSSHCertifiedPublicKey.p256KeyPrefix), signaturePrefix: algorithmIdentifier)
                    : nil
            case .ecdsaP384:
                return algorithmIdentifier == String(Self.ecdsaP384PublicKeyPrefix)
                    ? .init(name: String(NIOSSHCertifiedPublicKey.p384KeyPrefix), signaturePrefix: algorithmIdentifier)
                    : nil
            case .ecdsaP521:
                return algorithmIdentifier == String(Self.ecdsaP521PublicKeyPrefix)
                    ? .init(name: String(NIOSSHCertifiedPublicKey.p521KeyPrefix), signaturePrefix: algorithmIdentifier)
                    : nil
            case .certified:
                preconditionFailure("base key cannot be certified")
            }
        }
    }

    func userAuthenticationAlgorithm(
        named name: String
    ) -> ResolvedUserAuthenticationAlgorithm? {
        switch self.backingKey {
        case .ed25519:
            return name == String(Self.ed25519PublicKeyPrefix)
                ? .init(name: name, signaturePrefix: name)
                : nil
        case .ecdsaP256:
            return name == String(Self.ecdsaP256PublicKeyPrefix)
                ? .init(name: name, signaturePrefix: name)
                : nil
        case .ecdsaP384:
            return name == String(Self.ecdsaP384PublicKeyPrefix)
                ? .init(name: name, signaturePrefix: name)
                : nil
        case .ecdsaP521:
            return name == String(Self.ecdsaP521PublicKeyPrefix)
                ? .init(name: name, signaturePrefix: name)
                : nil
        case .custom(let key):
            return Self.registrations(for: key).lazy.compactMap { registration in
                let algorithm = registration.userAuthenticationAlgorithm
                guard algorithm.name == name
                    || algorithm.aliases.contains(name)
                else {
                    return nil
                }
                return .init(name: name, signaturePrefix: registration.signature.signaturePrefix)
            }.first
        case .certified(let certificate):
            switch certificate.key.backingKey {
            case .custom(let key):
                return Self.registrations(for: key).lazy.compactMap { registration in
                    guard let certificateAlgorithm = registration.userAuthenticationAlgorithm.certificate,
                        certificateAlgorithm.name == name
                            || certificateAlgorithm.aliases.contains(name)
                    else {
                        return nil
                    }
                    return .init(name: name, signaturePrefix: registration.signature.signaturePrefix)
                }.first
            case .ed25519:
                return name == String(NIOSSHCertifiedPublicKey.ed25519KeyPrefix)
                    ? .init(name: name, signaturePrefix: String(Self.ed25519PublicKeyPrefix))
                    : nil
            case .ecdsaP256:
                return name == String(NIOSSHCertifiedPublicKey.p256KeyPrefix)
                    ? .init(name: name, signaturePrefix: String(Self.ecdsaP256PublicKeyPrefix))
                    : nil
            case .ecdsaP384:
                return name == String(NIOSSHCertifiedPublicKey.p384KeyPrefix)
                    ? .init(name: name, signaturePrefix: String(Self.ecdsaP384PublicKeyPrefix))
                    : nil
            case .ecdsaP521:
                return name == String(NIOSSHCertifiedPublicKey.p521KeyPrefix)
                    ? .init(name: name, signaturePrefix: String(Self.ecdsaP521PublicKeyPrefix))
                    : nil
            case .certified:
                preconditionFailure("base key cannot be certified")
            }
        }
    }

    static func certificatePublicKeyPrefix(for key: NIOSSHPublicKeyProtocol) -> String? {
        self.registrations(for: key).lazy.compactMap {
            $0.userAuthenticationAlgorithm.certificate?.publicKeyPrefix
        }.first
    }

    static func basePublicKeyPrefix(forCertificatePublicKeyPrefix prefix: String) -> String? {
        self.customPublicKeyAlgorithmRegistrations.lazy.compactMap { registration in
            guard let certificate = registration.userAuthenticationAlgorithm.certificate,
                certificate.publicKeyPrefix == prefix
            else {
                return nil
            }
            return registration.publicKey.publicKeyPrefix
        }.first
    }

    private static func registrations(
        for key: NIOSSHPublicKeyProtocol
    ) -> [PublicKeyAlgorithmRegistration] {
        let keyTypeIdentifier = ObjectIdentifier(type(of: key))
        return self.customPublicKeyAlgorithmRegistrations.filter {
            ObjectIdentifier($0.publicKey) == keyTypeIdentifier
        }
    }
}

public enum NIOSSHAlgorithms {
    private static let bundledUserAuthenticationAlgorithmBindings: [NamedUserAuthenticationAlgorithmBinding] = [
        .init(
            names: [String(NIOSSHPublicKey.ed25519PublicKeyPrefix)],
            binding: .init(
                publicKeyParser: .bundledEd25519,
                publicKeyPrefix: String(NIOSSHPublicKey.ed25519PublicKeyPrefix),
                publicKeyForm: .plain,
                signatureParser: .bundledEd25519,
                signaturePrefix: String(NIOSSHPublicKey.ed25519PublicKeyPrefix)
            )
        ),
        .init(
            names: [String(NIOSSHPublicKey.ecdsaP256PublicKeyPrefix)],
            binding: .init(
                publicKeyParser: .bundledECDSAP256,
                publicKeyPrefix: String(NIOSSHPublicKey.ecdsaP256PublicKeyPrefix),
                publicKeyForm: .plain,
                signatureParser: .bundledECDSAP256,
                signaturePrefix: String(NIOSSHPublicKey.ecdsaP256PublicKeyPrefix)
            )
        ),
        .init(
            names: [String(NIOSSHPublicKey.ecdsaP384PublicKeyPrefix)],
            binding: .init(
                publicKeyParser: .bundledECDSAP384,
                publicKeyPrefix: String(NIOSSHPublicKey.ecdsaP384PublicKeyPrefix),
                publicKeyForm: .plain,
                signatureParser: .bundledECDSAP384,
                signaturePrefix: String(NIOSSHPublicKey.ecdsaP384PublicKeyPrefix)
            )
        ),
        .init(
            names: [String(NIOSSHPublicKey.ecdsaP521PublicKeyPrefix)],
            binding: .init(
                publicKeyParser: .bundledECDSAP521,
                publicKeyPrefix: String(NIOSSHPublicKey.ecdsaP521PublicKeyPrefix),
                publicKeyForm: .plain,
                signatureParser: .bundledECDSAP521,
                signaturePrefix: String(NIOSSHPublicKey.ecdsaP521PublicKeyPrefix)
            )
        ),
        .init(
            names: [String(NIOSSHCertifiedPublicKey.ed25519KeyPrefix)],
            binding: .init(
                publicKeyParser: .bundledEd25519,
                publicKeyPrefix: String(NIOSSHCertifiedPublicKey.ed25519KeyPrefix),
                publicKeyForm: .certificate,
                signatureParser: .bundledEd25519,
                signaturePrefix: String(NIOSSHPublicKey.ed25519PublicKeyPrefix)
            )
        ),
        .init(
            names: [String(NIOSSHCertifiedPublicKey.p256KeyPrefix)],
            binding: .init(
                publicKeyParser: .bundledECDSAP256,
                publicKeyPrefix: String(NIOSSHCertifiedPublicKey.p256KeyPrefix),
                publicKeyForm: .certificate,
                signatureParser: .bundledECDSAP256,
                signaturePrefix: String(NIOSSHPublicKey.ecdsaP256PublicKeyPrefix)
            )
        ),
        .init(
            names: [String(NIOSSHCertifiedPublicKey.p384KeyPrefix)],
            binding: .init(
                publicKeyParser: .bundledECDSAP384,
                publicKeyPrefix: String(NIOSSHCertifiedPublicKey.p384KeyPrefix),
                publicKeyForm: .certificate,
                signatureParser: .bundledECDSAP384,
                signaturePrefix: String(NIOSSHPublicKey.ecdsaP384PublicKeyPrefix)
            )
        ),
        .init(
            names: [String(NIOSSHCertifiedPublicKey.p521KeyPrefix)],
            binding: .init(
                publicKeyParser: .bundledECDSAP521,
                publicKeyPrefix: String(NIOSSHCertifiedPublicKey.p521KeyPrefix),
                publicKeyForm: .certificate,
                signatureParser: .bundledECDSAP521,
                signaturePrefix: String(NIOSSHPublicKey.ecdsaP521PublicKeyPrefix)
            )
        ),
    ]

    private static let bundledPublicKeyBlobPrefixes = Set(
        Self.bundledUserAuthenticationAlgorithmBindings.map { $0.binding.publicKeyPrefix }
    )

    private static let bundledSignaturePrefixes = Set(
        Self.bundledUserAuthenticationAlgorithmBindings.map { $0.binding.signaturePrefix }
    )

    static func validatedUserAuthenticationAlgorithmBindings(
        customBindings: [NamedUserAuthenticationAlgorithmBinding]
    ) -> [String: UserAuthenticationAlgorithmBinding]? {
        var bindings: [String: UserAuthenticationAlgorithmBinding] = [:]
        for namedBinding in Self.bundledUserAuthenticationAlgorithmBindings + customBindings {
            guard !namedBinding.names.isEmpty, !namedBinding.names.contains("") else {
                return nil
            }
            for name in namedBinding.names {
                if let existingBinding = bindings[name], existingBinding != namedBinding.binding {
                    return nil
                }
                bindings[name] = namedBinding.binding
            }
        }
        return bindings
    }

    static func userAuthenticationAlgorithmBindings(
        for registrations: [PublicKeyAlgorithmRegistration]
    ) -> [String: UserAuthenticationAlgorithmBinding]? {
        Self.validatedUserAuthenticationAlgorithmBindings(
            customBindings: registrations.flatMap { $0.namedUserAuthenticationAlgorithmBindings }
        )
    }

    public static func register(keyExchangeAlgorithm type: NIOSSHKeyExchangeAlgorithmProtocol.Type) {
        _CustomAlgorithms.keyExchangeAlgorithmsLock.withLockVoid {
            if !_CustomAlgorithms.keyExchangeAlgorithms.contains(where: { ObjectIdentifier($0) == ObjectIdentifier(type) }) {
                _CustomAlgorithms.keyExchangeAlgorithms.append(type)
            }
        }
    }

    public static func register(transportProtectionScheme type: NIOSSHTransportProtection.Type) {
        _CustomAlgorithms.transportProtectionSchemesLock.withLockVoid {
            if !_CustomAlgorithms.transportProtectionSchemes.contains(where: { ObjectIdentifier($0) == ObjectIdentifier(type) }) {
                _CustomAlgorithms.transportProtectionSchemes.append(type)
            }
        }
    }

    /// Registers a custom type tuple for use in Public Key Authentication.
    public static func register<
        PublicKey: NIOSSHPublicKeyProtocol,
        Signature: NIOSSHSignatureProtocol
    >(
        publicKey type: PublicKey.Type,
        signature: Signature.Type
    ) {
        self.register(
            publicKey: type,
            signature: signature,
            userAuthenticationAlgorithm: .init(name: PublicKey.publicKeyPrefix)
        )
    }

    /// Registers a custom public-key format, signature format, and user-authentication mapping.
    public static func register<
        PublicKey: NIOSSHPublicKeyProtocol,
        Signature: NIOSSHSignatureProtocol
    >(
        publicKey type: PublicKey.Type,
        signature: Signature.Type,
        userAuthenticationAlgorithm: NIOSSHUserAuthenticationAlgorithm
    ) {
        _CustomAlgorithms.publicKeyAlgorithmRegistrationsLock.withLockVoid {
            let publicKeyTypeIdentifier = ObjectIdentifier(type)
            let signatureTypeIdentifier = ObjectIdentifier(signature)
            let signaturePrefix = Signature.signaturePrefix
            let newRegistration = PublicKeyAlgorithmRegistration(
                publicKey: type,
                signature: signature,
                userAuthenticationAlgorithm: userAuthenticationAlgorithm
            )
            precondition(
                !signaturePrefix.isEmpty && !Self.bundledSignaturePrefixes.contains(signaturePrefix),
                "Custom signature identifiers must be non-empty and must not overlap bundled algorithms"
            )
            let registrationsUsingSignaturePrefix = _CustomAlgorithms.publicKeyAlgorithmRegistrations.filter {
                $0.signature.signaturePrefix == signaturePrefix
            }
            precondition(
                registrationsUsingSignaturePrefix.allSatisfy { ObjectIdentifier($0.signature) == signatureTypeIdentifier },
                "A signature identifier must use one globally consistent parser type"
            )

            let certificatePrefix = userAuthenticationAlgorithm.certificate?.publicKeyPrefix
            let newBlobPrefixes = Set([PublicKey.publicKeyPrefix] + [certificatePrefix].compactMap { $0 })
            precondition(
                newBlobPrefixes.count == (certificatePrefix == nil ? 1 : 2),
                "A certificate and its base public key must use distinct blob identifiers"
            )
            precondition(
                newBlobPrefixes.isDisjoint(with: Self.bundledPublicKeyBlobPrefixes),
                "Custom public-key blob identifiers must not overlap bundled algorithms"
            )
            let otherRegisteredBlobPrefixes = Set(
                _CustomAlgorithms.publicKeyAlgorithmRegistrations
                    .filter { ObjectIdentifier($0.publicKey) != publicKeyTypeIdentifier }
                    .flatMap { registration -> [String] in
                        var prefixes = [registration.publicKey.publicKeyPrefix]
                        if let certificatePrefix = registration.userAuthenticationAlgorithm.certificate?.publicKeyPrefix {
                            prefixes.append(certificatePrefix)
                        }
                        return prefixes
                    }
            )
            precondition(
                newBlobPrefixes.isDisjoint(with: otherRegisteredBlobPrefixes),
                "Custom public-key blob identifiers must be globally unique"
            )

            let plainAuthenticationNames = Set(
                [userAuthenticationAlgorithm.name]
                    + userAuthenticationAlgorithm.aliases
            )
            let certificateAuthenticationNames = Set(
                [userAuthenticationAlgorithm.certificate?.name].compactMap { $0 }
                    + (userAuthenticationAlgorithm.certificate?.aliases ?? [])
            )
            precondition(
                !plainAuthenticationNames.contains("")
                    && !certificateAuthenticationNames.contains("")
                    && plainAuthenticationNames.isDisjoint(with: certificateAuthenticationNames),
                "Plain and certificate user-authentication identifiers must be non-empty and distinct"
            )
            precondition(
                Self.userAuthenticationAlgorithmBindings(
                    for: _CustomAlgorithms.publicKeyAlgorithmRegistrations + [newRegistration]
                ) != nil,
                "A user-authentication identifier must resolve to one key format, key form, and signature algorithm"
            )

            if let certificatePrefix = userAuthenticationAlgorithm.certificate?.publicKeyPrefix {
                let registeredPrefixes = _CustomAlgorithms.publicKeyAlgorithmRegistrations.compactMap { registration -> String? in
                    guard ObjectIdentifier(registration.publicKey) == publicKeyTypeIdentifier else {
                        return nil
                    }
                    return registration.userAuthenticationAlgorithm.certificate?.publicKeyPrefix
                }
                precondition(
                    registeredPrefixes.allSatisfy { $0 == certificatePrefix },
                    "All algorithms for a custom public key must use the same canonical certificate format"
                )
            }
            let alreadyRegistered = _CustomAlgorithms.publicKeyAlgorithmRegistrations.contains { registration in
                ObjectIdentifier(registration.publicKey) == publicKeyTypeIdentifier
                    && ObjectIdentifier(registration.signature) == signatureTypeIdentifier
                    && registration.userAuthenticationAlgorithm == userAuthenticationAlgorithm
            }
            if !alreadyRegistered {
                _CustomAlgorithms.publicKeyAlgorithmRegistrations.append(newRegistration)
            }
        }
    }

    /// Used for our unit tests
    internal static func unregisterAlgorithms() {
        _CustomAlgorithms.transportProtectionSchemesLock.withLockVoid {
            _CustomAlgorithms.transportProtectionSchemes = []
        }
        _CustomAlgorithms.publicKeyAlgorithmRegistrationsLock.withLockVoid {
            _CustomAlgorithms.publicKeyAlgorithmRegistrations = []
        }
        _CustomAlgorithms.keyExchangeAlgorithmsLock.withLockVoid {
            _CustomAlgorithms.keyExchangeAlgorithms = []
        }
    }
}

internal var customTransportProtectionSchemes: [NIOSSHTransportProtection.Type] {
    _CustomAlgorithms.transportProtectionSchemesLock.withLock {
        _CustomAlgorithms.transportProtectionSchemes
    }
}

internal var customKeyExchangeAlgorithms: [NIOSSHKeyExchangeAlgorithmProtocol.Type] {
    _CustomAlgorithms.keyExchangeAlgorithmsLock.withLock {
        _CustomAlgorithms.keyExchangeAlgorithms
    }
}

private enum _CustomAlgorithms {
    static var transportProtectionSchemesLock = NIOLock()
    static var transportProtectionSchemes = [NIOSSHTransportProtection.Type]()
    static var keyExchangeAlgorithmsLock = NIOLock()
    static var keyExchangeAlgorithms = [NIOSSHKeyExchangeAlgorithmProtocol.Type]()
    static var publicKeyAlgorithmRegistrationsLock = NIOLock()
    static var publicKeyAlgorithmRegistrations: [PublicKeyAlgorithmRegistration] = []
}

extension NIOSSHPublicKey.BackingKey: Equatable {
    static func == (lhs: NIOSSHPublicKey.BackingKey, rhs: NIOSSHPublicKey.BackingKey) -> Bool {
        // We implement equatable in terms of the key representation.
        switch (lhs, rhs) {
        case (.ed25519(let lhs), .ed25519(let rhs)):
            return lhs.rawRepresentation == rhs.rawRepresentation
        case (.ecdsaP256(let lhs), .ecdsaP256(let rhs)):
            return lhs.rawRepresentation == rhs.rawRepresentation
        case (.ecdsaP384(let lhs), .ecdsaP384(let rhs)):
            return lhs.rawRepresentation == rhs.rawRepresentation
        case (.ecdsaP521(let lhs), .ecdsaP521(let rhs)):
            return lhs.rawRepresentation == rhs.rawRepresentation
        case (.custom(let lhs), .custom(let rhs)):
            return
                lhs.publicKeyPrefix == rhs.publicKeyPrefix &&
                lhs.rawRepresentation == rhs.rawRepresentation
        case (.certified(let lhs), .certified(let rhs)):
            return lhs == rhs
        case (.ed25519, _),
             (.ecdsaP256, _),
             (.ecdsaP384, _),
             (.ecdsaP521, _),
             (.custom, _),
             (.certified, _):
            return false
        }
    }
}

extension NIOSSHPublicKey.BackingKey: Hashable {
    func hash(into hasher: inout Hasher) {
        switch self {
        case .ed25519(let pkey):
            hasher.combine(1)
            hasher.combine(pkey.rawRepresentation)
        case .ecdsaP256(let pkey):
            hasher.combine(2)
            hasher.combine(pkey.rawRepresentation)
        case .ecdsaP384(let pkey):
            hasher.combine(3)
            hasher.combine(pkey.rawRepresentation)
        case .ecdsaP521(let pkey):
            hasher.combine(4)
            hasher.combine(pkey.rawRepresentation)
        case .custom(let pkey):
            hasher.combine(5)
            hasher.combine(pkey.publicKeyPrefix)
            hasher.combine(pkey.rawRepresentation)
        case .certified(let pkey):
            hasher.combine(6)
            hasher.combine(pkey)
        }
    }
}

extension NIOSSHPublicKey {
    @discardableResult
    public func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHHostKey(self)
    }

    @discardableResult
    func writeWithoutHeader(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHHostKeyWithoutHeader(self)
    }
}

extension ByteBuffer {
    @discardableResult
    mutating func writeSSHHostKeyWithoutHeader(_ key: NIOSSHPublicKey) -> Int {
        switch key.backingKey {
        case .ed25519(let key):
            return self.writeEd25519PublicKey(baseKey: key)
        case .ecdsaP256(let key):
            return self.writeECDSAP256PublicKey(baseKey: key)
        case .ecdsaP384(let key):
            return self.writeECDSAP384PublicKey(baseKey: key)
        case .ecdsaP521(let key):
            return self.writeECDSAP521PublicKey(baseKey: key)
        case .custom(let key):
            return key.write(to: &self)
        case .certified(let key):
            return self.writeCertifiedKey(key)
        }
    }

    /// Writes an SSH host key to this `ByteBuffer`.
    @discardableResult
    mutating func writeSSHHostKey(_ key: NIOSSHPublicKey) -> Int {
        var writtenBytes = 0

        switch key.backingKey {
        case .ed25519(let key):
            writtenBytes += self.writeSSHString(NIOSSHPublicKey.ed25519PublicKeyPrefix)
            writtenBytes += self.writeEd25519PublicKey(baseKey: key)
        case .ecdsaP256(let key):
            writtenBytes += self.writeSSHString(NIOSSHPublicKey.ecdsaP256PublicKeyPrefix)
            writtenBytes += self.writeECDSAP256PublicKey(baseKey: key)
        case .ecdsaP384(let key):
            writtenBytes += self.writeSSHString(NIOSSHPublicKey.ecdsaP384PublicKeyPrefix)
            writtenBytes += self.writeECDSAP384PublicKey(baseKey: key)
        case .ecdsaP521(let key):
            writtenBytes += self.writeSSHString(NIOSSHPublicKey.ecdsaP521PublicKeyPrefix)
            writtenBytes += self.writeECDSAP521PublicKey(baseKey: key)
        case .custom(let key):
            writtenBytes += writeSSHString(key.publicKeyPrefix.utf8)
            writtenBytes += key.write(to: &self)
        case .certified(let key):
            return self.writeCertifiedKey(key)
        }

        return writtenBytes
    }

    /// Writes an SSH host key to this `ByteBuffer`, without a prefix.
    ///
    /// This is mostly used as part of the certified key structure.
    @discardableResult
    mutating func writePublicKeyWithoutPrefix(_ key: NIOSSHPublicKey) -> Int {
        switch key.backingKey {
        case .ed25519(let key):
            return self.writeEd25519PublicKey(baseKey: key)
        case .ecdsaP256(let key):
            return self.writeECDSAP256PublicKey(baseKey: key)
        case .ecdsaP384(let key):
            return self.writeECDSAP384PublicKey(baseKey: key)
        case .ecdsaP521(let key):
            return self.writeECDSAP521PublicKey(baseKey: key)
        case .custom(let key):
            return key.write(to: &self)
        case .certified:
            preconditionFailure("Certified keys are the only callers of this method, and cannot contain themselves")
        }
    }

    mutating func readSSHHostKey() throws -> NIOSSHPublicKey? {
        try self.rewindOnNilOrError { buffer in
            // The wire format always begins with an SSH string containing the key format identifier. Let's grab that.
            guard let keyIdentifierBytes = buffer.readSSHString() else {
                return nil
            }

            // Now we need to check if they match our supported key algorithms.
            return try buffer.readPublicKeyWithoutPrefixForIdentifier(keyIdentifierBytes.readableBytesView)
        }
    }

    mutating func readPublicKeyWithoutPrefixForIdentifier<Bytes: Collection>(_ keyIdentifierBytes: Bytes) throws -> NIOSSHPublicKey? where Bytes.Element == UInt8 {
        try self.rewindOnNilOrError { buffer in
            if keyIdentifierBytes.elementsEqual(NIOSSHPublicKey.ed25519PublicKeyPrefix) {
                return try buffer.readEd25519PublicKey()
            } else if keyIdentifierBytes.elementsEqual(NIOSSHPublicKey.ecdsaP256PublicKeyPrefix) {
                return try buffer.readECDSAP256PublicKey()
            } else if keyIdentifierBytes.elementsEqual(NIOSSHPublicKey.ecdsaP384PublicKeyPrefix) {
                return try buffer.readECDSAP384PublicKey()
            } else if keyIdentifierBytes.elementsEqual(NIOSSHPublicKey.ecdsaP521PublicKeyPrefix) {
                return try buffer.readECDSAP521PublicKey()
            } else {
                for type in NIOSSHPublicKey.customPublicKeyAlgorithms {
                    if keyIdentifierBytes.elementsEqual(type.publicKeyPrefix.utf8) {
                        let publicKey = try type.read(from: &buffer)
                        return NIOSSHPublicKey(backingKey: .custom(publicKey))
                    }
                }

                // We don't know this public key type. Maybe the certified keys do.
                return try buffer.readCertifiedKeyWithoutKeyPrefix(keyIdentifierBytes).map(NIOSSHPublicKey.init)
            }
        }
    }

    private mutating func writeEd25519PublicKey(baseKey: Curve25519.Signing.PublicKey) -> Int {
        // For Ed25519 the key format is  Q as a String.
        self.writeSSHString(baseKey.rawRepresentation)
    }

    private mutating func writeECDSAP256PublicKey(baseKey: P256.Signing.PublicKey) -> Int {
        // For ECDSA-P256, the key format is the string "nistp256", followed by the
        // the public point Q.
        var writtenBytes = 0
        writtenBytes += self.writeSSHString("nistp256".utf8)
        writtenBytes += self.writeSSHString(baseKey.x963Representation)
        return writtenBytes
    }

    private mutating func writeECDSAP384PublicKey(baseKey: P384.Signing.PublicKey) -> Int {
        // For ECDSA-P384, the key format is the string "nistp384", followed by the
        // the public point Q.
        var writtenBytes = 0
        writtenBytes += self.writeSSHString("nistp384".utf8)
        writtenBytes += self.writeSSHString(baseKey.x963Representation)
        return writtenBytes
    }

    private mutating func writeECDSAP521PublicKey(baseKey: P521.Signing.PublicKey) -> Int {
        // For ECDSA-P521, the key format is the string "nistp521", followed by the
        // the public point Q.
        var writtenBytes = 0
        writtenBytes += self.writeSSHString("nistp521".utf8)
        writtenBytes += self.writeSSHString(baseKey.x963Representation)
        return writtenBytes
    }

    /// A helper function that reads an Ed25519 public key.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readEd25519PublicKey() throws -> NIOSSHPublicKey? {
        // For ed25519 the key format is just Q encoded as a String.
        guard let qBytes = self.readSSHString() else {
            return nil
        }

        let key = try Curve25519.Signing.PublicKey(rawRepresentation: qBytes.readableBytesView)
        return NIOSSHPublicKey(backingKey: .ed25519(key))
    }

    /// A helper function that reads an ECDSA P-256 public key.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readECDSAP256PublicKey() throws -> NIOSSHPublicKey? {
        // For ECDSA-P256, the key format is the string "nistp256" followed by the
        // the public point Q.
        guard var domainParameter = self.readSSHString() else {
            return nil
        }
        guard domainParameter.readableBytesView.elementsEqual("nistp256".utf8) else {
            let unexpectedParameter = domainParameter.readString(length: domainParameter.readableBytes) ?? "<unknown domain parameter>"
            throw NIOSSHError.invalidDomainParametersForKey(parameters: unexpectedParameter)
        }

        guard let qBytes = self.readSSHString() else {
            return nil
        }

        let key = try P256.Signing.PublicKey(x963Representation: qBytes.readableBytesView)
        return NIOSSHPublicKey(backingKey: .ecdsaP256(key))
    }

    /// A helper function that reads an ECDSA P-384 public key.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readECDSAP384PublicKey() throws -> NIOSSHPublicKey? {
        // For ECDSA-P384, the key format is the string "nistp384" followed by the
        // the public point Q.
        guard var domainParameter = self.readSSHString() else {
            return nil
        }
        guard domainParameter.readableBytesView.elementsEqual("nistp384".utf8) else {
            let unexpectedParameter = domainParameter.readString(length: domainParameter.readableBytes) ?? "<unknown domain parameter>"
            throw NIOSSHError.invalidDomainParametersForKey(parameters: unexpectedParameter)
        }

        guard let qBytes = self.readSSHString() else {
            return nil
        }

        let key = try P384.Signing.PublicKey(x963Representation: qBytes.readableBytesView)
        return NIOSSHPublicKey(backingKey: .ecdsaP384(key))
    }

    /// A helper function that reads an ECDSA P-521 public key.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readECDSAP521PublicKey() throws -> NIOSSHPublicKey? {
        // For ECDSA-P521, the key format is the string "nistp521" followed by the
        // the public point Q.
        guard var domainParameter = self.readSSHString() else {
            return nil
        }
        guard domainParameter.readableBytesView.elementsEqual("nistp521".utf8) else {
            let unexpectedParameter = domainParameter.readString(length: domainParameter.readableBytes) ?? "<unknown domain parameter>"
            throw NIOSSHError.invalidDomainParametersForKey(parameters: unexpectedParameter)
        }

        guard let qBytes = self.readSSHString() else {
            return nil
        }

        let key = try P521.Signing.PublicKey(x963Representation: qBytes.readableBytesView)
        return NIOSSHPublicKey(backingKey: .ecdsaP521(key))
    }

    /// A helper function for complex readers that will reset a buffer on nil or on error, as though the read
    /// never occurred.
    internal mutating func rewindOnNilOrError<T>(_ body: (inout ByteBuffer) throws -> T?) rethrows -> T? {
        let originalSelf = self

        let returnValue: T?
        do {
            returnValue = try body(&self)
        } catch {
            self = originalSelf
            throw error
        }

        if returnValue == nil {
            self = originalSelf
        }

        return returnValue
    }
}

extension String {
    /// Takes a NIOSSHPublicKey and turns it into OpenSSH public key string in the format of "algorithm-id base64-encoded-key"
    public init(openSSHPublicKey: NIOSSHPublicKey) {
        var buffer = ByteBuffer()
        buffer.writeSSHHostKey(openSSHPublicKey)
        let next = Data(buffer.readableBytesView).base64EncodedString()
        let publicKeyString = String(openSSHPublicKey.keyPrefix) + " " + next
        self = publicKeyString
    }
}
