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

#if os(macOS)
import Foundation
import NIOCore
import NIOPosix
@testable import NIOSSH
import XCTest

final class OpenSSHRSACertificateInteropTests: XCTestCase {
    func testAuthenticatesToOpenSSHWithRSASHA256Certificate() throws {
        let sshKeygen = "/usr/bin/ssh-keygen"
        let sshd = "/usr/sbin/sshd"
        let netcat = "/usr/bin/nc"
        let openSSL = "/usr/bin/openssl"
        for executable in [sshKeygen, sshd, netcat, openSSL]
        where !FileManager.default.isExecutableFile(atPath: executable)
        {
            throw XCTSkip("OpenSSH interoperability tool is unavailable: \(executable)")
        }

        NIOSSHAlgorithms.unregisterAlgorithms()
        TestRSAAlgorithms.registerSHA256()
        defer { NIOSSHAlgorithms.unregisterAlgorithms() }

        let temporaryDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("nio-ssh-rsa-cert-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: temporaryDirectory,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: temporaryDirectory) }

        let hostKeyPath = temporaryDirectory.appendingPathComponent("host_key").path
        let caKeyPath = temporaryDirectory.appendingPathComponent("ca_key").path
        let userKeyPath = temporaryDirectory.appendingPathComponent("user_key").path
        let username = NSUserName()

        try self.run(sshKeygen, ["-q", "-t", "ed25519", "-N", "", "-f", hostKeyPath])
        try self.run(sshKeygen, ["-q", "-t", "ed25519", "-N", "", "-f", caKeyPath])
        try self.run(sshKeygen, ["-q", "-m", "PEM", "-t", "rsa", "-b", "2048", "-N", "", "-f", userKeyPath])
        try self.run(
            sshKeygen,
            [
                "-q", "-s", caKeyPath,
                "-I", "nio-rsa-cert",
                "-n", username,
                "-V", "-1m:+10m",
                "\(userKeyPath).pub",
            ]
        )

        let certificateText = try String(contentsOfFile: "\(userKeyPath)-cert.pub", encoding: .utf8)
        let certifiedPublicKey = try XCTUnwrap(
            NIOSSHCertifiedPublicKey(
                NIOSSHPublicKey(openSSHPublicKey: certificateText)
            )
        )
        guard case .custom(let parsedPublicKey) = certifiedPublicKey.key.backingKey,
            let rsaPublicKey = parsedPublicKey as? TestRSAPublicKey
        else {
            return XCTFail("expected the OpenSSH certificate to contain an RSA public key")
        }
        let privateKey = TestRSAPrivateKey(openSSLKeyPath: userKeyPath, publicKey: rsaPublicKey)

        let caPublicKeyText = try String(contentsOfFile: "\(caKeyPath).pub", encoding: .utf8)
        let caPublicKey = try NIOSSHPublicKey(openSSHPublicKey: caPublicKeyText)
        XCTAssertNoThrow(
            try certifiedPublicKey.validate(
                principal: username,
                type: .user,
                allowedAuthoritySigningKeys: [caPublicKey]
            )
        )
        XCTAssertEqual(String(certifiedPublicKey.keyPrefix), TestRSAAlgorithms.certificatePublicKeyPrefix)

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let port = try self.unusedLoopbackPort(group: group)

        let daemon = Process()
        let daemonErrorPipe = Pipe()
        daemon.executableURL = URL(fileURLWithPath: sshd)
        daemon.arguments = [
            "-D", "-e", "-f", "/dev/null",
            "-p", String(port),
            "-h", hostKeyPath,
            "-o", "ListenAddress=127.0.0.1",
            "-o", "PidFile=\(temporaryDirectory.appendingPathComponent("sshd.pid").path)",
            "-o", "AuthorizedKeysFile=none",
            "-o", "TrustedUserCAKeys=\(caKeyPath).pub",
            "-o", "StrictModes=no",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "UsePAM=no",
            "-o", "PubkeyAuthentication=yes",
            "-o", "PubkeyAcceptedAlgorithms=\(TestRSAAlgorithms.sha256Certificate)",
            "-o", "CASignatureAlgorithms=ssh-ed25519",
        ]
        daemon.standardError = daemonErrorPipe
        try daemon.run()
        defer {
            if daemon.isRunning {
                daemon.terminate()
            }
            daemon.waitUntilExit()
        }

        guard self.waitUntilListening(netcat: netcat, port: port, daemon: daemon) else {
            if daemon.isRunning {
                daemon.terminate()
                daemon.waitUntilExit()
            }
            let diagnostics = String(
                decoding: daemonErrorPipe.fileHandleForReading.readDataToEndOfFile(),
                as: UTF8.self
            )
            XCTFail("OpenSSH daemon did not start: \(diagnostics)")
            return
        }

        let successPromise = group.next().makePromise(of: Void.self)
        let authenticationDelegate = OpenSSHCertificateClientAuthDelegate(
            username: username,
            privateKey: .init(custom: privateKey),
            certificate: certifiedPublicKey
        )
        let observer = OpenSSHAuthenticationObserver(successPromise: successPromise)
        let bootstrap = ClientBootstrap(group: group)
            .channelInitializer { channel in
                channel.pipeline.addHandlers([
                    NIOSSHHandler(
                        role: .client(
                            .init(
                                userAuthDelegate: authenticationDelegate,
                                serverAuthDelegate: OpenSSHAcceptAllHostKeysDelegate()
                            )
                        ),
                        allocator: channel.allocator,
                        inboundChildChannelInitializer: nil
                    ),
                    observer,
                ])
            }

        let channel = try bootstrap.connect(host: "127.0.0.1", port: port).wait()
        defer { try? channel.close().wait() }
        let timeout = channel.eventLoop.scheduleTask(in: .seconds(10)) {
            observer.failIfPending(OpenSSHInteropError.authenticationTimedOut)
        }
        defer { timeout.cancel() }

        try successPromise.futureResult.wait()
        XCTAssertEqual(authenticationDelegate.offerCount, 1)
    }

    private func unusedLoopbackPort(group: EventLoopGroup) throws -> Int {
        let channel = try ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeSucceededVoidFuture()
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer { try? channel.close().wait() }
        return try XCTUnwrap(channel.localAddress?.port)
    }

    @discardableResult
    private func run(_ executable: String, _ arguments: [String]) throws -> String {
        let process = Process()
        let outPipe = Pipe()
        let errPipe = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = outPipe
        process.standardError = errPipe
        try process.run()
        process.waitUntilExit()
        let standardOutput = outPipe.fileHandleForReading.readDataToEndOfFile()
        let standardError = errPipe.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationStatus == 0 else {
            throw OpenSSHInteropError.processFailed(
                executable,
                process.terminationStatus,
                String(decoding: standardError, as: UTF8.self)
            )
        }
        return String(decoding: standardOutput, as: UTF8.self)
    }

    private func waitUntilListening(netcat: String, port: Int, daemon: Process) -> Bool {
        for _ in 0..<100 {
            guard daemon.isRunning else {
                return false
            }
            let probe = Process()
            probe.executableURL = URL(fileURLWithPath: netcat)
            probe.arguments = ["-z", "127.0.0.1", String(port)]
            probe.standardOutput = FileHandle.nullDevice
            probe.standardError = FileHandle.nullDevice
            try? probe.run()
            probe.waitUntilExit()
            if probe.terminationStatus == 0 {
                return true
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        return false
    }
}

private final class OpenSSHCertificateClientAuthDelegate: NIOSSHClientUserAuthenticationDelegate {
    private let username: String
    private let privateKey: NIOSSHPrivateKey
    private let certificate: NIOSSHCertifiedPublicKey
    private(set) var offerCount = 0

    init(username: String, privateKey: NIOSSHPrivateKey, certificate: NIOSSHCertifiedPublicKey) {
        self.username = username
        self.privateKey = privateKey
        self.certificate = certificate
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        guard availableMethods.contains(.publicKey), self.offerCount == 0 else {
            nextChallengePromise.succeed(nil)
            return
        }
        self.offerCount += 1
        nextChallengePromise.succeed(
            .init(
                username: self.username,
                serviceName: "ssh-connection",
                offer: .privateKey(
                    .init(privateKey: self.privateKey, certifiedKey: self.certificate)
                )
            )
        )
    }
}

private struct OpenSSHAcceptAllHostKeysDelegate: NIOSSHClientServerAuthenticationDelegate {
    func validateHostKey(
        hostKey: NIOSSHPublicKey,
        validationCompletePromise: EventLoopPromise<Void>
    ) {
        validationCompletePromise.succeed(())
    }
}

private final class OpenSSHAuthenticationObserver: ChannelInboundHandler {
    typealias InboundIn = Any

    private let successPromise: EventLoopPromise<Void>
    private var isComplete = false

    init(successPromise: EventLoopPromise<Void>) {
        self.successPromise = successPromise
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if event is UserAuthSuccessEvent, !self.isComplete {
            self.isComplete = true
            self.successPromise.succeed(())
        }
        context.fireUserInboundEventTriggered(event)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        self.failIfPending(error)
        context.close(promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        self.failIfPending(OpenSSHInteropError.connectionClosed)
        context.fireChannelInactive()
    }

    func failIfPending(_ error: Error) {
        guard !self.isComplete else {
            return
        }
        self.isComplete = true
        self.successPromise.fail(error)
    }
}

private enum OpenSSHInteropError: Error, CustomStringConvertible {
    case processFailed(String, Int32, String)
    case authenticationTimedOut
    case connectionClosed

    var description: String {
        switch self {
        case .processFailed(let executable, let status, let diagnostics):
            return "\(executable) exited with status \(status): \(diagnostics)"
        case .authenticationTimedOut:
            return "OpenSSH authentication timed out"
        case .connectionClosed:
            return "OpenSSH closed the connection before authentication succeeded"
        }
    }
}
#endif
