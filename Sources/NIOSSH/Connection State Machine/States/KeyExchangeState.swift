//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

extension SSHConnectionStateMachine {
    /// The state of a state machine that is actively engaged in a key exchange operation.
    struct KeyExchangeState {
        /// The role of the connection
        let role: SSHConnectionRole

        /// The packet parser.
        var parser: SSHPacketParser

        /// The packet serializer used by this state machine.
        var serializer: SSHPacketSerializer

        var remoteVersion: String

        /// The backing state machine.
        var keyExchangeStateMachine: SSHKeyExchangeStateMachine

        let connectionAttributes: SSHConnectionStateMachine.Attributes

        init(sentVersionState state: SentVersionState, allocator: ByteBufferAllocator, loop: EventLoop, remoteVersion: String) {
            self.role = state.role
            self.parser = state.parser
            self.serializer = state.serializer
            self.remoteVersion = remoteVersion
            self.keyExchangeStateMachine = SSHKeyExchangeStateMachine(allocator: allocator, loop: loop, role: state.role, remoteVersion: remoteVersion, keyExchangeAlgorithms: state.role.keyExchangeAlgorithms, transportProtectionSchemes: state.role.transportProtectionSchemes, previousSessionIdentifier: nil)
            self.connectionAttributes = state.connectionAttributes
        }
    }
}

extension SSHConnectionStateMachine.KeyExchangeState: AcceptsKeyExchangeMessages {}

extension SSHConnectionStateMachine.KeyExchangeState: SendsKeyExchangeMessages {}
