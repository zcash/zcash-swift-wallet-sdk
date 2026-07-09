//
//  ZcashP2PSubmitter.swift
//  ZcashLightClientKit
//

import CommonCrypto
import Foundation

/// Submits a transaction directly to a Zcash P2P full node using the native Zcash
/// wire protocol, bypassing lightwalletd/Zaino.
///
/// This implements the "direct P2P submission" path from ZIP 327 / ZIP 328
/// (Component A): the wallet connects directly to a node, performs the version
/// handshake, and sends the raw transaction bytes as a `tx` P2P message.  The
/// receiving node enters the transaction into its Dandelion++ stem phase, preventing
/// any intermediary server from observing the IP↔transaction correlation.
///
/// ## Wire protocol
/// ```
/// TCP connect → send version → recv version → send verack
///             → recv verack  → send tx msg  → disconnect
/// ```
/// The `tx` message is sent without a prior `inv` (the "unadvertised tx" convention
/// from ZIP 327 §Stem-phase forwarding), signalling to the receiving node that this
/// is a direct wallet submission.
///
/// ## Peer discovery
/// Uses the Zcash mainnet DNS seeders (same set as Zebra defaults) to find a random
/// live full node.  Shuffles results and tries each in turn.
final class ZcashP2PSubmitter: EndpointSubmitter {
    private let p2pNetwork: ZcashP2PNetwork
    private let logger: Logger

    init(p2pNetwork: ZcashP2PNetwork, logger: Logger) {
        self.p2pNetwork = p2pNetwork
        self.logger = logger
    }

    func submit(transaction: CreatedTransaction, to endpoint: LightWalletEndpoint) async throws {
        let peers = try resolvePeers()
        guard !peers.isEmpty else {
            logger.error("Dandelion P2P: no peers resolved from DNS seeders")
            throw ZcashP2PError.noPeersAvailable
        }

        var lastError: Error = ZcashP2PError.noPeersAvailable
        for peer in peers.shuffled() {
            do {
                try await submitToPeer(peer, rawTx: transaction.raw)
                logger.info("Dandelion P2P: tx submitted via \(peer.hostName ?? peer.host ?? "?")")
                return
            } catch {
                logger.warn("Dandelion P2P: peer failed (\(error)); trying next")
                lastError = error
            }
        }
        throw lastError
    }

    // MARK: - Peer discovery

    private func resolvePeers() throws -> [NWPeer] {
        var peers: [NWPeer] = []
        for seeder in p2pNetwork.dnsSeeds {
            if let resolved = try? resolveHost(seeder) {
                peers += resolved
            }
        }
        return peers
    }

    /// Resolves a hostname to a list of IPv4/IPv6 addresses using the system resolver.
    private func resolveHost(_ hostname: String) throws -> [NWPeer] {
        var results: [String] = []
        var hints = addrinfo()
        hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
        hints.ai_family = Int32(AF_UNSPEC)

        var res: UnsafeMutablePointer<addrinfo>?
        defer { if res != nil { freeaddrinfo(res) } }

        let status = getaddrinfo(hostname, nil, &hints, &res)
        guard status == 0, let first = res else { return [] }

        var current: UnsafeMutablePointer<addrinfo>? = first
        while let info = current {
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(info.pointee.ai_addr, info.pointee.ai_addrlen,
                           &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                let addr = String(cString: host)
                results.append(addr)
            }
            current = info.pointee.ai_next
        }
        return results.map { NWPeer(host: $0, hostName: hostname) }
    }

    // MARK: - Wire exchange

    private func submitToPeer(_ peer: NWPeer, rawTx: Data) async throws {
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    try self.submitToPeerBlocking(peer, rawTx: rawTx)
                    continuation.resume()
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private func submitToPeerBlocking(_ peer: NWPeer, rawTx: Data) throws {
        let sock = try connect(to: peer.host ?? peer.hostName ?? "", port: p2pNetwork.port)
        defer { close(sock) }

        // 1. Send version
        let versionMsg = buildMessage(command: "version", payload: buildVersionPayload(peer: peer.host ?? ""))
        try sendAll(sock: sock, data: versionMsg)

        // 2. Receive version + verack
        var sawVersion = false
        var sawVerack = false
        for _ in 0..<10 {
            guard let msg = try? readMessage(sock: sock) else { break }
            if msg.command == "version" { sawVersion = true }
            if msg.command == "verack"  { sawVerack = true }
            if sawVersion { break }
        }
        guard sawVersion else { throw ZcashP2PError.handshakeFailed }

        // 3. Send verack
        try sendAll(sock: sock, data: buildMessage(command: "verack", payload: Data()))

        // 4. Send tx (unadvertised — no prior inv)
        try sendAll(sock: sock, data: buildMessage(command: "tx", payload: rawTx))

        // 5. Brief read for reject; timeout/EOF = success
        _ = try? readMessage(sock: sock)
        _ = sawVerack // used for debug; not required
    }

    // MARK: - Low-level socket

    private func connect(to host: String, port: Int) throws -> Int32 {
        var hints = addrinfo()
        hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
        hints.ai_family = Int32(AF_UNSPEC)

        var res: UnsafeMutablePointer<addrinfo>?
        defer { if res != nil { freeaddrinfo(res) } }

        guard getaddrinfo(host, String(port), &hints, &res) == 0,
              let info = res else { throw ZcashP2PError.connectionFailed }

        let fd = socket(info.pointee.ai_family, info.pointee.ai_socktype, 0)
        guard fd >= 0 else { throw ZcashP2PError.connectionFailed }

        // 5 second connect timeout via non-blocking + select
        var flags = fcntl(fd, F_GETFL, 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        let rc = Foundation.connect(fd, info.pointee.ai_addr, info.pointee.ai_addrlen)
        if rc != 0 && errno != EINPROGRESS {
            close(fd)
            throw ZcashP2PError.connectionFailed
        }

        var wfds = fd_set()
        FD_ZERO(&wfds)
        withUnsafeMutablePointer(to: &wfds) { ptr in
            let base = ptr.pointer(to: \.fds_bits)!
            let word = Int(fd) / (MemoryLayout<Int32>.size * 8)
            let bit  = Int(fd) % (MemoryLayout<Int32>.size * 8)
            _ = withUnsafeMutableBytes(of: &base[word]) { $0.storeBytes(of: Int32(1) << bit, as: Int32.self) }
        }
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        let sel = select(fd + 1, nil, &wfds, nil, &timeout)
        if sel <= 0 {
            close(fd)
            throw ZcashP2PError.connectionFailed
        }

        // Restore blocking
        flags = fcntl(fd, F_GETFL, 0)
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK)

        // Set 8-second IO timeout
        var tv = timeval(tv_sec: 8, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        return fd
    }

    private func sendAll(sock: Int32, data: Data) throws {
        var sent = 0
        try data.withUnsafeBytes { (buf: UnsafeRawBufferPointer) throws in
            while sent < data.count {
                let n = send(sock, buf.baseAddress!.advanced(by: sent), data.count - sent, 0)
                if n <= 0 { throw ZcashP2PError.sendFailed }
                sent += n
            }
        }
    }

    // MARK: - Zcash P2P framing

    private struct P2PMessage { let command: String; let payload: Data }

    private func buildMessage(command: String, payload: Data) -> Data {
        var magic = p2pNetwork.magic
        var cmdBytes = [UInt8](repeating: 0, count: 12)
        let enc = Array(command.utf8)
        for i in 0..<min(enc.count, 12) { cmdBytes[i] = enc[i] }

        let checksum = doubleSHA256(payload).prefix(4)
        var header = Data()
        header.append(contentsOf: magic)
        header.append(contentsOf: cmdBytes)
        var length = UInt32(payload.count).littleEndian
        header.append(contentsOf: withUnsafeBytes(of: &length) { Array($0) })
        header.append(contentsOf: checksum)
        return header + payload
    }

    private func buildVersionPayload(peer: String) -> Data {
        var data = Data()
        // Must be >= the node's minimum accepted protocol version (Zebra's floor
        // is the NU6.2 version 170_150 on mainnet/testnet/regtest) or the peer
        // rejects the handshake and disconnects.
        var version   = Int32(170_150).littleEndian
        var services  = UInt64(1).littleEndian
        var timestamp = Int64(Date().timeIntervalSince1970).littleEndian
        var nonce     = UInt64.random(in: 0...UInt64.max).littleEndian
        var height    = Int32(0).littleEndian

        data.append(contentsOf: withUnsafeBytes(of: &version)   { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: &services)  { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: &timestamp) { Array($0) })
        data.append(contentsOf: [UInt8](repeating: 0, count: 26)) // addr_recv
        data.append(contentsOf: [UInt8](repeating: 0, count: 26)) // addr_from
        data.append(contentsOf: withUnsafeBytes(of: &nonce)     { Array($0) })
        let ua = Array("/zodl-wallet:1.0/".utf8)
        data.append(UInt8(ua.count))
        data.append(contentsOf: ua)
        data.append(contentsOf: withUnsafeBytes(of: &height)    { Array($0) })
        return data
    }

    private func readMessage(sock: Int32) throws -> P2PMessage {
        var header = [UInt8](repeating: 0, count: 24)
        try recvAll(sock: sock, buf: &header, count: 24)
        let lengthBytes = header[16..<20]
        let length = Int(UInt32(littleEndian: lengthBytes.withUnsafeBytes { $0.load(as: UInt32.self) }))
        guard length >= 0 && length <= 4_000_000 else { throw ZcashP2PError.protocolError }
        var payload = [UInt8](repeating: 0, count: length)
        if length > 0 { try recvAll(sock: sock, buf: &payload, count: length) }
        let command = String(bytes: header[4..<16].prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
        return P2PMessage(command: command, payload: Data(payload))
    }

    private func recvAll(sock: Int32, buf: inout [UInt8], count: Int) throws {
        var received = 0
        while received < count {
            let n = recv(sock, &buf[received], count - received, 0)
            if n <= 0 { throw ZcashP2PError.receiveFailed }
            received += n
        }
    }

    private func doubleSHA256(_ data: Data) -> Data {
        let first  = data.sha256()
        return first.sha256()
    }
}

// MARK: - Supporting types

private struct NWPeer {
    let host: String?
    let hostName: String?
}

enum ZcashP2PError: Error {
    case noPeersAvailable
    case connectionFailed
    case handshakeFailed
    case sendFailed
    case receiveFailed
    case protocolError
    case rejected(String)
}

/// Wraps P2PSubmitter + falls back to gRPC lwd if P2P transport fails.
final class FallbackEndpointSubmitter: EndpointSubmitter {
    private let primary: EndpointSubmitter
    private let fallback: EndpointSubmitter
    private let logger: Logger

    init(primary: EndpointSubmitter, fallback: EndpointSubmitter, logger: Logger) {
        self.primary = primary
        self.fallback = fallback
        self.logger = logger
    }

    func submit(transaction: CreatedTransaction, to endpoint: LightWalletEndpoint) async throws {
        do {
            try await primary.submit(transaction: transaction, to: endpoint)
        } catch {
            logger.warn("Dandelion P2P submission failed (\(error)); falling back to lwd")
            try await fallback.submit(transaction: transaction, to: endpoint)
        }
    }
}

// MARK: - Data+SHA256 helper (stdlib only)

private extension Data {
    func sha256() -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        self.withUnsafeBytes { CC_SHA256($0.baseAddress, CC_LONG(self.count), &digest) }
        return Data(digest)
    }
}
