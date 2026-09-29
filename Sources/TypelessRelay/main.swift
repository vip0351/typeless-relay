import Darwin
import Dispatch
import Foundation

enum RelayError: Error, CustomStringConvertible {
    case invalidArgument(String)
    case socket(String)
    case socks(String)
    case unexpectedEOF

    var description: String {
        switch self {
        case .invalidArgument(let message), .socket(let message), .socks(let message):
            return message
        case .unexpectedEOF:
            return "unexpected end of stream"
        }
    }
}

struct Configuration {
    let listenHost: String
    let listenPort: UInt16
    let socksHost: String
    let socksPort: UInt16
    let targetHost: String
    let targetPort: UInt16
    let directIPv4: String?

    static func parse(_ arguments: [String]) throws -> Configuration {
        var values: [String: String] = [:]
        var index = 1
        while index < arguments.count {
            let key = arguments[index]
            guard key.hasPrefix("--"), index + 1 < arguments.count else {
                throw RelayError.invalidArgument("invalid argument: \(key)")
            }
            values[key] = arguments[index + 1]
            index += 2
        }

        func required(_ key: String) throws -> String {
            guard let value = values[key], !value.isEmpty else {
                throw RelayError.invalidArgument("missing argument: \(key)")
            }
            return value
        }

        func port(_ key: String) throws -> UInt16 {
            let value = try required(key)
            guard let parsed = UInt16(value), parsed > 0 else {
                throw RelayError.invalidArgument("invalid port for \(key): \(value)")
            }
            return parsed
        }

        return Configuration(
            listenHost: try required("--listen-host"),
            listenPort: try port("--listen-port"),
            socksHost: try required("--socks-host"),
            socksPort: try port("--socks-port"),
            targetHost: try required("--target-host"),
            targetPort: try port("--target-port"),
            directIPv4: values["--direct-ipv4"]
        )
    }
}

func errorMessage(_ operation: String) -> String {
    "\(operation): \(String(cString: strerror(errno)))"
}

func configureSocket(_ socket: Int32) {
    var enabled: Int32 = 1
    setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size))
}

func ipv4Address(host: String, port: UInt16) throws -> sockaddr_in {
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = port.bigEndian
    guard inet_pton(AF_INET, host, &address.sin_addr) == 1 else {
        throw RelayError.invalidArgument("only IPv4 literals are supported for local endpoints: \(host)")
    }
    return address
}

func withSocketAddress<T>(
    _ address: inout sockaddr_in,
    _ body: (UnsafePointer<sockaddr>, socklen_t) throws -> T
) rethrows -> T {
    try withUnsafePointer(to: &address) { pointer in
        try pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            try body($0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
}

func openTCP(host: String, port: UInt16, listener: Bool) throws -> Int32 {
    let socket = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    guard socket >= 0 else { throw RelayError.socket(errorMessage("socket")) }
    configureSocket(socket)

    do {
        var address = try ipv4Address(host: host, port: port)
        if listener {
            var reuseAddress: Int32 = 1
            setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &reuseAddress, socklen_t(MemoryLayout<Int32>.size))
            let result = withSocketAddress(&address) { Darwin.bind(socket, $0, $1) }
            guard result == 0 else { throw RelayError.socket(errorMessage("bind")) }
            guard Darwin.listen(socket, 128) == 0 else { throw RelayError.socket(errorMessage("listen")) }
        } else {
            let result = withSocketAddress(&address) { Darwin.connect(socket, $0, $1) }
            guard result == 0 else { throw RelayError.socket(errorMessage("connect")) }
        }
        return socket
    } catch {
        Darwin.close(socket)
        throw error
    }
}

func readExact(_ socket: Int32, count: Int) throws -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: count)
    var offset = 0
    while offset < count {
        let received = bytes.withUnsafeMutableBytes { buffer -> Int in
            Darwin.recv(socket, buffer.baseAddress!.advanced(by: offset), count - offset, 0)
        }
        if received == 0 { throw RelayError.unexpectedEOF }
        if received < 0 {
            if errno == EINTR { continue }
            throw RelayError.socket(errorMessage("recv"))
        }
        offset += received
    }
    return bytes
}

func writeAll(_ socket: Int32, bytes: [UInt8]) throws {
    var offset = 0
    while offset < bytes.count {
        let sent = bytes.withUnsafeBytes { buffer -> Int in
            Darwin.send(socket, buffer.baseAddress!.advanced(by: offset), bytes.count - offset, 0)
        }
        if sent < 0 {
            if errno == EINTR { continue }
            throw RelayError.socket(errorMessage("send"))
        }
        offset += sent
    }
}

// MARK: - DNS resolution bypassing /etc/hosts

func skipDNSName(_ packet: [UInt8], _ offset: Int) -> Int? {
    var index = offset
    while index < packet.count {
        let length = Int(packet[index])
        if length == 0 { return index + 1 }
        if length & 0xC0 == 0xC0 { return index + 2 }
        index += length + 1
    }
    return nil
}

func queryARecords(host: String, server: String, timeoutSeconds: Int) -> [UInt32] {
    var packet: [UInt8] = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    for label in host.split(separator: ".") {
        packet.append(UInt8(label.count))
        packet.append(contentsOf: label.utf8)
    }
    packet.append(0)
    packet.append(contentsOf: [0x00, 0x01, 0x00, 0x01])

    let socket = Darwin.socket(AF_INET, SOCK_DGRAM, 0)
    guard socket >= 0 else { return [] }
    defer { Darwin.close(socket) }
    configureSocket(socket)
    var timeout = timeval(tv_sec: timeoutSeconds, tv_usec: 0)
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = UInt16(53).bigEndian
    guard inet_pton(AF_INET, server, &address.sin_addr) == 1 else { return [] }

    let sent = withUnsafePointer(to: &address) { pointer -> Int in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
            packet.withUnsafeBytes { buffer in
                Darwin.sendto(socket, buffer.baseAddress, buffer.count, 0, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
    }
    guard sent == packet.count else { return [] }

    var response = [UInt8](repeating: 0, count: 512)
    let received = response.withUnsafeMutableBytes { Darwin.recv(socket, $0.baseAddress, $0.count, 0) }
    guard received > 12 else { return [] }
    response = Array(response[0..<received])

    let answerCount = Int(response[6]) << 8 | Int(response[7])
    guard var index = skipDNSName(response, 12) else { return [] }
    index += 4
    var addresses: [UInt32] = []
    for _ in 0..<answerCount {
        guard let nameEnd = skipDNSName(response, index), nameEnd + 10 <= response.count else { break }
        let type = Int(response[nameEnd]) << 8 | Int(response[nameEnd + 1])
        let dataLength = Int(response[nameEnd + 8]) << 8 | Int(response[nameEnd + 9])
        let dataStart = nameEnd + 10
        if type == 1, dataLength == 4, dataStart + 4 <= response.count {
            let value = UInt32(response[dataStart]) << 24 | UInt32(response[dataStart + 1]) << 16
                | UInt32(response[dataStart + 2]) << 8 | UInt32(response[dataStart + 3])
            addresses.append(value)
        }
        index = dataStart + dataLength
    }
    return addresses
}

let resolverLock = NSLock()
var cachedAddresses: [UInt32] = []
var cacheExpiry = Date.distantPast

func resolvedIPv4(host: String) -> UInt32? {
    resolverLock.lock()
    defer { resolverLock.unlock() }
    if Date() < cacheExpiry, let address = cachedAddresses.randomElement() {
        return address
    }
    for server in ["223.5.5.5", "119.29.29.29"] {
        let addresses = queryARecords(host: host, server: server, timeoutSeconds: 3)
        if !addresses.isEmpty {
            cachedAddresses = addresses
            cacheExpiry = Date().addingTimeInterval(60)
            return addresses.randomElement()
        }
    }
    return cachedAddresses.randomElement()
}

func dottedIPv4(_ value: UInt32) -> String {
    var address = in_addr(s_addr: value.bigEndian)
    var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
    _ = inet_ntop(AF_INET, &address, &buffer, socklen_t(INET_ADDRSTRLEN))
    return String(cString: buffer)
}

func setSocketTimeout(_ socket: Int32, seconds: Double) {
    let microseconds = Int(seconds * 1_000_000)
    var timeout = timeval(tv_sec: microseconds / 1_000_000, tv_usec: __darwin_suseconds_t(microseconds % 1_000_000))
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
}

func connectTCP(host: String, port: UInt16, timeoutSeconds: Double) throws -> Int32 {
    let socket = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    guard socket >= 0 else { throw RelayError.socket(errorMessage("socket")) }
    configureSocket(socket)
    do {
        var address = try ipv4Address(host: host, port: port)
        let flags = fcntl(socket, F_GETFL, 0)
        _ = fcntl(socket, F_SETFL, flags | O_NONBLOCK)
        let result = withSocketAddress(&address) { Darwin.connect(socket, $0, $1) }
        if result != 0 {
            guard errno == EINPROGRESS else { throw RelayError.socket(errorMessage("connect")) }
            var pollDescriptor = pollfd(fd: socket, events: Int16(POLLOUT), revents: 0)
            guard poll(&pollDescriptor, 1, Int32(timeoutSeconds * 1000)) > 0 else {
                throw RelayError.socket("connect timed out")
            }
            var socketError: Int32 = 0
            var length = socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(socket, SOL_SOCKET, SO_ERROR, &socketError, &length) == 0, socketError == 0 else {
                throw RelayError.socket(errorMessage("connect"))
            }
        }
        _ = fcntl(socket, F_SETFL, flags)
        return socket
    } catch {
        Darwin.close(socket)
        throw error
    }
}

func connectThroughSOCKS(_ socket: Int32, host: String, port: UInt16, ipv4: UInt32? = nil) throws {
    let hostBytes = Array(host.utf8)
    guard hostBytes.count <= 255 else { throw RelayError.socks("SOCKS target hostname is too long") }

    try writeAll(socket, bytes: [5, 1, 0])
    guard try readExact(socket, count: 2) == [5, 0] else {
        throw RelayError.socks("SOCKS server rejected no-authentication mode")
    }

    var request: [UInt8]
    if let ipv4 {
        request = [5, 1, 0, 1, UInt8(ipv4 >> 24 & 0xff), UInt8(ipv4 >> 16 & 0xff), UInt8(ipv4 >> 8 & 0xff), UInt8(ipv4 & 0xff)]
    } else {
        request = [5, 1, 0, 3, UInt8(hostBytes.count)]
        request.append(contentsOf: hostBytes)
    }
    request.append(UInt8(port >> 8))
    request.append(UInt8(port & 0xff))
    try writeAll(socket, bytes: request)

    let response = try readExact(socket, count: 4)
    guard response[0] == 5, response[1] == 0 else {
        throw RelayError.socks("SOCKS CONNECT failed with status \(response[1])")
    }
    switch response[3] {
    case 1: _ = try readExact(socket, count: 4)
    case 3: _ = try readExact(socket, count: Int(try readExact(socket, count: 1)[0]))
    case 4: _ = try readExact(socket, count: 16)
    default: throw RelayError.socks("SOCKS server returned an unknown address type")
    }
    _ = try readExact(socket, count: 2)
}

func copyStream(from source: Int32, to destination: Int32) {
    var buffer = [UInt8](repeating: 0, count: 32 * 1024)
    while true {
        let received = buffer.withUnsafeMutableBytes {
            Darwin.recv(source, $0.baseAddress, $0.count, 0)
        }
        if received == 0 { break }
        if received < 0 {
            if errno == EINTR { continue }
            break
        }
        do { try writeAll(destination, bytes: Array(buffer[0..<received])) } catch { break }
    }
    Darwin.shutdown(destination, SHUT_WR)
}

// MARK: - Proxy path
//
// The SOCKS request MUST carry the resolved real IP, never the target
// hostname: /etc/hosts maps the hostname to 127.0.0.1 (that is how we
// intercept Typeless), so a hostname-based SOCKS request makes the proxy
// resolve it to the relay itself and loop back forever.

func connectViaProxy(_ configuration: Configuration, ipv4: UInt32) throws -> Int32 {
    let upstream = try openTCP(host: configuration.socksHost, port: configuration.socksPort, listener: false)
    do {
        setSocketTimeout(upstream, seconds: 2)
        try connectThroughSOCKS(
            upstream,
            host: configuration.targetHost,
            port: configuration.targetPort,
            ipv4: ipv4
        )
        setSocketTimeout(upstream, seconds: 0)
        return upstream
    } catch {
        Darwin.close(upstream)
        throw error
    }
}

func connectDirect(_ configuration: Configuration, ipv4: UInt32) throws -> Int32 {
    try connectTCP(host: dottedIPv4(ipv4), port: configuration.targetPort, timeoutSeconds: 2)
}

// MARK: - TLS probe split
//
// The probe is the leading TLS handshake records (ClientHello and friends).
// Those bytes are safe to duplicate across both race paths: they carry no user
// data. Everything from the first non-handshake record on is never read here —
// it stays in the kernel buffer and is delivered to the race winner only, which
// makes exactly-once delivery of user data trivial to guarantee.

func peekByteAvailable(_ socket: Int32) -> UInt8? {
    var byte: UInt8 = 0
    let received = Darwin.recv(socket, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
    return received == 1 ? byte : nil
}

func readTLSRecord(_ socket: Int32) throws -> [UInt8] {
    let header = try readExact(socket, count: 5)
    let length = Int(header[3]) << 8 | Int(header[4])
    return header + (try readExact(socket, count: length))
}

func peekByteBlocking(_ socket: Int32) -> UInt8? {
    var byte: UInt8 = 0
    return Darwin.recv(socket, &byte, 1, MSG_PEEK) == 1 ? byte : nil
}

func readTLSProbe(_ socket: Int32) -> [UInt8]? {
    setSocketTimeout(socket, seconds: 2)
    defer { setSocketTimeout(socket, seconds: 0) }
    guard let first = peekByteAvailable(socket) ?? peekByteBlocking(socket),
          first == 0x16 || first == 0x14 else {
        return nil
    }
    var probe: [UInt8] = []
    while probe.count < 64 * 1024 {
        guard let type = peekByteAvailable(socket), type == 0x16 || type == 0x14 else { break }
        guard let record = try? readTLSRecord(socket) else { break }
        probe.append(contentsOf: record)
    }
    return probe.isEmpty ? nil : probe
}

// MARK: - Dual-path race
//
// Both paths receive the probe and race to return the first response byte.
// TCP connect success is NOT a win signal: a zombie path (dead proxy node after
// system sleep) completes CONNECT but black-holes all data. The first response
// byte is proof that bytes actually round-trip.
//
// Exactly-once invariant: user data is never written to a path before it wins,
// and after a win the losing path is closed. There is no retry after data flows.

final class RaceState {
    private let lock = NSLock()
    private let client: Int32
    private let pathCount: Int
    private var decided = false
    private var failures = 0

    init(client: Int32, pathCount: Int) {
        self.client = client
        self.pathCount = pathCount
    }

    func tryWin() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if decided { return false }
        decided = true
        return true
    }

    func reportFailure(name: String, reason: String) {
        lock.lock()
        defer { lock.unlock() }
        failures += 1
        FileHandle.standardError.write(Data("race: \(name) lost (\(reason))\n".utf8))
        if !decided, failures == pathCount {
            decided = true
            drainAndClose(client)
            FileHandle.standardError.write(Data("race: all paths failed, closing client\n".utf8))
        }
    }
}

func pump(client: Int32, upstream: Int32) {
    let group = DispatchGroup()
    group.enter()
    DispatchQueue.global().async { copyStream(from: client, to: upstream); group.leave() }
    group.enter()
    DispatchQueue.global().async { copyStream(from: upstream, to: client); group.leave() }
    group.notify(queue: .global()) { Darwin.close(client); Darwin.close(upstream) }
}

func racePath(
    name: String,
    client: Int32,
    probe: [UInt8],
    deadline: Date,
    state: RaceState,
    connect: () throws -> Int32
) {
    var upstream: Int32 = -1
    do {
        upstream = try connect()
        try writeAll(upstream, bytes: probe)
        setSocketTimeout(upstream, seconds: max(0.1, deadline.timeIntervalSinceNow))
        var first = [UInt8](repeating: 0, count: 16 * 1024)
        let received = first.withUnsafeMutableBytes { Darwin.recv(upstream, $0.baseAddress, $0.count, 0) }
        guard received > 0 else {
            Darwin.close(upstream)
            state.reportFailure(name: name, reason: "no response before deadline")
            return
        }
        guard state.tryWin() else {
            Darwin.close(upstream)
            return
        }
        FileHandle.standardError.write(Data("race: \(name) won\n".utf8))
        do {
            try writeAll(client, bytes: Array(first[0..<received]))
            pump(client: client, upstream: upstream)
            upstream = -1
        } catch {
            Darwin.close(upstream)
            Darwin.close(client)
        }
    } catch {
        if upstream >= 0 { Darwin.close(upstream) }
        state.reportFailure(name: name, reason: "\(error)")
    }
}

// Closing a socket with unread data in the receive queue sends a TCP RST,
// which surfaces as "connection reset" on the client. Drain first so refusal
// is a clean FIN.
func drainAndClose(_ socket: Int32) {
    setSocketTimeout(socket, seconds: 0.2)
    var buffer = [UInt8](repeating: 0, count: 4096)
    while buffer.withUnsafeMutableBytes({ Darwin.recv(socket, $0.baseAddress, $0.count, 0) }) > 0 {}
    Darwin.close(socket)
}

func handleClient(_ client: Int32, configuration: Configuration) {
    guard let probe = readTLSProbe(client) else {
        drainAndClose(client)
        FileHandle.standardError.write(Data("connection refused: not a TLS handshake\n".utf8))
        return
    }
    let directIPv4 = configuration.directIPv4.flatMap { UInt32(bigEndianAddress: $0) } ?? resolvedIPv4(host: configuration.targetHost)
    guard let directIPv4 else {
        drainAndClose(client)
        FileHandle.standardError.write(Data("connection refused: DNS resolution failed\n".utf8))
        return
    }
    if dottedIPv4(directIPv4) == configuration.listenHost, configuration.targetPort == configuration.listenPort {
        drainAndClose(client)
        FileHandle.standardError.write(Data("connection refused: target would connect to the relay itself\n".utf8))
        return
    }

    let state = RaceState(client: client, pathCount: 2)
    let deadline = Date().addingTimeInterval(2.5)
    let probeCopy = probe
    DispatchQueue.global().async {
        racePath(name: "proxy", client: client, probe: probeCopy, deadline: deadline, state: state) {
            try connectViaProxy(configuration, ipv4: directIPv4)
        }
    }
    DispatchQueue.global().async {
        racePath(name: "direct", client: client, probe: probeCopy, deadline: deadline, state: state) {
            try connectDirect(configuration, ipv4: directIPv4)
        }
    }
}

extension UInt32 {
    init?(bigEndianAddress dotted: String) {
        var address = in_addr()
        guard inet_pton(AF_INET, dotted, &address) == 1 else { return nil }
        self = UInt32(bigEndian: address.s_addr)
    }
}

do {
    signal(SIGPIPE, SIG_IGN)
    let configuration = try Configuration.parse(CommandLine.arguments)
    let listener = try openTCP(host: configuration.listenHost, port: configuration.listenPort, listener: true)
    while true {
        let client = Darwin.accept(listener, nil, nil)
        if client < 0 {
            if errno == EINTR { continue }
            throw RelayError.socket(errorMessage("accept"))
        }
        configureSocket(client)
        DispatchQueue.global().async { handleClient(client, configuration: configuration) }
    }
} catch {
    FileHandle.standardError.write(Data("fatal: \(error)\n".utf8))
    exit(1)
}
