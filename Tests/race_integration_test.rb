#!/usr/bin/env ruby

require "socket"
require "timeout"

ROOT = File.expand_path("..", __dir__)
BINARY = File.join(ROOT, ".build", "release", "typeless-proxy-relay")
TARGET_HOST = "api.typeless.com"

abort("relay binary missing: #{BINARY}") unless File.executable?(BINARY)

def read_exact(socket, length)
  data = +""
  data << socket.readpartial(length - data.bytesize) while data.bytesize < length
  data
end

def tls_record(type, payload)
  [type, 0x0301, payload.bytesize].pack("C n n") + payload
end

PROBE = tls_record(0x16, "CLIENT-HELLO-PROBE")
USER  = tls_record(0x17, "USER-DATA-PAYLOAD!")

# Fake backend: TLS-agnostic TCP server that records every byte it receives.
# mode :echo    - echoes bytes back (healthy path)
# mode :silent  - accepts and records but never responds (zombie / black hole)
class Backend
  attr_reader :target_host, :target_port

  def initialize(port:, mode:, socks: false)
    @mode = mode
    @socks = socks
    @received = +""
    @mutex = Mutex.new
    @server = TCPServer.new("127.0.0.1", port)
    @thread = Thread.new { serve }
  end

  def received_bytes
    @mutex.synchronize { @received.dup }
  end

  def close
    @server.close
    @thread.join(1)
  end

  private

  def serve
    socket = @server.accept
    if @socks
      greeting = read_exact(socket, 3).bytes
      raise "unexpected SOCKS greeting: #{greeting.inspect}" unless greeting == [5, 1, 0]
      socket.write([5, 0].pack("C*"))
      header = read_exact(socket, 4).bytes
      raise "unexpected SOCKS request header: #{header.inspect}" unless header[0, 3] == [5, 1, 0]
      @target_host = case header[3]
                     when 1 then read_exact(socket, 4).bytes.join(".")
                     when 3 then read_exact(socket, read_exact(socket, 1).unpack1("C"))
                     else raise "unexpected ATYP: #{header[3]}"
                     end
      @target_port = read_exact(socket, 2).unpack1("n")
      socket.write([5, 0, 0, 1, 127, 0, 0, 1, 0, 0].pack("C*"))
    end
    loop do
      chunk = socket.readpartial(16 * 1024)
      @mutex.synchronize { @received << chunk }
      socket.write(chunk) if @mode == :echo
    end
  rescue EOFError, Errno::ECONNRESET, IOError
    nil
  ensure
    socket&.close
  end
end

def with_relay(listen_port:, socks_port:, direct_port:, direct_ipv4: "127.0.0.1")
  pid = Process.spawn(
    BINARY,
    "--listen-host", "127.0.0.1",
    "--listen-port", listen_port.to_s,
    "--socks-host", "127.0.0.1",
    "--socks-port", socks_port.to_s,
    "--target-host", TARGET_HOST,
    "--target-port", direct_port.to_s,
    "--direct-ipv4", direct_ipv4,
    out: File::NULL,
    err: File::NULL
  )
  client = nil
  Timeout.timeout(5) do
    loop do
      begin
        client = TCPSocket.new("127.0.0.1", listen_port)
        break
      rescue Errno::ECONNREFUSED
        raise "relay exited before listening" unless Process.waitpid(pid, Process::WNOHANG).nil?
        sleep 0.05
      end
    end
  end
  yield client
ensure
  client&.close
  Process.kill("TERM", pid) rescue nil
  Process.wait(pid) rescue nil
end

# T1: proxy path is a zombie (SOCKS handshake succeeds, then black holes all
# data), direct path is healthy. User data must flow through direct exactly
# once; the zombie must see the probe only. This is the real 2026-09-28 outage.
def scenario_t1_zombie_proxy_falls_back_to_direct
  socks = Backend.new(port: 21_090, mode: :silent, socks: true)
  direct = Backend.new(port: 21_444, mode: :echo)
  with_relay(listen_port: 21_443, socks_port: 21_090, direct_port: 21_444) do |client|
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    client.write(PROBE + USER)
    echoed = Timeout.timeout(4) { read_exact(client, (PROBE + USER).bytesize) }
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

    raise "unexpected echo: #{echoed.inspect}" unless echoed == PROBE + USER
    raise "relay too slow: #{elapsed.round(2)}s (zombie path must not delay the winner)" unless elapsed < 2.0

    sleep 0.3
    zombie = socks.received_bytes
    raise "zombie must receive probe only, got: #{zombie.inspect}" unless zombie == PROBE
    healthy = direct.received_bytes
    raise "direct must receive probe+user, got: #{healthy.inspect}" unless healthy == PROBE + USER
  end
  socks.close
  direct.close
  puts "PASS: T1 zombie proxy falls back to direct; user data sent exactly once"
end

# T2: direct path refuses connection, proxy path is healthy. Proxy wins and
# carries all user data; the refused path never sees anything.
def scenario_t2_refused_direct_falls_back_to_proxy
  socks = Backend.new(port: 22_090, mode: :echo, socks: true)
  with_relay(listen_port: 22_443, socks_port: 22_090, direct_port: 22_444) do |client|
    client.write(PROBE + USER)
    echoed = Timeout.timeout(4) { read_exact(client, (PROBE + USER).bytesize) }
    raise "unexpected echo: #{echoed.inspect}" unless echoed == PROBE + USER
    sleep 0.3
    raise "proxy must receive probe+user" unless socks.received_bytes == PROBE + USER
    # Loop regression (2026-09-29 outage): the SOCKS request must carry the
    # resolved IP. A hostname request makes the proxy resolve it via /etc/hosts
    # to 127.0.0.1, i.e. back into the relay — an infinite connection loop.
    raise "SOCKS must get resolved IP, got hostname #{socks.target_host.inspect} (would loop via /etc/hosts)" unless socks.target_host == "127.0.0.1"
  end
  socks.close
  puts "PASS: T2 refused direct path loses to healthy proxy; SOCKS gets resolved IP"
end

# T3: both paths are zombies. The relay must close the client promptly (within
# the race deadline) instead of hanging until Typeless's own 6-7s timeout.
def scenario_t3_both_dead_fails_fast
  socks = Backend.new(port: 23_090, mode: :silent, socks: true)
  direct = Backend.new(port: 23_444, mode: :silent)
  with_relay(listen_port: 23_443, socks_port: 23_090, direct_port: 23_444) do |client|
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    client.write(PROBE)
    data = Timeout.timeout(5) { client.read }
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    raise "client should get no data, got: #{data.inspect}" unless data == ""
    raise "relay must fail fast, took #{elapsed.round(2)}s" unless elapsed < 3.5
  end
  socks.close
  direct.close
  puts "PASS: T3 both dead paths fail fast, client closed within race deadline"
end

# T4: both paths healthy. Exactly one carries user data; the loser must see the
# probe (permitted duplication) and nothing else.
def scenario_t4_both_healthy_exactly_once
  socks = Backend.new(port: 24_090, mode: :echo, socks: true)
  direct = Backend.new(port: 24_444, mode: :echo)
  with_relay(listen_port: 24_443, socks_port: 24_090, direct_port: 24_444) do |client|
    client.write(PROBE + USER)
    echoed = Timeout.timeout(4) { read_exact(client, (PROBE + USER).bytesize) }
    raise "unexpected echo: #{echoed.inspect}" unless echoed == PROBE + USER
    sleep 0.3
    got = [socks.received_bytes, direct.received_bytes]
    winners = got.select { |b| b == PROBE + USER }
    losers  = got.select { |b| b == PROBE }
    raise "expected exactly one full path and one probe-only path, got: #{got.inspect}" \
      unless winners.size == 1 && losers.size == 1
  end
  socks.close
  direct.close
  puts "PASS: T4 both healthy: user data on exactly one path, loser sees probe only"
end

# T5: non-TLS traffic is refused outright (design decision: no fallback path).
# The client connection is closed and no backend sees a single byte.
def scenario_t5_non_tls_refused
  socks = Backend.new(port: 25_090, mode: :echo, socks: true)
  direct = Backend.new(port: 25_444, mode: :echo)
  with_relay(listen_port: 25_443, socks_port: 25_090, direct_port: 25_444) do |client|
    client.write("GET / HTTP/1.1\r\n")
    data = Timeout.timeout(4) { client.read }
    raise "client should get no data, got: #{data.inspect}" unless data == ""
    sleep 0.3
    raise "proxy must see nothing" unless socks.received_bytes == ""
    raise "direct must see nothing" unless direct.received_bytes == ""
  end
  socks.close
  direct.close
  puts "PASS: T5 non-TLS traffic refused; no backend sees any byte"
end

# T6: TLS 1.3 0-RTT style traffic — probe (0x16) followed by application data
# (0x17). The 0x17 record and everything after must reach the winner only.
def scenario_t6_early_data_winner_only
  socks = Backend.new(port: 26_090, mode: :echo, socks: true)
  direct = Backend.new(port: 26_444, mode: :echo)
  with_relay(listen_port: 26_443, socks_port: 26_090, direct_port: 26_444) do |client|
    client.write(PROBE + USER)
    echoed = Timeout.timeout(4) { read_exact(client, (PROBE + USER).bytesize) }
    raise "unexpected echo: #{echoed.inspect}" unless echoed == PROBE + USER
    sleep 0.3
    got = [socks.received_bytes, direct.received_bytes]
    raise "early data leaked to loser: #{got.inspect}" unless got.include?(PROBE + USER) && got.include?(PROBE)
  end
  socks.close
  direct.close
  puts "PASS: T6 early data (0x17) reaches winner only"
end

scenario_t1_zombie_proxy_falls_back_to_direct
scenario_t2_refused_direct_falls_back_to_proxy
scenario_t3_both_dead_fails_fast
scenario_t4_both_healthy_exactly_once
scenario_t5_non_tls_refused
scenario_t6_early_data_winner_only
