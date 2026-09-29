#!/usr/bin/env ruby

require "socket"
require "timeout"

ROOT = File.expand_path("..", __dir__)
BINARY = File.join(ROOT, ".build", "release", "typeless-proxy-relay")
LISTEN_PORT = 18_443
SOCKS_PORT = 19_090
TARGET_HOST = "api.typeless.com"
TARGET_PORT = 18_444

abort("relay binary missing: #{BINARY}") unless File.executable?(BINARY)

def read_exact(socket, length)
  data = +""
  data << socket.readpartial(length - data.bytesize) while data.bytesize < length
  data
end

observed_target = Queue.new
socks_server = TCPServer.new("127.0.0.1", SOCKS_PORT)
socks_thread = Thread.new do
  socket = socks_server.accept
  greeting = read_exact(socket, 3).bytes
  raise "unexpected SOCKS greeting: #{greeting.inspect}" unless greeting == [5, 1, 0]
  socket.write([5, 0].pack("C*"))

  header = read_exact(socket, 4).bytes
  raise "unexpected SOCKS request header: #{header.inspect}" unless header == [5, 1, 0, 1]
  host = read_exact(socket, 4).bytes.join(".")
  port = read_exact(socket, 2).unpack1("n")
  observed_target << [host, port]

  socket.write([5, 0, 0, 1, 127, 0, 0, 1, 0, 0].pack("C*"))
  loop do
    payload = socket.readpartial(16 * 1024)
    socket.write(payload)
  end
rescue EOFError
  nil
ensure
  socket&.close
end

relay_pid = Process.spawn(
  BINARY,
  "--listen-host", "127.0.0.1",
  "--listen-port", LISTEN_PORT.to_s,
  "--socks-host", "127.0.0.1",
  "--socks-port", SOCKS_PORT.to_s,
  "--target-host", TARGET_HOST,
  "--target-port", TARGET_PORT.to_s,
  "--direct-ipv4", "127.0.0.1",
  out: File::NULL,
  err: File::NULL
)

begin
  client = nil
  Timeout.timeout(5) do
    loop do
      begin
        client = TCPSocket.new("127.0.0.1", LISTEN_PORT)
        break
      rescue Errno::ECONNREFUSED
        raise "relay exited before listening" unless Process.waitpid(relay_pid, Process::WNOHANG).nil?
        sleep 0.05
      end
    end
  end

  # relay only speaks to TLS handshakes; wrap the payload as a handshake record
  payload = [0x16, 0x0301, "typeless-relay-test".bytesize].pack("C n n") + "typeless-relay-test"
  client.write(payload)
  echoed = read_exact(client, payload.bytesize)
  raise "unexpected relay payload: #{echoed.inspect}" unless echoed == payload

  target = Timeout.timeout(2) { observed_target.pop }
  raise "unexpected target: #{target.inspect}" unless target == ["127.0.0.1", TARGET_PORT]

  puts "PASS: SOCKS5 domain target and bidirectional relay"
ensure
  client&.close
  Process.kill("TERM", relay_pid) rescue nil
  Process.wait(relay_pid) rescue nil
  socks_server.close
  socks_thread.join(1)
end
