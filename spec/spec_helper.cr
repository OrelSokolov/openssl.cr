# spec_helper — реальный TLS-оракул на 127.0.0.1 (python3 stdlib) +
# самоподписанный сертификат, генерируемый на лету.

# ВАЖНО: этот at_exit регистрируется ДО require "spec": примеры гоняются
# в at_exit-обработчике самого spec-фреймворка, а обработчики выполняются
# LIFO — иначе Oracle.stop убьёт сервер до запуска примеров.
at_exit { Oracle.stop }

require "spec"
require "process"
require "socket"
require "../src/openssl-shim"

module Oracle
  MARKER = "hello-oracle-body"

  class_property port : Int32 = 0
  class_property cert : String = ""
  class_property wrong_cert : String = ""

  @@server : Process? = nil
  @@server_err = IO::Memory.new

  def self.start : Nil
    tmp = File.join(__DIR__, "tmp")
    Dir.mkdir_p(tmp)
    cert = File.join(tmp, "oracle-cert.pem")
    key = File.join(tmp, "oracle-key.pem")
    wrong_cert = File.join(tmp, "wrong-ca.pem")
    wrong_key = File.join(tmp, "wrong-key.pem")

    # SAN IP:127.0.0.1 нужен для SSL_set1_host (hostname check шима).
    gen_cert(cert, key)
    gen_cert(wrong_cert, wrong_key) # чужой CA — для негативного теста

    @@port = free_port
    @@server = Process.new("python3",
      [File.join(__DIR__, "oracle_server.py"),
       port.to_s, cert, key],
      error: @@server_err)
    wait_port(port)
    @@cert = cert
    @@wrong_cert = wrong_cert
  end

  def self.stop : Nil
    @@server.try &.terminate
    @@server.try &.wait
  end

  # GET через шард против оракула (по умолчанию — с верификацией).
  def self.get(path : String, timeout_s : Int32 = 15) : String
    Openssl::HTTPS.get("127.0.0.1", path, port: port,
                       ca_file: cert, timeout_s: timeout_s)
  end

  private def self.gen_cert(cert : String, key : String) : Nil
    ok = Process.run("openssl", ["req", "-x509", "-newkey", "rsa:2048",
                                 "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1",
                                 "-addext", "subjectAltName=IP:127.0.0.1",
                                 "-keyout", key, "-out", cert]).success?
    raise "openssl req failed (генерация сертификата оракула)" unless ok
  end

  private def self.free_port : Int32
    server = TCPServer.new("127.0.0.1", 0)
    port = server.local_address.port
    server.close
    port
  end

  private def self.wait_port(port : Int32) : Nil
    50.times do
      begin
        sock = TCPSocket.new("127.0.0.1", port, connect_timeout: 0.2)
        sock.close
        return
      rescue IO::Error | Socket::Error
        sleep 0.1.seconds
      end
    end
    raise "оракул не поднялся на порту #{port}: #{@@server_err.to_s[0, 400]}"
  end
end

Oracle.start
