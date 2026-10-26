require "./spec_helper"

# Каждый спек — реальный TLS-хендшейк с локальным оракулом
# (python3 http.server + ssl, самоподписанный сертификат из spec_helper).

describe Openssl::HTTPS do
  it "GET /hello с CA оракула → 200 + тело-маркер" do
    Oracle.get("/hello").should eq Oracle::MARKER
  end

  it "неверный CA-файл → ошибка хендшейка (сертификат не прошёл проверку)" do
    expect_raises(Openssl::Error, /tls_handshake|ca_file/) do
      Openssl::HTTPS.get("127.0.0.1", "/hello", port: Oracle.port,
                         ca_file: Oracle.wrong_cert, timeout_s: 5)
    end
  end

  it "без CA (verify off) → успех (фолбэк для DPI-подменённых цепочек)" do
    Openssl::HTTPS.get("127.0.0.1", "/hello", port: Oracle.port,
                       timeout_s: 5).should eq Oracle::MARKER
  end

  it "chunked-ответ → тело уже декодировано (dechunk в шиме)" do
    body = Oracle.get("/chunked")
    body.should eq "hello chunked world"
    body.should_not contain("\r")
  end

  it "404 → raise HTTP 404" do
    expect_raises(Openssl::Error, /HTTP 404/) { Oracle.get("/notfound") }
  end

  it "большой ответ (~1 МБ) → без обрезки" do
    body = Oracle.get("/big")
    body.bytesize.should eq 1024 * 1024
    body.should eq "x" * 1023 + "\n" + ("x" * 1023 + "\n") * 1023
  end

  it "несуществующий хост → ERROR: dns" do
    expect_raises(Openssl::Error, /ERROR: dns:/) do
      Openssl::HTTPS.get("nonexistent.perevodilka.invalid", "/",
                         timeout_s: 5)
    end
  end

  it "oversized path → громкая ошибка, не молчаливое обрезание" do
    huge = "/get?q=" + "a" * 12_000
    expect_raises(Openssl::Error, /request too long/) do
      Openssl::HTTPS.get("127.0.0.1", huge, port: Oracle.port,
                         timeout_s: 5)
    end
  end

  it "таймаут: сервер молчит дольше timeout_s → ошибка, не зависание" do
    t0 = Time.instant
    expect_raises(Openssl::Error, /read|timeout/i) do
      Oracle.get("/hang", timeout_s: 1)
    end
    (Time.instant - t0).total_seconds.should be < 10
  end
end
