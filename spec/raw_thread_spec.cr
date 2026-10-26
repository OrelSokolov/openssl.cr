# Главная спека шарда: НАСТОЯЩИЙ stdlib HTTP::Client + OpenSSL из
# НАСТОЯЩЕГО raw-потока (pthread без Crystal-планировщика) — то, ради
# чего шард существует. Плюс обычные (main-thread) проверки клиента.

require "./spec_helper"

# Канал результатов из raw-треда: пишем в буферы до join, статус —
# обычным Int32 (join даёт happens-before, Atomic тут не нужен и,
# будучи структурой, мутировал бы копию через class_property).
# Job кладётся в class-переменную: C-колбэк должен быть non-capturing
# proc'ом.
class RawResult
  class_property job : (->)? = nil
  class_property body : String = ""
  class_property err : String = ""
  class_property status : Int32 = 0 # 0 ran, 1 ok, 2 failed
end

# Сырой pthread: никакого Crystal Thread TLS, никакого планировщика —
# ровно то окружение, что даёт egui/sokol (C-тред, дёргающий колбэк).
private def run_in_raw_thread(&block : -> ) : Nil
  RawResult.status = 0
  RawResult.job = block
  proc = ->(arg : Void*) {
    begin
      RawResult.job.try &.call
      RawResult.status = 1
    rescue ex
      RawResult.err = ex.message.to_s
      RawResult.status = 2
    end
    Pointer(Void).null
  }
  tid = uninitialized LibC::PthreadT
  ret = LibC.pthread_create(pointerof(tid), Pointer(LibC::PthreadAttrT).null,
    proc, Pointer(Void).null)
  raise "pthread_create failed: #{ret}" unless ret == 0
  retval = Pointer(Void).null
  LibC.pthread_join(tid, pointerof(retval))
end

describe "openssl-static" do
  it "HTTP::Client + TLS verification from a RAW pthread" do
    run_in_raw_thread do
      RawResult.body = Oracle.get("/hello")
    end
    RawResult.status.should eq(1), RawResult.err
    RawResult.body.should eq(Oracle::MARKER)
  end

  it "non-2xx raises the stdlib way from a raw thread" do
    code = 0
    run_in_raw_thread do
      begin
        Oracle.get("/notfound")
      rescue ex : Exception
        code = ex.message.to_s.starts_with?("HTTP 404") ? 404 : -1
      end
    end
    RawResult.status.should eq(1), RawResult.err
    code.should eq(404)
  end

  it "certificate verification failure raises from a raw thread" do
    failed = false
    run_in_raw_thread do
      begin
        ctx = OpenSSL::SSL::Context::Client.new
        ctx.ca_certificates = Oracle.wrong_cert
        client = HTTP::Client.new("127.0.0.1", Oracle.port, ctx)
        client.get("/hello")
      rescue ex : OpenSSL::Error | IO::Error
        failed = true
      end
    end
    RawResult.status.should eq(1), RawResult.err
    failed.should be_true
  end

  it "the main thread keeps its own scheduler loop" do
    Fiber::ExecutionContext.current?.should_not be_nil
    Oracle.get("/hello").should eq(Oracle::MARKER)
  end
end
