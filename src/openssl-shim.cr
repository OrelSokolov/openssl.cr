# Openssl — blocking HTTPS GET through the OpenSSL C API (ext/https_shim.c).
#
# Made for raw threads without a Crystal scheduler — on Android (egui/sokol
# apps) every Crystal socket call from such a thread dies with
# NilAssertionError "Thread#scheduler cannot be nil". One call does the
# whole exchange: DNS → TCP → TLS → GET → read-to-EOF, all blocking
# syscalls, no event loop.
#
# Native code loading is platform-split:
#   * desktop — ext/libhttps_shim.so is dlopen'd at runtime (compiled by
#     ext/build.sh; on first use the shard compiles it itself if missing —
#     path dependencies don't run the shard's postinstall). No link-time
#     dependency on libssl for consumers, no --link-flags needed.
#   * Android — the app's android build compiles ext/https_shim.c with the
#     NDK against the static openssl and links it into the same .so as
#     this code, so the extern symbols resolve directly.
#
# The namespace is `Openssl`, not `OpenSSL`, to never collide with the
# Crystal stdlib OpenSSL module.

module Openssl
  class Error < Exception
  end

  module HTTPS
    # ------------------------------------------------------------ native

    {% if flag?(:android) %}
      # The shim .o is linked into the same image as this code (see the
      # app's android build) — plain extern symbols, no dlopen.
      lib LibHttpsShim
        fun get = slush_https_get(host : UInt8*, port : Int32, path : UInt8*,
                                  ca_file : UInt8*, ca_dir : UInt8*,
                                  timeout_s : Int32) : UInt8*
        fun free_resp = slush_https_free(resp : UInt8*)
      end

      private def self.raw_get(host : String, port : Int32, path : String,
                               ca_file : String?, ca_dir : String?,
                               timeout_s : Int32) : String
        ptr = LibHttpsShim.get(host.to_unsafe, port, path.to_unsafe,
                               (ca_file || "").to_unsafe,
                               (ca_dir || "").to_unsafe, timeout_s)
        raise Error.new("https_shim: нет памяти") if ptr.null?
        raw = String.new(ptr)
        LibHttpsShim.free_resp(ptr)
        raw
      end
    {% else %}
      @[Link("dl")]
      lib LibDL
        RTLD_NOW    = 2
        RTLD_DEFAULT = Pointer(Void).new(0) # search the global scope

        fun dlopen = dlopen(filename : UInt8*, flag : Int32) : Void*
        fun dlsym = dlsym(handle : Void*, symbol : UInt8*) : Void*
        fun dlerror = dlerror : UInt8*
      end

      alias GetFn  = (UInt8*, Int32, UInt8*, UInt8*, UInt8*, Int32 -> UInt8*)
      alias FreeFn = (UInt8* -> Nil)

      @@mutex    = Thread::Mutex.new
      @@get_fn   : GetFn?  = nil
      @@free_fn  : FreeFn? = nil

      private def self.shim_so : String
        env = ENV["OPENSSL_SHIM_SO"]?
        return env if env && File.exists?(env)
        so = File.expand_path("#{__DIR__}/../ext/libhttps_shim.so")
        build_shim(so) unless File.exists?(so)
        so
      end

      # Path dependencies don't run the shard's postinstall — compile the
      # shim on first use if the .so wasn't built yet.
      private def self.build_shim(so : String) : Nil
        outp = IO::Memory.new
        status = Process.run("bash",
          [File.expand_path("#{__DIR__}/../ext/build.sh")],
          output: outp, error: outp)
        unless status.success? && File.exists?(so)
          raise Error.new("https_shim build failed: #{outp.to_s[0, 500]}")
        end
      end

      private def self.load_fns : {GetFn, FreeFn}
        # Statically linked? The symbols are already in this binary's
        # global scope — no dlopen needed.
        get_ptr = LibDL.dlsym(LibDL::RTLD_DEFAULT, "slush_https_get")
        free_ptr = LibDL.dlsym(LibDL::RTLD_DEFAULT, "slush_https_free")
        if get_ptr && free_ptr
          return {GetFn.new(get_ptr, Pointer(Void).null),
                   FreeFn.new(free_ptr, Pointer(Void).null)}
        end

        path = shim_so
        handle = LibDL.dlopen(path.to_unsafe, LibDL::RTLD_NOW)
        unless handle
          detail = LibDL.dlerror
          raise Error.new("dlopen(#{path}): #{detail ? String.new(detail) : "failed"}")
        end
        get_ptr = LibDL.dlsym(handle, "slush_https_get")
        free_ptr = LibDL.dlsym(handle, "slush_https_free")
        unless get_ptr && free_ptr
          raise Error.new("dlsym: slush_https_get/slush_https_free not found in #{path}")
        end
        {GetFn.new(get_ptr, Pointer(Void).null),
         FreeFn.new(free_ptr, Pointer(Void).null)}
      end

      private def self.raw_get(host : String, port : Int32, path : String,
                               ca_file : String?, ca_dir : String?,
                               timeout_s : Int32) : String
        get_fn, free_fn = @@mutex.synchronize do
          pair = {@@get_fn, @@free_fn}
          unless pair[0] && pair[1]
            g, f = load_fns
            @@get_fn, @@free_fn = g, f
            pair = {g, f}
          end
          pair
        end
        ptr = get_fn.not_nil!.call(host.to_unsafe, port, path.to_unsafe,
                                   (ca_file || "").to_unsafe,
                                   (ca_dir || "").to_unsafe, timeout_s)
        raise Error.new("https_shim: нет памяти") if ptr.null?
        raw = String.new(ptr)
        free_fn.not_nil!.call(ptr)
        raw
      end
    {% end %}

    # ------------------------------------------------------------ public

    # Blocking HTTPS GET → response body (chunked bodies are decoded by
    # the shim). Verification is enabled when ca_file (a PEM bundle) or
    # ca_dir (an OpenSSL hashed-CA dir) is given; both empty disables it
    # (the fallback for DPI-substituted chains). The hostname is checked
    # via SSL_set1_host.
    #
    # Raises Openssl::Error:
    #   * shim failures keep their informative prefixes — "dns:",
    #     "tls_handshake:", "ca_file:", "read:", "write:" …;
    #   * non-2xx answers raise "HTTP <code>: <status line>".
    def self.get(host : String, path : String, port : Int32 = 443,
                 ca_file : String? = nil, ca_dir : String? = nil,
                 timeout_s : Int32 = 15) : String
      raw = raw_get(host, port, path, ca_file, ca_dir, timeout_s)
      if raw.starts_with?("ERROR: ")
        raise Error.new(raw)
      end
      status = raw.split("\r\n").first? || "(пусто)"
      code = status.split(' ')[1]? || "0"
      unless (200..299).includes?(code.to_i? || 0)
        raise Error.new("HTTP #{code}: #{status[0, 80]}")
      end
      body_at = raw.index("\r\n\r\n")
      body_at ? raw[(body_at + 4)..] : raw
    end
  end
end
