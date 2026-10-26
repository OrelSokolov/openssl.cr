# openssl shard tasks.
#
#   rake spec      # локальный TLS-оракул (python3) — основные тесты
#   rake test:net  # реальный интернет (MyMemory) — дежурная проверка
#   rake build     # ext/libhttps_shim.so (для crystal run примеров)

EXT = File.expand_path("ext", __dir__)
SO  = File.join(EXT, "libhttps_shim.so")
NET = File.join(EXT, "test_https_shim")

file SO => [File.join(EXT, "https_shim.c"), File.join(EXT, "build.sh")] do
  sh "bash #{File.join(EXT, "build.sh")}"
end

desc "Build ext/libhttps_shim.so (desktop, dlopen target)"
task build: [SO]

file NET => [File.join(EXT, "test_https_shim.c"),
             File.join(EXT, "https_shim.c")] do
  sh "cc -O2 -o #{NET} #{EXT}/test_https_shim.c #{EXT}/https_shim.c -lssl -lcrypto"
end

desc "Run the shim tests against the real network (MyMemory)"
task "test:net" => [NET] do
  sh NET
end

desc "Run the local TLS-oracle specs (python3 oracle, no network)"
task :spec do
  sh "crystal spec"
end

task default: :spec
