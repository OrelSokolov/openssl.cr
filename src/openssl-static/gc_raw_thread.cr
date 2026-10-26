# Boehm GC must know every pthread that allocates: a collection triggered
# from an unregistered thread aborts the whole process with
# "Collecting from unknown thread". Crystal-spawned threads are registered
# by `GC.pthread_create`; raw threads (started by C code — sokol/egui frame
# and worker threads, or our own pthread_create) are not. We hook the
# allocation entry points (`GC.malloc` & friends — every
# `__crystal_malloc64` lands there) and register the running pthread at
# its very first allocation.
#
# Registration alone is not enough: when such a thread EXITS while still
# registered, the next GC stop-world sends its suspend signal to a dead
# pthread — glibc resends forever ("Collecting from unknown thread" /
# deadlock), bionic aborts outright ("invalid pthread_t passed to
# pthread_kill"). So the registration also arms a pthread TLS destructor
# (the same mechanism bdwgc itself uses) that unregisters the thread when
# it exits.
#
# The per-thread fast path is a zero-initialized TLS flag — one extra load
# per allocation. The slow path runs once per thread and must not allocate
# itself (no reentrancy): it is plain C calls and struct writes.
lib LibGC
  fun thread_is_registered = GC_thread_is_registered : Int
  fun register_my_thread = GC_register_my_thread(sb : StackBase*) : Int
  fun unregister_my_thread = GC_unregister_my_thread : Int
end

# pthread TLS keys. The Android stdlib LibC already declares them (with
# its own PthreadKeyT alias); on other targets (glibc/musl desktops) we
# declare our own — pthread_key_t is a 32-bit int everywhere we target.
{% if flag?(:android) %}
  alias GcKeyT = LibC::PthreadKeyT
{% else %}
  alias GcKeyT = UInt32

  lib LibOS
    fun pthread_key_create(key : UInt32*, destructor : (Void* ->)) : LibC::Int
    fun pthread_setspecific(key : UInt32, value : Void*) : LibC::Int
  end
{% end %}

module OpenSSLStatic
  # Zero-initialized per thread (TLS BSS): false until this thread has
  # been confirmed with / registered to the GC.
  @[ThreadLocal]
  @@gc_thread_ok = uninitialized Bool

  # TLS key whose destructor unregisters the thread from the GC at exit;
  # armed only for threads registered by us (pre-registered Crystal
  # threads keep a null value and an inert destructor).
  @@gc_exit_key = uninitialized GcKeyT

  # :nodoc:
  def self.gc_thread_ok? : Bool
    @@gc_thread_ok
  end

  # :nodoc:
  def self.gc_exit_key=(key : GcKeyT) : Nil
    @@gc_exit_key = key
  end

  # :nodoc:
  def self.gc_key_create(key : GcKeyT*, dtor : (Void* ->)) : LibC::Int
    {% if flag?(:android) %}
      LibC.pthread_key_create(key, dtor)
    {% else %}
      LibOS.pthread_key_create(key, dtor)
    {% end %}
  end

  # :nodoc:
  def self.gc_key_set(key : GcKeyT, value : Void*) : LibC::Int
    {% if flag?(:android) %}
      LibC.pthread_setspecific(key, value)
    {% else %}
      LibOS.pthread_setspecific(key, value)
    {% end %}
  end

  # Runs at the exit of a thread we registered (pthread TLS destructor).
  # :nodoc:
  def self.gc_exit(data : Void*) : Nil
    LibGC.unregister_my_thread unless data.null?
  end

  # Once per thread: make sure the Boehm GC knows this pthread. Safe to
  # call from `GC.malloc` — allocates nothing.
  def self.ensure_gc_thread : Nil
    if LibGC.thread_is_registered != 0
      @@gc_thread_ok = true
      return
    end

    # Register with the true stack bounds so the GC scans the whole stack,
    # not just below the current frame. pthread_getattr_np works on glibc,
    # musl and bionic; fall back to the current frame address if it fails.
    frame = uninitialized UInt8
    stack_top = pointerof(frame).as(Void*)
    attr = uninitialized LibC::PthreadAttrT
    if LibC.pthread_getattr_np(LibC.pthread_self(), pointerof(attr)) == 0
      stack_base = Pointer(Void).null
      stack_size = uninitialized LibC::SizeT
      if LibC.pthread_attr_getstack(pointerof(attr), pointerof(stack_base),
           pointerof(stack_size)) == 0
        stack_top = (stack_base.as(UInt8*) + stack_size).as(Void*)
      end
      LibC.pthread_attr_destroy(pointerof(attr))
    end

    sb = LibGC::StackBase.new
    sb.mem_base = stack_top
    LibGC.register_my_thread(pointerof(sb)) # DUPLICATE (0 != ...) is fine

    # Unregister this pthread when it exits (see the top of this file).
    OpenSSLStatic.gc_key_set(@@gc_exit_key, Pointer(Void).new(1))
    @@gc_thread_ok = true
  end
end

module GC
  def self.malloc(size : LibC::SizeT) : Void*
    OpenSSLStatic.ensure_gc_thread unless OpenSSLStatic.gc_thread_ok?
    previous_def(size)
  end

  def self.malloc_atomic(size : LibC::SizeT) : Void*
    OpenSSLStatic.ensure_gc_thread unless OpenSSLStatic.gc_thread_ok?
    previous_def(size)
  end

  def self.realloc(ptr : Void*, size : LibC::SizeT) : Void*
    OpenSSLStatic.ensure_gc_thread unless OpenSSLStatic.gc_thread_ok?
    previous_def(ptr, size)
  end
end

# The TLS key is process-wide; create it once at require time (we are on
# the main thread here, before any raw thread can exist).
key = uninitialized GcKeyT
ret = OpenSSLStatic.gc_key_create(pointerof(key), ->OpenSSLStatic.gc_exit(Void*))
raise RuntimeError.from_os_error("pthread_key_create", Errno.new(ret)) unless ret == 0
OpenSSLStatic.gc_exit_key = key
