# Boehm GC must know every pthread that allocates: a collection triggered
# from an unregistered thread aborts the whole process with
# "Collecting from unknown thread". Crystal-spawned threads are registered
# by `GC.pthread_create`; raw threads (started by C code — sokol/egui frame
# and worker threads) are not. We hook the allocation entry points
# (`GC.malloc` & friends — every `__crystal_malloc64` lands there) and
# register the running pthread at its very first allocation.
#
# The per-thread fast path is a zero-initialized TLS flag — one extra load
# per allocation. The slow path runs once per thread and must not allocate
# itself (no reentrancy): it is plain C calls and struct writes.
lib LibGC
  fun thread_is_registered = GC_thread_is_registered : Int
  fun register_my_thread = GC_register_my_thread(sb : StackBase*) : Int
end

module OpenSSLStatic
  # Zero-initialized per thread (TLS BSS): false until this thread has
  # been confirmed with / registered to the GC.
  @[ThreadLocal]
  @@gc_thread_ok = uninitialized Bool

  # :nodoc:
  def self.gc_thread_ok? : Bool
    @@gc_thread_ok
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
