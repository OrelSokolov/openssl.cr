# A raw pthread (created by C code, outside Crystal) has no `::Thread`
# object in its thread-local storage. The stdlib fallback
# `Crystal::System::Thread.current_thread` then lazily runs `::Thread.new`,
# whose `#stack_address` asks the Boehm GC for this thread's stack bottom —
# and GC_get_my_stackbottom segfaults, because the thread was never
# registered with GC_pthread_create.
#
# `Fiber.current` reaches that path from everywhere (e.g. `Crystal::FdLock`
# sets `@closing = Fiber.current` on every socket close), so a raw thread
# gets a pre-created STAND-IN `::Thread` instead.
#
# The stand-in is built with `allocate` — NEVER `Thread.new`/`Fiber.new`:
# the real initializers push the objects into the global `Thread.threads`
# / `Fiber.fibers` lists, and the GC `before_collect` hook walks those
# lists calling `GC_set_stackbottom` for every entry. A list entry for a
# thread that owns no real GC registration corrupts the mark phase
# (SIGSEGV inside GC_mark_from). The allocated pair stays out of both
# lists: it is an IDENTITY MARKER ONLY — nobody may resume the fiber or
# join the thread.
#
# The main thread itself ALSO has an empty TLS early at startup, and
# there the stdlib lazy create-and-store must keep working — hence the
# `pthread_self` check against the handle captured at require time.
module OpenSSLStatic
  # :nodoc:
  @@raw_thread : ::Thread?

  # :nodoc:
  @@main_pthread : LibC::PthreadT?

  # :nodoc:
  def self.raw_thread : ::Thread
    # Must already exist — creating it lazily from the raw thread itself
    # would crash exactly the way described above.
    @@raw_thread.not_nil!
  end

  # True when the calling pthread is NOT the process main thread.
  # :nodoc:
  def self.raw_pthread? : Bool
    if main = @@main_pthread
      LibC.pthread_self() != main
    else
      false
    end
  end

  # Called once at require time from the main thread.
  # :nodoc:
  def self.raw_thread_setup(main_pthread : LibC::PthreadT) : Nil
    @@main_pthread = main_pthread
    @@raw_thread ||= ::Thread.openssl_static_standin
  end
end

class Thread
  # Stand-in outside the global threads list (see the top of this file).
  # :nodoc:
  def self.openssl_static_standin : Thread
    thread = Thread.allocate
    thread.openssl_static_init(Fiber.allocate)
    thread
  end

  # :nodoc:
  def openssl_static_init(fake_main_fiber : Fiber) : Nil
    @main_fiber = fake_main_fiber
    @current_fiber = fake_main_fiber
    @name = "openssl-static-raw"
  end
end

module Crystal::System::Thread
  def self.current_thread : ::Thread
    if current_thread?
      previous_def
    elsif OpenSSLStatic.raw_pthread?
      OpenSSLStatic.raw_thread
    else
      # main thread before its TLS is populated: stdlib behavior
      # (create the main Thread object and store it)
      previous_def
    end
  end
end

# Eager setup at require time (we are on the main thread here).
OpenSSLStatic.raw_thread_setup(LibC.pthread_self())
