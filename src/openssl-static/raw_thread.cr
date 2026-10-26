# A raw pthread (created by C code, outside Crystal) has no `::Thread`
# object in its thread-local storage. The stdlib fallback
# `Crystal::System::Thread.current_thread` then lazily runs `::Thread.new`,
# whose `#stack_address` asks the Boehm GC for this thread's stack bottom —
# and GC_get_my_stackbottom segfaults, because the thread was never
# registered with GC_pthread_create.
#
# `Fiber.current` reaches that path from everywhere (e.g. `Crystal::FdLock`
# sets `@closing = Fiber.current` on every socket close), so a raw thread
# gets a pre-created STAND-IN `::Thread` instead — built here at require
# time, while we are on the scheduler-equipped main thread where the GC is
# happy. The stand-in's fake main fiber is never resumed: raw threads never
# enter fiber scheduling, the object only serves as an identity marker.
#
# The main thread itself ALSO has an empty TLS early at startup, and there
# the stdlib lazy create-and-store must keep working — hence the
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
      LibC.pthread_self != main
    else
      false
    end
  end

  # Called once at require time from the main thread.
  # :nodoc:
  def self.raw_thread_setup(main_pthread : LibC::PthreadT) : Nil
    @@main_pthread = main_pthread
    @@raw_thread ||= ::Thread.new
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

# Eager setup at require time (we are on the main thread here):
# capture the main pthread handle, then build the stand-in. `Thread.new`
# without a block is the "represent an existing thread" initializer the
# stdlib itself uses for the main thread.
OpenSSLStatic.raw_thread_setup(LibC.pthread_self)
