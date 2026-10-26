# BlockingEventLoop — a stateless `Crystal::EventLoop` implementation for
# raw threads (no `Fiber::ExecutionContext`): every operation is a plain
# blocking libc syscall (poll/recv/send/connect…), the calling thread
# simply blocks. Installed as the `Crystal::EventLoop.current` fallback
# by the reopen at the bottom — scheduler-equipped threads keep their
# io_uring/epoll loop untouched.
#
# All syscalls go through the stdlib `LibC` (same signatures as the
# io_uring/epoll backends use); only `poll` isn't part of it, hence the
# tiny LibOS below.

require "socket"

{% if flag?(:unix) && !flag?(:wasi) %}

lib LibOS
  POLLIN  = 0x001
  POLLOUT = 0x004
  SO_ERROR = 4

  struct PollFd
    fd : Int32
    events : Int16
    revents : Int16
  end

  fun poll(fds : PollFd*, nfds : UInt32, timeout : Int32) : Int32
end

module OpenSSLStatic
  # errno of the last syscall (thread-local; bionic names it __errno).
  def self.errno : Errno
    {% if flag?(:android) %}
      Errno.new(LibC.__errno.value)
    {% else %}
      Errno.new(LibC.__errno_location.value)
    {% end %}
  end

  def self.eagain? : Bool
    e = errno
    e == Errno::EAGAIN || e == Errno::EWOULDBLOCK
  end

  # poll(fd, events, timeout) → true when ready, false on timeout.
  def self.poll_fd(fd : Int32, events : Int32, timeout : Time::Span?) : Bool
    pfd = LibOS::PollFd.new
    pfd.fd = fd
    pfd.events = events.to_i16!
    ms = timeout ? timeout.not_nil!.total_milliseconds.clamp(-1.0, Int32::MAX.to_f).to_i32 : -1
    loop do
      r = LibOS.poll(pointerof(pfd), 1_u32, ms)
      return true if r > 0
      return false if r == 0
      return false unless errno == Errno::EINTR
    end
  end

  # Thread-safe SO_SNDTIMEO-free blocking read of one buffer; the
  # `EINTR`-safe syscall loop every method below repeats.
  def self.syscall(& : -> LibC::SSizeT) : LibC::SSizeT
    loop do
      r = yield
      return r if r >= 0 || errno != Errno::EINTR
    end
  end
end

class OpenSSLStatic::BlockingEventLoop < Crystal::EventLoop
  class_getter instance : self { new }

  # The scheduler entry point — never called: this loop is only handed
  # out to scheduler-less (raw) threads, no one ever runs it.
  def run(queue, blocking) : Nil
    raise "BlockingEventLoop has no scheduler to run"
  end

  def run(blocking : Bool) : Bool
    raise "BlockingEventLoop has no scheduler to run"
  end

  # Scheduler bookkeeping — unreachable for the same reason as #run.
  def lock?(&) : Bool
    raise "BlockingEventLoop has no scheduler to run"
  end

  def interrupt? : Bool
    raise "BlockingEventLoop has no scheduler to run"
  end

  def interrupt : Nil
    raise "BlockingEventLoop has no scheduler to run"
  end

  # A real sleep for raw threads: nanosleep (thread-safe, no alarm),
  # not a fiber park — there is no fiber here.
  def sleep(duration : Time::Span) : Nil
    req = uninitialized LibC::Timespec
    req.tv_sec = duration.total_seconds.to_i64
    req.tv_nsec = duration.nanoseconds.to_i64 % 1_000_000_000
    rem = uninitialized LibC::Timespec
    while LibC.nanosleep(pointerof(req), pointerof(rem)) == -1 &&
          OpenSSLStatic.errno == Errno::EINTR
      req = rem
    end
  end

  def create_timeout_event(fiber : Fiber) : Crystal::EventLoop::Event
    raise "BlockingEventLoop has no scheduler to run"
  end

  # Event#finalize calls this on every backend; ours never creates
  # timer events (see #create_timeout_event), so it's a no-op.
  def delete_timer(event : Crystal::EventLoop::Event*) : Nil
  end

  def delete_timer(event : Crystal::EventLoop::Polling::Event*) : Nil
  end

  # FiberEvent#add (sleep/select timeouts) — no timers on a blocking
  # loop: the thread waits inside the syscall itself.
  def add_timer(event : Crystal::EventLoop::Polling::Event*) : Nil
  end

  # ------------------------------------------------------- FileDescriptor

  def open(path : String, flags : Int32, permissions : File::Permissions,
           blocking : Bool | ::Nil) : Errno | Tuple(Int32, Bool) | WinError
    fd = LibC.open(path.check_no_null_byte.to_unsafe,
      flags | LibC::O_CLOEXEC, permissions.value)
    fd < 0 ? Errno.new(OpenSSLStatic.errno) : {fd, true}
  end

  def pipe(read_blocking : Bool | ::Nil, write_blocking : Bool | ::Nil) : Tuple(IO::FileDescriptor, IO::FileDescriptor)
    fds = StaticArray(LibC::Int, 2).new(0)
    ret = LibC.pipe2(fds, LibC::O_CLOEXEC)
    raise IO::Error.from_os_error("pipe2", OpenSSLStatic.errno) unless ret == 0
    {IO::FileDescriptor.new(fds[0], blocking: read_blocking),
     IO::FileDescriptor.new(fds[1], blocking: write_blocking)}
  end

  def read(file_descriptor : Crystal::System::FileDescriptor, slice : Bytes) : Int32
    n = OpenSSLStatic.syscall do
      LibC.read(file_descriptor.fd, slice.to_unsafe.as(Void*), slice.size)
    end
    raise IO::Error.from_os_error("read", OpenSSLStatic.errno) if n < 0
    n.to_i32
  end

  def pread(file_descriptor, slice, offset) : Int32
    n = OpenSSLStatic.syscall do
      LibC.pread(file_descriptor.fd, slice.to_unsafe.as(Void*), slice.size, offset)
    end
    raise IO::Error.from_os_error("pread", OpenSSLStatic.errno) if n < 0
    n.to_i32
  end

  def wait_readable(file_descriptor) : Nil
    OpenSSLStatic.poll_fd(file_descriptor.fd, LibOS::POLLIN, nil)
  end

  def write(file_descriptor, slice) : Int32
    n = OpenSSLStatic.syscall do
      LibC.write(file_descriptor.fd, slice.to_unsafe.as(Void*), slice.size)
    end
    raise IO::Error.from_os_error("write", OpenSSLStatic.errno) if n < 0
    n.to_i32
  end

  def wait_writable(file_descriptor) : Nil
    OpenSSLStatic.poll_fd(file_descriptor.fd, LibOS::POLLOUT, nil)
  end

  def reopened(file_descriptor) : Nil
  end

  def shutdown(file_descriptor) : Nil
    LibC.shutdown(file_descriptor.fd, 2)
  end

  def close(file_descriptor) : Nil
    LibC.close(file_descriptor.fd)
  end

  # -------------------------------------------------------------- Socket

  def socket(family : ::Socket::Family, type : ::Socket::Type,
             protocol : ::Socket::Protocol, blocking : Bool | ::Nil) : Tuple(Int32, Bool)
    fd = LibC.socket(family.value, type.value | LibC::SOCK_CLOEXEC, protocol.value)
    raise ::Socket::Error.from_os_error("socket", OpenSSLStatic.errno) if fd < 0
    {fd, true} # created blocking — the caller must not flip it
  end

  def socketpair(type : ::Socket::Type, protocol : ::Socket::Protocol) : Tuple(Tuple(Int32, Int32), Bool)
    fds = StaticArray(LibC::Int, 2).new(0)
    ret = LibC.socketpair(::Socket::Family::UNIX.value,
      type.value | LibC::SOCK_CLOEXEC, protocol.value, fds)
    raise ::Socket::Error.from_os_error("socketpair", OpenSSLStatic.errno) unless ret == 0
    pair = {fds[0], fds[1]}
    {pair, true}
  end

  def read(socket : ::Socket, slice : Bytes) : Int32
    fd = socket.fd
    loop do
      n = OpenSSLStatic.syscall do
        LibC.recv(fd, slice.to_unsafe.as(Void*), slice.size, 0)
      end
      if n < 0 && OpenSSLStatic.eagain? &&
         OpenSSLStatic.poll_fd(fd, LibOS::POLLIN, socket.read_timeout)
        next
      end
      raise IO::Error.from_os_error("recv", OpenSSLStatic.errno) if n < 0
      return n.to_i32
    end
  end

  def wait_readable(socket : ::Socket) : Nil
    OpenSSLStatic.poll_fd(socket.fd, LibOS::POLLIN, socket.read_timeout)
  end

  def write(socket : ::Socket, slice : Bytes) : Int32
    fd = socket.fd
    loop do
      n = OpenSSLStatic.syscall do
        LibC.send(fd, slice.to_unsafe.as(Void*), slice.size, 0)
      end
      if n < 0 && OpenSSLStatic.eagain? &&
         OpenSSLStatic.poll_fd(fd, LibOS::POLLOUT, socket.write_timeout)
        next
      end
      raise IO::Error.from_os_error("send", OpenSSLStatic.errno) if n < 0
      return n.to_i32
    end
  end

  def wait_writable(socket : ::Socket) : Nil
    OpenSSLStatic.poll_fd(socket.fd, LibOS::POLLOUT, socket.write_timeout)
  end

  def accept(socket : ::Socket) : {::Socket::Handle, Bool}?
    fd = socket.fd
    loop do
      client = LibC.accept4(fd, nil, nil, LibC::SOCK_CLOEXEC)
      if client < 0 && OpenSSLStatic.eagain? &&
         OpenSSLStatic.poll_fd(fd, LibOS::POLLIN, nil)
        next
      end
      if client < 0
        return nil if OpenSSLStatic.errno == Errno::EBADF # closed
        raise ::Socket::Error.from_os_error("accept", OpenSSLStatic.errno)
      end
      return {client.as(::Socket::Handle), true}
    end
  end

  def connect(socket : ::Socket, address, timeout) : IO::Error?
    fd = socket.fd
    sockaddr = address.to_unsafe
    addrlen = address.size

    # blocking connect bounded by poll: flip to O_NONBLOCK, poll for
    # writability, check SO_ERROR, restore the blocking mode
    flags = LibC.fcntl(fd, LibC::F_GETFL, 0)
    LibC.fcntl(fd, LibC::F_SETFL, flags | LibC::O_NONBLOCK)

    err : IO::Error? = nil
    loop do
      r = LibC.connect(fd, sockaddr, addrlen)
      if r == 0
        break
      else
        e = OpenSSLStatic.errno
        if e == Errno::EINTR
          next
        elsif e == Errno::EINPROGRESS
          unless OpenSSLStatic.poll_fd(fd, LibOS::POLLOUT, timeout)
            err = IO::TimeoutError.new("Connect timed out")
            break
          end
          so_err = 0_i32
          len = 0_u32
          LibC.getsockopt(fd, LibC::SOL_SOCKET, LibOS::SO_ERROR,
            pointerof(so_err).as(Void*), pointerof(len).as(LibC::SocklenT*))
          err = ::Socket::ConnectError.from_os_error("connect",
            Errno.new(so_err)) unless so_err == 0
          break
        elsif e == Errno::EISCONN
          break
        else
          err = ::Socket::ConnectError.from_os_error("connect", e)
          break
        end
      end
    end
    LibC.fcntl(fd, LibC::F_SETFL, flags)
    err
  end

  def send_to(socket : ::Socket, slice : Bytes, address) : Int32
    n = OpenSSLStatic.syscall do
      LibC.sendto(socket.fd, slice.to_unsafe.as(Void*), slice.size, 0,
        address.to_unsafe, address.size)
    end
    raise ::Socket::Error.from_os_error("sendto", OpenSSLStatic.errno) if n < 0
    n.to_i32
  end

  def receive_from(socket : ::Socket, slice : Bytes) : Tuple(Int32, ::Socket::Address)
    sockaddr = uninitialized LibC::SockaddrStorage
    addrlen = sizeof(LibC::SockaddrStorage).to_u32!
    n = OpenSSLStatic.syscall do
      LibC.recvfrom(socket.fd, slice.to_unsafe.as(Void*), slice.size, 0,
        pointerof(sockaddr).as(LibC::Sockaddr*), pointerof(addrlen))
    end
    raise ::Socket::Error.from_os_error("recvfrom", OpenSSLStatic.errno) if n < 0
    {n.to_i32, ::Socket::Address.from(pointerof(sockaddr), addrlen)}
  end

  def sendfile(socket : ::Socket, fd, offset, count, flags) : Int64 | Errno | WinError
    off = offset
    n = OpenSSLStatic.syscall do
      LibC.sendfile(socket.fd, fd, pointerof(off), count)
    end
    n < 0 ? Errno.new(OpenSSLStatic.errno) : n.to_i64
  end

  # kTLS path (OpenSSL::SSL::Socket with TLS 1.3 kernel offload):
  # plain blocking recvmsg/sendmsg on the socket fd.
  def recvmsg(socket : ::Socket, msg : LibC::Msghdr*, flags : Int32) : Int32
    n = OpenSSLStatic.syscall { LibC.recvmsg(socket.fd, msg, flags).to_i64 }
    raise IO::Error.from_os_error("recvmsg", OpenSSLStatic.errno) if n < 0
    n.to_i32
  end

  def sendmsg(socket : ::Socket, msg : LibC::Msghdr*, flags : Int32) : Int32
    n = OpenSSLStatic.syscall { LibC.sendmsg(socket.fd, msg, flags).to_i64 }
    raise IO::Error.from_os_error("sendmsg", OpenSSLStatic.errno) if n < 0
    n.to_i32
  end

  def shutdown(socket : ::Socket) : Nil
    LibC.shutdown(socket.fd, 2)
  end

  def close(socket : ::Socket) : Nil
    LibC.close(socket.fd)
  end
end

# The fallback itself: a raw thread (no Fiber::ExecutionContext) gets
# the blocking loop instead of a NilAssertionError; every other thread
# keeps its scheduler's own loop.
class Crystal::EventLoop
  def self.current : self
    if ec = Fiber::ExecutionContext.current?
      ec.event_loop
    else
      OpenSSLStatic::BlockingEventLoop.instance.as(self)
    end
  end
end

# Fiber.syscall offloads a blocking C call (DNS getaddrinfo and friends)
# to the scheduler's syscall thread — on a raw thread there is no
# scheduler (and Thread auto-creation dies inside the GC), so the call
# runs inline: the thread just blocks, exactly what we want.
class Fiber
  def self.syscall(&)
    if Fiber::ExecutionContext.current?
      previous_def { yield }
    else
      yield
    end
  end
end

{% end %}
