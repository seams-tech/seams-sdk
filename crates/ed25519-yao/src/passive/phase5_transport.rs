//! Explicit completion boundary for dedicated Phase 5 one-way bodies.

use std::io::{self, Read, Write};

pub(super) mod sealed {
    pub trait Sealed {}
}

/// A dedicated one-way body writer that can create an observable exact EOF.
///
/// Implementations must flush all preceding bytes, half-close or close the
/// transport's write direction, and ensure no surviving writer clone can keep
/// the body open. `abort_body` must be safe to retry after a failed close. Raw
/// memory writers and shared transport handles do not satisfy this contract.
pub trait EofBodyWriter: sealed::Sealed + Write {
    /// Value retained by the caller after the table body is observably closed.
    type Completion;

    /// Completes the body and makes exact EOF observable by its reader.
    ///
    /// An error must never return a completion value. The consumed writer must
    /// still make its best effort to close the write direction before return.
    fn finish_body(self) -> io::Result<Self::Completion>;

    /// Aborts an incomplete body and makes EOF observable immediately.
    fn abort_body(&mut self) -> io::Result<()>;
}

/// A dedicated blocking body reader whose zero-length read is an observable EOF.
///
/// This marker is sealed so public benchmark entry points cannot accept memory
/// cursors or custom readers that report a transient zero-length read as EOF.
/// Generic readers remain available only inside the private benchmark harness.
pub trait ExactEofBodyReader: sealed::Sealed + Read {}

/// Library-owned Unix body writer whose successful finish always attempts a
/// write-direction shutdown, including when flushing fails.
#[cfg(unix)]
#[doc(hidden)]
pub struct UnixEofBodyWriter(std::os::unix::net::UnixStream);

#[cfg(unix)]
impl UnixEofBodyWriter {
    /// Takes exclusive ownership of one Unix stream handle.
    pub fn new(stream: std::os::unix::net::UnixStream) -> Self {
        Self(stream)
    }
}

#[cfg(unix)]
impl Write for UnixEofBodyWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

#[cfg(unix)]
impl sealed::Sealed for UnixEofBodyWriter {}

#[cfg(unix)]
impl EofBodyWriter for UnixEofBodyWriter {
    type Completion = ();

    fn finish_body(mut self) -> io::Result<Self::Completion> {
        use std::net::Shutdown;

        let flush_result = self.0.flush();
        let shutdown_result = self.0.shutdown(Shutdown::Write);
        flush_result.and(shutdown_result)
    }

    fn abort_body(&mut self) -> io::Result<()> {
        use std::net::Shutdown;

        self.0.shutdown(Shutdown::Write)
    }
}

/// Library-owned Unix body reader used by Deriver B's public native benchmark facade.
#[cfg(unix)]
#[doc(hidden)]
pub struct UnixExactEofBodyReader(std::os::unix::net::UnixStream);

#[cfg(unix)]
impl UnixExactEofBodyReader {
    /// Takes exclusive ownership of one blocking Unix stream handle.
    pub fn new(stream: std::os::unix::net::UnixStream) -> Self {
        Self(stream)
    }
}

#[cfg(unix)]
impl Read for UnixExactEofBodyReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.read(buffer)
    }
}

#[cfg(unix)]
impl sealed::Sealed for UnixExactEofBodyReader {}

#[cfg(unix)]
impl ExactEofBodyReader for UnixExactEofBodyReader {}
