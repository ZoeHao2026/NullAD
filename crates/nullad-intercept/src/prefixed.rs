//! A stream wrapper that replays already-read bytes before the live socket.
//!
//! Inspecting a TLS ClientHello requires reading bytes from a socket that must
//! then be handed to the *real* handler untouched. Consuming those bytes would
//! corrupt the connection, so they are buffered and prepended instead.
//!
//! This is the standard "peek without peeking" technique: TCP-level `peek` is
//! unreliable here because a ClientHello can span multiple segments, so the
//! only correct approach is to read, inspect, and replay.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Wraps an I/O stream and yields a buffered prefix before the underlying
/// stream's own bytes.
#[derive(Debug)]
pub struct PrefixedIo<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PrefixedIo<S> {
    /// Creates a wrapper that will emit `prefix` first, then `inner`.
    #[must_use]
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }

    /// Returns how many prefix bytes have not yet been consumed.
    #[must_use]
    pub fn remaining_prefix(&self) -> usize {
        self.prefix.len().saturating_sub(self.offset)
    }

    /// Consumes the wrapper, returning the inner stream and any unread prefix.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, S) {
        (
            self.prefix[self.offset.min(self.prefix.len())..].to_vec(),
            self.inner,
        )
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drain the buffered prefix first. Only once it is exhausted does the
        // read reach the socket, which preserves byte order exactly.
        if self.offset < self.prefix.len() {
            let available = &self.prefix[self.offset..];
            let take = available.len().min(buf.remaining());
            buf.put_slice(&available[..take]);
            self.offset += take;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn prefix_is_emitted_before_inner_bytes() {
        let inner = &b"WORLD"[..];
        let mut stream = PrefixedIo::new(b"HELLO".to_vec(), inner);

        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"HELLOWORLD");
    }

    #[tokio::test]
    async fn empty_prefix_passes_through() {
        let inner = &b"DATA"[..];
        let mut stream = PrefixedIo::new(Vec::new(), inner);

        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"DATA");
    }

    #[tokio::test]
    async fn small_reads_drain_the_prefix_progressively() {
        let inner = &b"Z"[..];
        let mut stream = PrefixedIo::new(b"ABCDE".to_vec(), inner);

        let mut one = [0u8; 2];
        let n = stream.read(&mut one).await.unwrap();
        assert_eq!(&one[..n], b"AB");
        assert_eq!(stream.remaining_prefix(), 3);

        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"CDEZ");
    }

    #[test]
    fn into_parts_returns_unread_prefix() {
        let stream = PrefixedIo::new(b"ABC".to_vec(), ());
        let (prefix, _inner) = stream.into_parts();
        assert_eq!(prefix, b"ABC");
    }
}
