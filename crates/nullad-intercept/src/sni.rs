//! TLS ClientHello SNI extraction and connection-level filtering.
//!
//! The Server Name Indication extension is sent in the clear as part of the TLS
//! handshake, so a hostname can be read and acted on without decrypting
//! anything. This gives whole-connection blocking at zero cryptographic cost.
//!
//! ## What this deliberately cannot do
//!
//! * Filter by path or query inside an HTTPS URL. The request line is
//!   encrypted. Only certificate-inspecting interception could see it.
//! * See anything at all when the client uses Encrypted Client Hello (ECH),
//!   which wraps SNI in a second layer of encryption. Such connections are
//!   passed through and counted, never silently misreported as clean.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

use crate::prefixed::PrefixedIo;
use crate::{DecisionSource, EngineHandle};

/// TLS record content type for a handshake message.
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
/// TLS major version 3.
const TLS_MAJOR: u8 = 0x03;

/// Maximum bytes to buffer while looking for the ClientHello.
///
/// A real ClientHello is comfortably under 2 KiB; 16 KiB leaves room for
/// generous extension sets and post-quantum key shares without letting a
/// hostile client make us buffer without bound.
const MAX_CLIENT_HELLO: usize = 16 * 1024;

/// How long to wait for a client to send its ClientHello.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Configuration for the SNI listener.
#[derive(Debug, Clone)]
pub struct SniConfig {
    /// Address to accept connections on.
    pub listen: SocketAddr,
    /// Timeout for receiving a ClientHello.
    pub handshake_timeout: Duration,
}

impl Default for SniConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8443".parse().expect("valid literal address"),
            handshake_timeout: HANDSHAKE_TIMEOUT,
        }
    }
}

/// The result of inspecting a client's first bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientHello {
    /// A TLS handshake naming this host.
    Sni(String),
    /// A TLS handshake with no SNI extension (or ECH), so no hostname is
    /// recoverable.
    NoSni,
    /// Not a TLS handshake at all.
    NotTls,
    /// The handshake was truncated, malformed, or larger than the buffer.
    Malformed,
}

/// Accepts TCP connections and filters them by their TLS SNI.
#[derive(Debug)]
pub struct SniListener {
    listener: TcpListener,
    handle: EngineHandle,
    config: SniConfig,
}

impl SniListener {
    /// Binds the listener.
    pub async fn bind(config: SniConfig, handle: EngineHandle) -> std::io::Result<Self> {
        let listener = TcpListener::bind(config.listen).await?;
        Ok(Self {
            listener,
            handle,
            config,
        })
    }

    /// The address actually bound, which is useful when port 0 was requested.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Runs the accept loop until the task is cancelled.
    pub async fn run(self: Arc<Self>) {
        loop {
            let (stream, peer) = match self.listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    // A failed accept is rarely fatal (EMFILE, transient
                    // network errors); pause briefly and keep serving.
                    tracing::warn!(error = %err, "sni accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };

            let this = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(err) = this.handle_connection(stream, peer).await {
                    tracing::debug!(error = %err, %peer, "sni connection ended");
                }
            });
        }
    }

    /// Reads the ClientHello, decides, and either closes or forwards.
    async fn handle_connection(&self, mut stream: TcpStream, peer: SocketAddr) -> std::io::Result<()> {
        let started = read_client_hello(&mut stream, self.config.handshake_timeout).await;

        let (prefix, hello) = started?;

        // Extract the decision input by reference so `hello` stays usable.
        let decision_host: Option<&str> = match &hello {
            ClientHello::Sni(host) => Some(host.as_str()),
            _ => None,
        };

        match decision_host {
            Some(host) => {
                if self.handle.decide(
                    &format!("https://{host}/"),
                    nullad_engine::ResourceType::Document,
                    None,
                    DecisionSource::Sni,
                ) {
                    // Blocking is a plain close. There is no TLS alert that can
                    // be sent without completing a handshake, and a closed
                    // connection is the clearest signal to the client.
                    tracing::debug!(%host, %peer, "sni blocked");
                    return Ok(());
                }
            }
            None => {
                self.handle.stats.record_sni(false);
                match hello {
                    ClientHello::NoSni => {
                        tracing::trace!(%peer, "client hello without sni; passing through");
                    }
                    ClientHello::NotTls => {
                        tracing::trace!(%peer, "connection is not tls; passing through");
                    }
                    ClientHello::Malformed => {
                        tracing::debug!(%peer, "malformed client hello; passing through");
                    }
                    ClientHello::Sni(_) => unreachable!("handled by the Some arm"),
                }
            }
        }

        // Replay the buffered bytes so the real handshake proceeds untouched.
        let mut upstream = PrefixedIo::new(prefix, stream);
        forward_to_sni_target(&mut upstream, decision_host).await
    }
}

/// Connects to the host named in the ClientHello and splices the two streams.
async fn forward_to_sni_target(
    client: &mut PrefixedIo<TcpStream>,
    target: Option<&str>,
) -> std::io::Result<()> {
    // Without a hostname there is nowhere to forward to, so the connection is
    // closed. Resolving a fallback route would require configuration this
    // module deliberately does not guess at.
    let Some(target) = target else {
        return Ok(());
    };

    let mut upstream = TcpStream::connect((target, 443)).await?;
    tokio::io::copy_bidirectional(client, &mut upstream).await?;
    Ok(())
}

/// Reads the beginning of a connection and parses the ClientHello.
///
/// Returns the raw bytes read (so they can be replayed) together with the
/// inspection result.
pub async fn read_client_hello(
    stream: &mut TcpStream,
    timeout: Duration,
) -> std::io::Result<(Vec<u8>, ClientHello)> {
    let mut buffer = Vec::with_capacity(2048);

    let read = async {
        loop {
            // Stop as soon as the record containing the ClientHello is complete.
            if !buffer.is_empty() {
                match hello_is_complete(&buffer) {
                    Completeness::Complete => match parse_client_hello(&buffer) {
                        Some(hello) => return Ok(hello),
                        None => return Ok(ClientHello::Malformed),
                    },
                    Completeness::Need(_) => {}
                    Completeness::NotTls => {
                        // Nothing to inspect; read a little more so a plain
                        // HTTP request still has enough bytes to route, then
                        // stop rather than consuming an entire body.
                        if buffer.len() >= 1024 {
                            return Ok(ClientHello::NotTls);
                        }
                    }
                }
            }

            if buffer.len() >= MAX_CLIENT_HELLO {
                return Ok(ClientHello::Malformed);
            }

            let mut chunk = [0u8; 4096];
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                // Peer closed. Report whatever was detected from what arrived.
                if buffer.is_empty() {
                    return Ok(ClientHello::NotTls);
                }
                return Ok(parse_client_hello(&buffer).unwrap_or(ClientHello::Malformed));
            }
            buffer.extend_from_slice(&chunk[..n]);
        }
    };

    match tokio::time::timeout(timeout, read).await {
        Ok(Ok(hello)) => Ok((buffer, hello)),
        Ok(Err(err)) => Err(err),
        Err(_) => Ok((buffer, ClientHello::Malformed)),
    }
}

/// How many more bytes a partial record needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Completeness {
    /// Enough bytes are present to parse.
    Complete,
    /// More bytes are needed.
    Need(usize),
    /// The stream does not begin with a TLS handshake record.
    NotTls,
}

/// Determines whether the buffered bytes contain a whole TLS record.
fn hello_is_complete(buffer: &[u8]) -> Completeness {
    if buffer.len() < 5 {
        return Completeness::Need(5 - buffer.len());
    }
    if buffer[0] != CONTENT_TYPE_HANDSHAKE || buffer[1] != TLS_MAJOR {
        return Completeness::NotTls;
    }

    let record_len = usize::from(u16::from_be_bytes([buffer[3], buffer[4]]));
    let total = 5 + record_len;
    if buffer.len() < total {
        return Completeness::Need(total - buffer.len());
    }
    Completeness::Complete
}

/// Parses a TLS ClientHello and extracts the SNI hostname.
///
/// Returns `None` when the bytes are not a well-formed ClientHello, which the
/// caller reports as malformed rather than guessing.
#[must_use]
pub fn parse_client_hello(buffer: &[u8]) -> Option<ClientHello> {
    // TLS record header: type(1) version(2) length(2).
    let record = buffer.get(..)?;
    if record.len() < 5 || record[0] != CONTENT_TYPE_HANDSHAKE {
        return Some(ClientHello::NotTls);
    }
    let record_len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    let body = record.get(5..5 + record_len)?;

    // Handshake header: type(1) length(3).
    if body.len() < 4 || body[0] != 0x01 {
        return Some(ClientHello::Malformed);
    }
    let hs_len = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | body[3] as usize;
    let hs = body.get(4..4 + hs_len)?;

    let mut cursor = Cursor::new(hs);

    // client_version(2) random(32)
    cursor.skip(2)?;
    cursor.skip(32)?;

    // session_id: length-prefixed
    let session_len = cursor.u8()? as usize;
    cursor.skip(session_len)?;

    // cipher_suites: 16-bit length prefix
    let cipher_len = cursor.u16()? as usize;
    cursor.skip(cipher_len)?;

    // compression_methods: 8-bit length prefix
    let compression_len = cursor.u8()? as usize;
    cursor.skip(compression_len)?;

    // extensions: 16-bit length prefix
    let extensions_len = cursor.u16()? as usize;
    let extensions = cursor.take(extensions_len)?;

    let mut ext_cursor = Cursor::new(extensions);
    while ext_cursor.remaining() >= 4 {
        let ext_type = ext_cursor.u16()?;
        let ext_len = ext_cursor.u16()? as usize;
        let ext = ext_cursor.take(ext_len)?;

        if ext_type == 0x0000 {
            // server_name extension: list_length(2), then entries.
            let mut sni = Cursor::new(ext);
            let _list_len = sni.u16()?;
            while sni.remaining() >= 3 {
                let name_type = sni.u8()?;
                let name_len = sni.u16()? as usize;
                let name = sni.take(name_len)?;
                if name_type == 0x00 {
                    let host = std::str::from_utf8(name).ok()?.trim_end_matches('.').to_ascii_lowercase();
                    if host.is_empty() {
                        return Some(ClientHello::NoSni);
                    }
                    return Some(ClientHello::Sni(host));
                }
            }
            return Some(ClientHello::NoSni);
        }
    }

    Some(ClientHello::NoSni)
}

/// A minimal bounds-checked reader over a byte slice.
#[derive(Debug)]
struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        if self.remaining() < n {
            return None;
        }
        self.offset += n;
        Some(())
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let slice = &self.data[self.offset..self.offset + n];
        self.offset += n;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal but structurally valid ClientHello record.
    fn build_client_hello(host: Option<&str>) -> Vec<u8> {
        let mut extensions = Vec::new();

        if let Some(host) = host {
            let mut sni = Vec::new();
            let name = host.as_bytes();
            let entry_len = 1 + 2 + name.len();
            sni.extend_from_slice(&u16::try_from(entry_len).unwrap().to_be_bytes());
            sni.push(0x00); // host_name
            sni.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
            sni.extend_from_slice(name);

            extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // server_name
            extensions.extend_from_slice(&u16::try_from(sni.len()).unwrap().to_be_bytes());
            extensions.extend_from_slice(&sni);
        } else {
            // An unrelated extension so the block is still well formed.
            extensions.extend_from_slice(&0x0017u16.to_be_bytes()); // extended_master_secret
            extensions.extend_from_slice(&0u16.to_be_bytes());
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(32); // session_id length
        body.extend_from_slice(&[0u8; 32]); // session_id
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1); // compression methods length
        body.push(0); // null compression
        body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01); // client_hello
        let len = body.len();
        handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&u16::try_from(handshake.len()).unwrap().to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_sni_from_a_real_shaped_client_hello() {
        let record = build_client_hello(Some("ads.example.com"));
        assert_eq!(
            parse_client_hello(&record),
            Some(ClientHello::Sni("ads.example.com".into()))
        );
    }

    #[test]
    fn normalises_case_and_trailing_dot() {
        let record = build_client_hello(Some("ADS.Example.COM"));
        assert_eq!(
            parse_client_hello(&record),
            Some(ClientHello::Sni("ads.example.com".into()))
        );
    }

    #[test]
    fn reports_missing_sni_rather_than_guessing() {
        let record = build_client_hello(None);
        assert_eq!(parse_client_hello(&record), Some(ClientHello::NoSni));
    }

    #[test]
    fn non_tls_input_is_identified() {
        assert_eq!(
            parse_client_hello(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
            Some(ClientHello::NotTls)
        );
        assert_eq!(parse_client_hello(b"\x16\x03\x01"), Some(ClientHello::NotTls));
    }

    #[test]
    fn truncated_input_is_reported_not_panicked_on() {
        let record = build_client_hello(Some("ads.example.com"));
        // Every truncation point must be handled without panicking.
        for cut in 0..record.len() {
            let _ = parse_client_hello(&record[..cut]);
        }
    }

    #[test]
    fn completeness_detection_waits_for_the_whole_record() {
        let record = build_client_hello(Some("ads.example.com"));
        assert_eq!(hello_is_complete(&[]), Completeness::Need(5));
        assert_eq!(hello_is_complete(&record[..3]), Completeness::Need(2));
        assert!(matches!(
            hello_is_complete(&record[..10]),
            Completeness::Need(_)
        ));
        assert_eq!(hello_is_complete(&record), Completeness::Complete);
        assert_eq!(
            hello_is_complete(b"GET / HTTP/1.1"),
            Completeness::NotTls
        );
    }

    #[test]
    fn length_overflow_is_rejected() {
        // Declare a huge record length; the parser must refuse rather than
        // slice out of bounds.
        let mut record = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x01, 0xFF, 0xFF];
        record.extend_from_slice(&[0x01, 0x00, 0x00, 0x05]);
        assert!(parse_client_hello(&record).is_none());
    }

    #[test]
    fn absurd_extension_length_is_rejected() {
        // Claim an extension list far longer than the handshake actually holds.
        // The parser must refuse rather than read past the end of the buffer.
        let record = build_client_hello(Some("ads.example.com"));

        // Locate the extensions block and overwrite its 16-bit length prefix.
        // It sits immediately before the server_name extension, so it is found
        // by searching for the extension type bytes that follow it.
        let ext_len_pos = record
            .windows(6)
            .position(|w| w[4] == 0x00 && w[5] == 0x00)
            .map(|pos| pos + 2)
            .expect("extensions length prefix");

        let mut corrupted = record.clone();
        corrupted[ext_len_pos] = 0xFF;
        corrupted[ext_len_pos + 1] = 0xFF;

        assert!(
            parse_client_hello(&corrupted).is_none(),
            "an oversized extensions length must be rejected"
        );
    }

    #[test]
    fn extension_inner_length_overflow_is_rejected() {
        // A well-formed extensions block whose single extension claims a body
        // longer than the block contains.
        let record = build_client_hello(Some("ads.example.com"));
        let ext_len_pos = record
            .windows(6)
            .position(|w| w[4] == 0x00 && w[5] == 0x00)
            .map(|pos| pos + 2)
            .expect("extensions length prefix");

        let mut corrupted = record.clone();
        // Keep the list length truthful but make the inner extension length
        // absurd, so the inner cursor runs off the extension block.
        corrupted[ext_len_pos + 2] = 0x00; // ext type hi
        corrupted[ext_len_pos + 3] = 0x00; // ext type lo (server_name)
        corrupted[ext_len_pos + 4] = 0x7F; // ext length hi
        corrupted[ext_len_pos + 5] = 0xFF; // ext length lo

        assert!(parse_client_hello(&corrupted).is_none());
    }
}
