//! A DNS sinkhole with a hand-written message codec.
//!
//! This answers DNS queries directly, returning a sinkhole address for any name
//! the filter rules block and forwarding everything else to an upstream
//! resolver. Blocking at this layer stops an advertising domain from ever
//! resolving, which is the earliest and cheapest possible interception point.
//!
//! ## Privileges
//!
//! Binding UDP/TCP port 53 and repointing the system resolver both require
//! administrator or root rights on every supported platform. The MVP therefore
//! makes DNS opt-in and leaves it disabled by default, so the rest of NullAD
//! remains fully usable without elevation.
//!
//! ## Why the codec is hand-written
//!
//! A mature DNS crate (`hickory-proto` and friends) is not present in this
//! host's offline registry cache, so the wire format is implemented here. Only
//! the subset needed for filtering is supported: standard queries with a single
//! question, with name decompression. Anything unusual is forwarded upstream
//! untouched rather than being mis-answered.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::lifecycle::{stop_children, stopped};
use crate::{DnsOutcome, EngineHandle};

/// Maximum size of a DNS message we will handle over TCP.
const MAX_TCP_MESSAGE: usize = u16::MAX as usize;
/// Shared upper bound on in-flight UDP queries and TCP clients.
const MAX_CONCURRENT_QUERIES: usize = 128;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(15);
/// Default upstream resolver.
pub const DEFAULT_UPSTREAM: &str = "8.8.8.8:53";
/// TTL for sinkhole answers, in seconds.
const SINKHOLE_TTL: u32 = 60;
/// Timeout for an upstream exchange.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

// DNS record types we synthesise answers for.
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_HTTPS: u16 = 65;
const CLASS_IN: u16 = 1;

/// Configuration for the DNS sinkhole.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// Address to listen on. Port 53 needs elevation; 5353 does not.
    pub listen: SocketAddr,
    /// Upstream resolver to forward non-blocked queries to.
    pub upstream: SocketAddr,
    /// Address returned for blocked A queries.
    pub sinkhole_v4: Ipv4Addr,
    /// Address returned for blocked AAAA queries.
    pub sinkhole_v6: Ipv6Addr,
    /// Answer blocked queries with NXDOMAIN instead of a sinkhole address.
    ///
    /// NXDOMAIN is more decisive but can make some software treat the name as
    /// broken rather than blocked, so the sinkhole address is the default.
    pub nxdomain: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:5353".parse().expect("valid literal address"),
            upstream: DEFAULT_UPSTREAM.parse().expect("valid literal address"),
            sinkhole_v4: Ipv4Addr::new(0, 0, 0, 0),
            sinkhole_v6: Ipv6Addr::UNSPECIFIED,
            nxdomain: false,
        }
    }
}

/// A parsed DNS question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The queried name, lowercase, without a trailing dot.
    pub name: String,
    /// Query type, for example 1 for A.
    pub qtype: u16,
    /// Query class, normally 1 for IN.
    pub qclass: u16,
}

/// Parses the header and questions of a DNS message.
///
/// Returns `None` for anything this layer should not try to answer, which the
/// caller forwards upstream instead.
#[must_use]
pub fn parse_question(packet: &[u8]) -> Option<Question> {
    if packet.len() < 12 {
        return None;
    }

    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    // Only standard queries (opcode 0). Anything else is not ours to answer.
    if (flags >> 11) & 0x0F != 0 {
        return None;
    }
    // A response must never be treated as a query.
    if flags & 0x8000 != 0 {
        return None;
    }

    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    // Multi-question messages are legal but almost never used; forwarding them
    // is safer than answering only part of the message.
    if qdcount != 1 {
        return None;
    }

    let (name, mut offset) = parse_name(packet, 12)?;
    if packet.len() < offset + 4 {
        return None;
    }
    let qtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    offset += 2;
    let qclass = u16::from_be_bytes([packet[offset], packet[offset + 1]]);

    Some(Question {
        name,
        qtype,
        qclass,
    })
}

/// Decodes a (possibly compressed) DNS name starting at `start`.
///
/// Returns the lowercased dotted name and the offset just past the name in the
/// original message, which is where the question's type/class fields begin.
///
/// Decompression is bounded to prevent a malicious packet from looping: each
/// pointer must strictly decrease, so every name terminates.
fn parse_name(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut offset = start;
    let mut jumped = false;
    let mut after_jump: Option<usize> = None;
    let mut hops = 0usize;

    loop {
        let len = *packet.get(offset)?;

        // A zero length terminates the name.
        if len == 0 {
            offset += 1;
            if !jumped {
                after_jump = Some(offset);
            }
            break;
        }

        // Top two bits set means a compression pointer.
        if len & 0xC0 == 0xC0 {
            let second = *packet.get(offset + 1)?;
            let target = (usize::from(len & 0x3F) << 8) | usize::from(second);
            if !jumped {
                after_jump = Some(offset + 2);
                jumped = true;
            }
            // Pointers must point strictly backwards, which both matches the
            // format (the compressor emits only backward references) and
            // guarantees termination.
            if target >= offset {
                return None;
            }
            hops += 1;
            if hops > 64 {
                return None;
            }
            offset = target;
            continue;
        }

        // A label length above 63 is invalid.
        if len > 63 {
            return None;
        }
        let len = usize::from(len);
        let label = packet.get(offset + 1..offset + 1 + len)?;
        if !label.is_ascii() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        if name.len() > 253 {
            return None;
        }
        offset += 1 + len;
    }

    Some((name, after_jump?))
}

/// Builds a response that answers `question` with a sinkhole address.
///
/// The query ID, question section, and recursion-desired bit are copied from
/// the request so the client accepts the answer as valid.
#[must_use]
pub fn build_sinkhole_response(packet: &[u8], question: &Question, config: &DnsConfig) -> Vec<u8> {
    if packet.len() < 4 {
        return build_servfail(packet);
    }
    // Name compression is not used here: every name is written in full, which
    // keeps the encoder trivially correct at a few bytes of cost.
    let mut out = Vec::with_capacity(512);

    let request_flags = u16::from_be_bytes([packet[2], packet[3]]);
    let recursion_desired = request_flags & 0x0100;

    // Response flags: QR=1, RD copied, RA=1 (we do offer recursion), RCODE.
    let mut flags: u16 = 0x8000 | recursion_desired | 0x0080;
    if config.nxdomain {
        // NXDOMAIN carries no answer records.
        flags |= 0x0003;
        out.extend_from_slice(&packet[0..2]);
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        encode_question(&mut out, question);
        return out;
    }

    // Only A and AAAA have a meaningful sinkhole answer. For anything else an
    // empty NOERROR response is returned so the client stops asking without
    // being told something false.
    let answer: Option<Vec<u8>> = match (question.qtype, question.qclass) {
        (TYPE_A, CLASS_IN) => Some(config.sinkhole_v4.octets().to_vec()),
        (TYPE_AAAA, CLASS_IN) => Some(config.sinkhole_v6.octets().to_vec()),
        (TYPE_HTTPS, CLASS_IN) => None,
        _ => None,
    };

    let ancount = u16::from(answer.is_some());

    out.extend_from_slice(&packet[0..2]); // ID
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    encode_question(&mut out, question);

    if let Some(rdata) = answer {
        // A pointer to the question's name at offset 12, which is both valid
        // and the standard way to keep answers small.
        out.extend_from_slice(&[0xC0, 0x0C]);
        out.extend_from_slice(&question.qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&SINKHOLE_TTL.to_be_bytes());
        out.extend_from_slice(&u16::try_from(rdata.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&rdata);
    }

    out
}

/// Writes a question section in uncompressed form.
fn encode_question(out: &mut Vec<u8>, question: &Question) {
    for label in question.name.split('.').filter(|l| !l.is_empty()) {
        let bytes = label.as_bytes();
        let len = u8::try_from(bytes.len().min(63)).unwrap_or(63);
        out.push(len);
        out.extend_from_slice(&bytes[..usize::from(len)]);
    }
    out.push(0); // root label
    out.extend_from_slice(&question.qtype.to_be_bytes());
    out.extend_from_slice(&question.qclass.to_be_bytes());
}

/// Builds a SERVFAIL response for a query that could not be resolved.
#[must_use]
pub fn build_servfail(packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(packet.get(..2).unwrap_or(&[0, 0]));
    // QR=1, RA=1, RCODE=2 (server failure).
    out.extend_from_slice(&(0x8000u16 | 0x0080 | 0x0002).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

/// A running DNS sinkhole.
#[derive(Debug)]
pub struct DnsServer {
    handle: EngineHandle,
    config: DnsConfig,
    bindings: Mutex<Option<(UdpSocket, TcpListener)>>,
    address: SocketAddr,
}

#[derive(Debug, Clone, Copy)]
enum Transport {
    Udp,
    Tcp,
}

impl DnsServer {
    /// Binds both transports before reporting readiness, including for port 0.
    pub async fn bind(mut config: DnsConfig, handle: EngineHandle) -> std::io::Result<Self> {
        let udp = UdpSocket::bind(config.listen).await?;
        let address = udp.local_addr()?;
        let tcp = TcpListener::bind(address).await?;
        config.listen = address;
        Ok(Self {
            handle,
            config,
            bindings: Mutex::new(Some((udp, tcp))),
            address,
        })
    }

    /// The address actually bound.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.address)
    }

    /// Compatibility entry point for callers without an explicit stop signal.
    pub async fn run(self: Arc<Self>) {
        let (_keep_alive, stop) = watch::channel(false);
        if let Err(err) = self.run_until(stop).await {
            tracing::warn!(error = %err, "dns listener stopped");
        }
    }

    /// Runs both transports with at most 128 supervised client tasks.
    /// Shutdown cancels and joins all children before releasing both ports.
    pub async fn run_until(
        self: Arc<Self>,
        mut stop: watch::Receiver<bool>,
    ) -> std::io::Result<()> {
        let (udp, tcp) = self
            .bindings
            .lock()
            .map_err(|_| std::io::Error::other("dns listener lock poisoned"))?
            .take()
            .ok_or_else(|| std::io::Error::other("dns listener already running or stopped"))?;
        let udp = Arc::new(udp);
        let mut children = JoinSet::new();
        let mut buffer = vec![0u8; MAX_TCP_MESSAGE];
        loop {
            tokio::select! {
                biased;
                _ = stopped(&mut stop) => break,
                result = children.join_next(), if !children.is_empty() => {
                    if let Some(Ok(Err(err))) = result {
                        tracing::debug!(error = %err, "dns client ended");
                    }
                }
                received = udp.recv_from(&mut buffer) => {
                    match received {
                        Ok((len, peer)) => {
                            // A response cannot preserve an ID from fewer than two bytes.
                            if len < 2 {
                                continue;
                            }
                            if children.len() >= MAX_CONCURRENT_QUERIES {
                                self.handle.stats.record_dns(DnsOutcome::Failed);
                                let response = build_servfail(&buffer[..len]);
                                let _ = udp.send_to(&response, peer).await;
                                continue;
                            }
                            let packet = buffer[..len].to_vec();
                            let this = Arc::clone(&self);
                            let reply_socket = Arc::clone(&udp);
                            children.spawn(async move {
                                let response = this.answer(&packet, Transport::Udp).await;
                                reply_socket.send_to(&response, peer).await?;
                                Ok(())
                            });
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "dns udp receive failed");
                            tokio::select! {
                                _ = stopped(&mut stop) => break,
                                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
                            }
                        }
                    }
                }
                accepted = tcp.accept(), if children.len() < MAX_CONCURRENT_QUERIES => {
                    match accepted {
                        Ok((stream, _peer)) => {
                            let this = Arc::clone(&self);
                            children.spawn(async move { this.handle_tcp(stream).await });
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "dns tcp accept failed");
                            tokio::select! {
                                _ = stopped(&mut stop) => break,
                                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                            }
                        }
                    }
                }
            }
        }
        stop_children(&mut children).await;
        drop(tcp);
        drop(udp);
        Ok(())
    }

    /// Handles one TCP connection, which may carry several sequential queries.
    async fn handle_tcp(&self, mut stream: TcpStream) -> std::io::Result<()> {
        loop {
            let mut length_prefix = [0u8; 2];
            if tokio::time::timeout(CLIENT_TIMEOUT, stream.read_exact(&mut length_prefix))
                .await
                .map_or(true, |result| result.is_err())
            {
                return Ok(()); // Client closed.
            }
            let length = usize::from(u16::from_be_bytes(length_prefix));
            if length == 0 || length > MAX_TCP_MESSAGE {
                return Ok(());
            }

            let mut packet = vec![0u8; length];
            tokio::time::timeout(CLIENT_TIMEOUT, stream.read_exact(&mut packet))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS client read timed out")
                })??;

            let response = self.answer(&packet, Transport::Tcp).await;

            let len = u16::try_from(response.len()).unwrap_or(0);
            tokio::time::timeout(CLIENT_TIMEOUT, async {
                stream.write_all(&len.to_be_bytes()).await?;
                stream.write_all(&response).await?;
                stream.flush().await
            })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS client write timed out")
            })??;
        }
    }

    /// Decides a single DNS packet and produces a response.
    async fn answer(&self, packet: &[u8], transport: Transport) -> Vec<u8> {
        if let Some(question) = parse_question(packet) {
            if self.handle.decide_host(&question.name) {
                self.handle.stats.record_dns(DnsOutcome::Blocked);
                return build_sinkhole_response(packet, &question, &self.config);
            }
        }

        match self.forward(packet, transport).await {
            Ok(response) => {
                self.handle.stats.record_dns(DnsOutcome::Forwarded);
                response
            }
            Err(err) => {
                self.handle.stats.record_dns(DnsOutcome::Failed);
                tracing::debug!(error = %err, "DNS upstream exchange failed");
                build_servfail(packet)
            }
        }
    }

    /// One deadline covers UDP, and any TCP retry required by a truncated answer.
    async fn forward(&self, packet: &[u8], transport: Transport) -> std::io::Result<Vec<u8>> {
        tokio::time::timeout(UPSTREAM_TIMEOUT, async {
            match transport {
                Transport::Tcp => self.forward_tcp(packet).await,
                Transport::Udp => {
                    let response = self.forward_udp(packet).await?;
                    if response[2] & 0x02 != 0 {
                        self.forward_tcp(packet).await
                    } else {
                        Ok(response)
                    }
                }
            }
        })
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS upstream timed out"))?
    }

    async fn forward_udp(&self, packet: &[u8]) -> std::io::Result<Vec<u8>> {
        let local = if self.config.upstream.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(local).await?;
        socket.connect(self.config.upstream).await?;
        socket.send(packet).await?;
        let mut buffer = vec![0u8; MAX_TCP_MESSAGE];
        let received = socket.recv(&mut buffer).await?;
        buffer.truncate(received);
        validate_response(packet, &buffer)?;
        Ok(buffer)
    }

    async fn forward_tcp(&self, packet: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut stream = TcpStream::connect(self.config.upstream).await?;
        let length = u16::try_from(packet.len()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "DNS query too large")
        })?;
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(packet).await?;
        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).await?;
        let length = usize::from(u16::from_be_bytes(prefix));
        let mut response = vec![0u8; length];
        stream.read_exact(&mut response).await?;
        validate_response(packet, &response)?;
        Ok(response)
    }
}

fn validate_response(query: &[u8], response: &[u8]) -> std::io::Result<()> {
    if response.len() < 12 || response.get(..2) != query.get(..2) || response[2] & 0x80 == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS upstream response has an invalid header or transaction ID",
        ));
    }
    Ok(())
}

/// Parses an upstream address from text, with a helpful default.
#[must_use]
pub fn resolve_upstream(text: &str) -> Option<SocketAddr> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Some(addr);
    }
    // Allow a bare IP by assuming port 53.
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 53));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes a query the same way a real client would.
    fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD set
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.').filter(|l| !l.is_empty()) {
            out.push(u8::try_from(label.len()).unwrap());
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out
    }

    #[test]
    fn parses_a_simple_query() {
        let query = build_query(0x1234, "ads.example.com", TYPE_A);
        let question = parse_question(&query).expect("parsed");
        assert_eq!(question.name, "ads.example.com");
        assert_eq!(question.qtype, TYPE_A);
        assert_eq!(question.qclass, CLASS_IN);
    }

    #[test]
    fn lowercases_decompressed_names() {
        let query = build_query(1, "ADS.Example.COM", TYPE_A);
        let question = parse_question(&query).expect("parsed");
        assert_eq!(question.name, "ads.example.com");
    }

    #[test]
    fn rejects_responses_and_non_queries() {
        let mut query = build_query(1, "a.com", TYPE_A);
        query[2] = 0x80; // set QR
        assert!(parse_question(&query).is_none());

        // Opcode != 0
        let mut query = build_query(1, "a.com", TYPE_A);
        query[2] = 0x08;
        assert!(parse_question(&query).is_none());
    }

    #[test]
    fn rejects_malformed_input_without_panicking() {
        assert!(parse_question(&[]).is_none());
        assert!(parse_question(&[0u8; 11]).is_none());

        let query = build_query(1, "ads.example.com", TYPE_A);
        for cut in 0..query.len() {
            let _ = parse_question(&query[..cut]);
        }
    }

    #[test]
    fn rejects_forward_compression_pointers() {
        // A pointer that points at or past itself must be refused, otherwise a
        // hostile packet could loop forever.
        let mut packet = build_query(1, "a.com", TYPE_A);
        packet[12] = 0xC0;
        packet[13] = 0x0C; // points to offset 12 == itself
        assert!(parse_question(&packet).is_none());
    }

    #[test]
    fn builds_a_sinkhole_answer_for_a_queries() {
        let query = build_query(0xBEEF, "ads.example.com", TYPE_A);
        let question = parse_question(&query).expect("parsed");
        let config = DnsConfig::default();
        let response = build_sinkhole_response(&query, &question, &config);

        // ID preserved, QR set.
        assert_eq!(&response[0..2], &[0xBE, 0xEF]);
        assert_eq!(response[2] & 0x80, 0x80);
        // One question, one answer.
        assert_eq!(u16::from_be_bytes([response[4], response[5]]), 1);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        // RCODE 0
        assert_eq!(response[3] & 0x0F, 0x00);
        // The sinkhole address appears in the answer.
        assert!(response
            .windows(4)
            .any(|w| w == config.sinkhole_v4.octets()));
    }

    #[test]
    fn builds_nxdomain_when_configured() {
        let query = build_query(1, "ads.example.com", TYPE_A);
        let question = parse_question(&query).expect("parsed");
        let config = DnsConfig {
            nxdomain: true,
            ..DnsConfig::default()
        };
        let response = build_sinkhole_response(&query, &question, &config);

        assert_eq!(response[3] & 0x0F, 0x03, "RCODE must be NXDOMAIN");
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }

    #[test]
    fn aaaa_queries_get_the_v6_sinkhole() {
        let query = build_query(1, "ads.example.com", TYPE_AAAA);
        let question = parse_question(&query).expect("parsed");
        let config = DnsConfig {
            sinkhole_v6: "::1".parse().unwrap(),
            ..DnsConfig::default()
        };
        let response = build_sinkhole_response(&query, &question, &config);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert!(response
            .windows(16)
            .any(|w| w == config.sinkhole_v6.octets()));
    }

    #[test]
    fn unrelated_types_get_an_empty_noerror_answer() {
        let query = build_query(1, "ads.example.com", TYPE_HTTPS);
        let question = parse_question(&query).expect("parsed");
        let response = build_sinkhole_response(&query, &question, &DnsConfig::default());
        assert_eq!(response[3] & 0x0F, 0x00, "RCODE must be NOERROR");
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }

    #[test]
    fn servfail_preserves_the_query_id() {
        let query = build_query(0x4321, "x.com", TYPE_A);
        let response = build_servfail(&query);
        assert_eq!(&response[0..2], &[0x43, 0x21]);
        assert_eq!(response[3] & 0x0F, 0x02);
    }

    #[test]
    fn upstream_parsing_accepts_bare_ips_and_host_ports() {
        assert_eq!(
            resolve_upstream("8.8.8.8"),
            Some("8.8.8.8:53".parse().unwrap())
        );
        assert_eq!(
            resolve_upstream("1.1.1.1:5353"),
            Some("1.1.1.1:5353".parse().unwrap())
        );
        assert_eq!(resolve_upstream("not an address"), None);
    }

    #[test]
    fn compression_expansion_is_bounded() {
        // Build a packet whose name uses a valid backward pointer.
        let mut packet = build_query(1, "example.com", TYPE_A);
        let original_len = packet.len();
        // Append a second question whose name is a pointer to offset 12.
        packet[4] = 0;
        packet[5] = 2; // claim two questions
        packet.extend_from_slice(&[0xC0, 0x0C]);
        packet.extend_from_slice(&TYPE_A.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        assert!(packet.len() > original_len);
        // Two questions is refused outright rather than partially answered.
        assert!(parse_question(&packet).is_none());
    }
}
