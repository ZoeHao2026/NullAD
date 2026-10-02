//! A filtering forward proxy for plaintext HTTP.
//!
//! The proxy accepts both request forms a client may use:
//!
//! * `CONNECT host:443` — a tunnel request. NullAD opens the tunnel and applies
//!   connection-level filtering, but does **not** decrypt it. See the
//!   [`crate::sni`] module note on why HTTPS URL filtering needs a different
//!   mechanism.
//! * `GET http://host/path HTTP/1.1` — absolute-form plaintext HTTP. This is
//!   where the proxy is fully effective, because the URL is visible.
//!
//! ## Implementation note
//!
//! The HTTP/1.1 message framing here is written directly on top of `TcpStream`
//! with `httparse` for header parsing, rather than through a general-purpose
//! HTTP server stack. A forward proxy is one of the few places where owning the
//! framing outright is genuinely the simpler option: the proxy must forward
//! bytes with minimal interpretation, distinguish absolute-form from
//! origin-form, and splice raw byte streams after `CONNECT`. All three are
//! awkward through an abstraction that expects to normalise requests for you.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use nullad_engine::ResourceType;

use crate::{is_local_address, DecisionSource, EngineHandle};

/// Maximum bytes of request head we will buffer.
const MAX_HEAD: usize = 64 * 1024;
/// Timeout for reading a request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(15);
/// Timeout for establishing an upstream connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Configuration for the HTTP proxy.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address to accept connections on.
    pub listen: SocketAddr,
    /// How long to wait for a request head.
    pub head_timeout: Duration,
    /// How long to wait for an upstream connection.
    pub connect_timeout: Duration,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".parse().expect("valid literal address"),
            head_timeout: HEAD_TIMEOUT,
            connect_timeout: CONNECT_TIMEOUT,
        }
    }
}

/// The outcome of reading a request head.
#[derive(Debug)]
enum HeadOutcome {
    /// A complete request was parsed.
    Request(Box<ProxyRequest>),
    /// The connection produced something unusable; this response explains why.
    Reject(String),
    /// The client closed or timed out before completing a request.
    Closed,
}

/// A parsed proxy request head.
#[derive(Debug, Clone)]
pub struct ProxyRequest {
    /// The request method.
    pub method: String,
    /// The full request target. Absolute form for proxied HTTP; `host:port` for
    /// `CONNECT`.
    pub target: String,
    /// The HTTP version as written.
    pub version: String,
    /// Raw header lines, preserved verbatim for forwarding.
    pub headers: Vec<(String, String)>,
    /// How many bytes of the connection the head occupied.
    pub head_len: usize,
}

impl ProxyRequest {
    /// Returns the value of a header, case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Returns `true` for a `CONNECT` tunnel request.
    #[must_use]
    pub fn is_connect(&self) -> bool {
        self.method.eq_ignore_ascii_case("CONNECT")
    }

    /// Extracts the host used for filtering.
    ///
    /// For `CONNECT` the target is already `host:port`; for absolute-form the
    /// host is taken from the URL. A missing `Host` header in origin-form is
    /// treated as unfilterable rather than assumed.
    #[must_use]
    pub fn host(&self) -> Option<String> {
        if self.is_connect() {
            let host = self.target.split(':').next()?;
            return (!host.is_empty()).then(|| host.to_ascii_lowercase());
        }
        if self.target.contains("://") {
            return nullad_engine::request::extract_host(&self.target);
        }
        self.header("host").map(|h| {
            h.split(':')
                .next()
                .unwrap_or(h)
                .trim()
                .to_ascii_lowercase()
        })
    }

    /// Returns the URL to evaluate for filtering.
    #[must_use]
    pub fn url_for_filtering(&self) -> String {
        if self.is_connect() {
            format!("https://{}/", self.target)
        } else if self.target.contains("://") {
            self.target.clone()
        } else {
            let host = self.header("host").unwrap_or_default();
            format!("http://{host}{}", self.target)
        }
    }

    /// Guesses the resource type from the method and accept headers.
    ///
    /// This is necessarily approximate: only a browser knows the real
    /// destination type. `Xhr` is used for non-document methods and `Document`
    /// for navigations, which matches how filter-list authors reason about
    /// these requests.
    #[must_use]
    pub fn resource_type(&self) -> ResourceType {
        if self.is_connect() {
            return ResourceType::Document;
        }
        match self.method.to_ascii_uppercase().as_str() {
            "GET" | "HEAD" => match self.header("accept") {
                Some(accept) if accept.contains("text/html") => ResourceType::Document,
                _ => ResourceType::Other,
            },
            _ => ResourceType::Xhr,
        }
    }
}

/// Parses a request head.
///
/// Returns `Ok(None)` when more bytes are needed. The returned request records
/// how many bytes the head occupied so unparsed body bytes remain untouched.
pub fn parse_request_head(buffer: &[u8]) -> Result<Option<ProxyRequest>, String> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut headers);

    match parsed.parse(buffer) {
        Ok(httparse::Status::Complete(head_len)) => {
            let method = parsed
                .method
                .ok_or_else(|| "request line has no method".to_owned())?
                .to_owned();
            let target = parsed
                .path
                .ok_or_else(|| "request line has no target".to_owned())?
                .to_owned();
            let version = match parsed.version {
                Some(0) => "1.0".to_owned(),
                _ => "1.1".to_owned(),
            };

            let mut collected = Vec::with_capacity(parsed.headers.len());
            for header in parsed.headers.iter() {
                let name = header.name.to_owned();
                let value = String::from_utf8_lossy(header.value).into_owned();
                collected.push((name, value));
            }

            Ok(Some(ProxyRequest {
                method,
                target,
                version,
                headers: collected,
                head_len,
            }))
        }
        Ok(httparse::Status::Partial) => Ok(None),
        Err(err) => Err(format!("malformed request head: {err}")),
    }
}

/// Returns the `host:port` to connect to for an upstream request.
///
/// Defaults the port from the scheme, which is what a proxy must do when the
/// URL omits it.
#[must_use]
pub fn upstream_authority(request: &ProxyRequest) -> Option<String> {
    if request.is_connect() {
        let authority = request.target.trim();
        if authority.is_empty() {
            return None;
        }
        // CONNECT always includes the port.
        return Some(authority.to_owned());
    }

    let host = request.host()?;
    let port = if let Some(after) = request.target.split("://").nth(1) {
        let authority = after.split('/').next().unwrap_or_default();
        if let Some(colon) = authority.rfind(':') {
            authority[colon + 1..].parse::<u16>().ok()
        } else {
            None
        }
    } else {
        request
            .header("host")
            .and_then(|h| h.rsplit_once(':'))
            .and_then(|(_, port)| port.parse::<u16>().ok())
    };

    let scheme = request
        .target
        .split("://")
        .next()
        .unwrap_or("http")
        .to_ascii_lowercase();
    let default_port = if scheme == "https" { 443 } else { 80 };

    Some(format!("{host}:{}", port.unwrap_or(default_port)))
}

/// Builds the origin-form request head to send upstream.
///
/// Absolute-form targets are rewritten to origin-form, which is what an origin
/// server expects. `Proxy-Connection` and hop-by-hop headers are dropped.
#[must_use]
pub fn build_upstream_head(request: &ProxyRequest, authority: &str) -> String {
    let path = if request.target.contains("://") {
        // Strip scheme and authority, keeping the path and query.
        match request.target.split_once("://") {
            Some((_, rest)) => match rest.find('/') {
                Some(slash) => rest[slash..].to_owned(),
                None => "/".to_owned(),
            },
            None => request.target.clone(),
        }
    } else {
        request.target.clone()
    };

    let mut out = format!("{} {} HTTP/1.1\r\n", request.method, path);
    let mut sent_host = false;

    for (name, value) in &request.headers {
        let lower = name.to_ascii_lowercase();
        // Hop-by-hop headers must not be forwarded.
        if matches!(
            lower.as_str(),
            "proxy-connection" | "connection" | "keep-alive" | "proxy-authorization" | "te" | "upgrade"
        ) {
            continue;
        }
        if lower == "host" {
            if sent_host {
                continue;
            }
            sent_host = true;
            out.push_str(&format!("Host: {authority}\r\n"));
            continue;
        }
        out.push_str(&format!("{name}: {value}\r\n"));
    }

    if !sent_host {
        out.push_str(&format!("Host: {authority}\r\n"));
    }

    out.push_str("Connection: close\r\n");
    out.push_str("\r\n");
    out
}

/// Builds a block response.
#[must_use]
pub fn build_block_response(rule: Option<&str>, host: &str) -> String {
    let detail = match rule {
        Some(rule) => format!("Blocked by NullAD rule: {rule}"),
        None => "Blocked by NullAD".to_owned(),
    };
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Blocked</title></head>\
         <body style=\"font-family:system-ui;margin:4rem auto;max-width:40rem\">\
         <h1>Blocked by NullAD</h1><p>{host}</p><pre>{detail}</pre></body></html>"
    );

    format!(
        "HTTP/1.1 403 Forbidden\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         X-NullAD-Blocked: 1\r\n\
         X-NullAD-Host: {host}\r\n\
         Connection: close\r\n\
         \r\n{body}",
        body.len()
    )
}

/// Builds an error response for a request NullAD cannot serve.
#[must_use]
pub fn build_error_response(status: u16, reason: &str, message: &str) -> String {
    format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         X-NullAD-Error: 1\r\n\
         Connection: close\r\n\
         \r\n{message}",
        message.len()
    )
}

/// A running filtering proxy.
#[derive(Debug)]
pub struct ProxyServer {
    listener: TcpListener,
    handle: EngineHandle,
    config: ProxyConfig,
}

impl ProxyServer {
    /// Binds the listener.
    pub async fn bind(config: ProxyConfig, handle: EngineHandle) -> std::io::Result<Self> {
        let listener = TcpListener::bind(config.listen).await?;
        Ok(Self {
            listener,
            handle,
            config,
        })
    }

    /// The address actually bound.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Runs the accept loop until cancelled.
    pub async fn run(self: Arc<Self>) {
        loop {
            let (stream, peer) = match self.listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    tracing::warn!(error = %err, "proxy accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };

            // Disable Nagle: proxy traffic is many small, latency-sensitive
            // writes, and coalescing them adds delay without saving bandwidth.
            let _ = stream.set_nodelay(true);

            let this = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(err) = this.serve_connection(stream).await {
                    tracing::debug!(error = %err, %peer, "proxy connection ended");
                }
            });
        }
    }

    /// Serves one client connection.
    pub async fn serve_connection(&self, mut client: TcpStream) -> std::io::Result<()> {
        let request = match self.read_head(&mut client).await? {
            HeadOutcome::Request(request) => *request,
            HeadOutcome::Reject(response) => {
                client.write_all(response.as_bytes()).await?;
                client.flush().await?;
                return Ok(());
            }
            HeadOutcome::Closed => return Ok(()),
        };

        let target_url = request.url_for_filtering();
        let host = request.host().unwrap_or_default();

        // Refuse requests aimed back at our own listener, which would otherwise
        // forward to ourselves forever.
        let authority = upstream_authority(&request);
        if let Some(authority) = &authority {
            if self.is_self_referential(authority) {
                let response = build_error_response(
                    508,
                    "Loop Detected",
                    "NullAD refused to proxy a request aimed at itself.",
                );
                client.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        }

        let blocked = self.handle.decide(
            &target_url,
            request.resource_type(),
            None,
            DecisionSource::Proxy,
        );

        if blocked {
            // The rule that matched is looked up again only for reporting, so
            // the common path does not pay for it.
            let rule = self.explain(&target_url);
            let response = build_block_response(rule.as_deref(), &host);
            client.write_all(response.as_bytes()).await?;
            client.flush().await?;
            return Ok(());
        }

        let Some(authority) = authority else {
            let response = build_error_response(
                400,
                "Bad Request",
                "NullAD could not determine an upstream host.",
            );
            client.write_all(response.as_bytes()).await?;
            return Ok(());
        };

        let upstream = match tokio::time::timeout(
            self.config.connect_timeout,
            TcpStream::connect(&authority),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                let response = build_error_response(
                    502,
                    "Bad Gateway",
                    &format!("Could not connect to {authority}: {err}"),
                );
                client.write_all(response.as_bytes()).await?;
                return Ok(());
            }
            Err(_) => {
                let response = build_error_response(
                    504,
                    "Gateway Timeout",
                    &format!("Timed out connecting to {authority}."),
                );
                client.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };
        let _ = upstream.set_nodelay(true);

        if request.is_connect() {
            self.tunnel(client, upstream).await
        } else {
            self.forward(client, upstream, &request, &authority).await
        }
    }

    /// Reads a request head, honouring the configured timeout.
    ///
    /// A malformed head yields the error response to send, rather than being
    /// silently dropped, so a client can tell why its request failed.
    async fn read_head(&self, client: &mut TcpStream) -> std::io::Result<HeadOutcome> {
        let mut buffer = Vec::with_capacity(2048);
        let read = async {
            loop {
                match parse_request_head(&buffer) {
                    Ok(Some(request)) => return Ok(HeadOutcome::Request(Box::new(request))),
                    Ok(None) => {}
                    Err(err) => {
                        return Ok(HeadOutcome::Reject(build_error_response(
                            400,
                            "Bad Request",
                            &err,
                        )));
                    }
                }

                if buffer.len() >= MAX_HEAD {
                    return Ok(HeadOutcome::Reject(build_error_response(
                        431,
                        "Request Header Fields Too Large",
                        "The request head exceeded NullAD's buffer limit.",
                    )));
                }

                let mut chunk = [0u8; 4096];
                let n = client.read(&mut chunk).await?;
                if n == 0 {
                    // The client went away without sending a full request.
                    return Ok(HeadOutcome::Closed);
                }
                buffer.extend_from_slice(&chunk[..n]);
            }
        };

        match tokio::time::timeout(self.config.head_timeout, read).await {
            Ok(result) => result,
            Err(_) => Ok(HeadOutcome::Closed),
        }
    }

    /// Establishes a blind tunnel for a `CONNECT` request.
    async fn tunnel(&self, mut client: TcpStream, mut upstream: TcpStream) -> std::io::Result<()> {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        client.flush().await?;
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        Ok(())
    }

    /// Forwards a plaintext HTTP request and streams the response back.
    async fn forward(
        &self,
        mut client: TcpStream,
        mut upstream: TcpStream,
        request: &ProxyRequest,
        authority: &str,
    ) -> std::io::Result<()> {
        let head = build_upstream_head(request, authority);
        upstream.write_all(head.as_bytes()).await?;
        upstream.flush().await?;

        // From here the proxy is a byte pump. Response headers are not rewritten
        // because nothing in them needs correcting for a client that asked in
        // absolute form.
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        Ok(())
    }

    /// Returns the deciding rule for a URL, for reporting only.
    fn explain(&self, url: &str) -> Option<String> {
        let request = nullad_engine::Request::new(url, ResourceType::Other);
        let result = self.handle.engine.check(&request);
        result.matched_rule.as_ref().map(|r| r.raw.clone())
    }

    /// Returns `true` when an authority resolves to one of our own listeners.
    fn is_self_referential(&self, authority: &str) -> bool {
        let Some((host, port)) = authority.rsplit_once(':') else {
            return false;
        };
        let Ok(port) = port.parse::<u16>() else {
            return false;
        };
        if port != self.config.listen.port() {
            return false;
        }
        match host.parse::<std::net::IpAddr>() {
            Ok(ip) => is_local_address(ip),
            Err(_) => matches!(host, "localhost" | "localhost.localdomain"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> ProxyRequest {
        match parse_request_head(text.as_bytes()) {
            Ok(Some(request)) => request,
            other => panic!("expected a complete request, got {other:?}"),
        }
    }

    #[test]
    fn parses_absolute_form_request() {
        let request = parse("GET http://ads.example.com/banner.gif HTTP/1.1\r\nHost: ads.example.com\r\n\r\n");
        assert_eq!(request.method, "GET");
        assert_eq!(request.target, "http://ads.example.com/banner.gif");
        assert_eq!(request.host().as_deref(), Some("ads.example.com"));
        assert_eq!(
            request.url_for_filtering(),
            "http://ads.example.com/banner.gif"
        );
    }

    #[test]
    fn parses_connect_request() {
        let request = parse("CONNECT ads.example.com:443 HTTP/1.1\r\nHost: ads.example.com:443\r\n\r\n");
        assert!(request.is_connect());
        assert_eq!(request.host().as_deref(), Some("ads.example.com"));
        assert_eq!(request.url_for_filtering(), "https://ads.example.com:443/");
    }

    #[test]
    fn origin_form_uses_the_host_header() {
        let request = parse("GET /pixel.gif HTTP/1.1\r\nHost: tracker.example.com\r\n\r\n");
        assert_eq!(request.host().as_deref(), Some("tracker.example.com"));
        assert_eq!(
            request.url_for_filtering(),
            "http://tracker.example.com/pixel.gif"
        );
    }

    #[test]
    fn partial_head_requests_more_bytes() {
        let partial = b"GET http://a.com/ HTTP/1.1\r\nHost: a.com\r\n";
        assert!(matches!(parse_request_head(partial), Ok(None)));
    }

    #[test]
    fn malformed_head_is_an_error_not_a_panic() {
        let bad = b"\x00\x01\x02 not http at all \r\n\r\n";
        assert!(parse_request_head(bad).is_err());
    }

    #[test]
    fn head_length_excludes_any_body_bytes() {
        let text = "POST http://a.com/x HTTP/1.1\r\nHost: a.com\r\n\r\nBODY";
        match parse_request_head(text.as_bytes()) {
            Ok(Some(request)) => {
                assert_eq!(request.head_len, text.len() - 4);
            }
            other => panic!("expected a request, got {other:?}"),
        }
    }

    #[test]
    fn derives_upstream_authority_with_default_ports() {
        let request = parse("GET http://ads.example.com/x HTTP/1.1\r\nHost: ads.example.com\r\n\r\n");
        assert_eq!(upstream_authority(&request).as_deref(), Some("ads.example.com:80"));

        let request = parse("GET http://ads.example.com:8080/x HTTP/1.1\r\nHost: ads.example.com:8080\r\n\r\n");
        assert_eq!(
            upstream_authority(&request).as_deref(),
            Some("ads.example.com:8080")
        );

        let request = parse("CONNECT ads.example.com:443 HTTP/1.1\r\n\r\n");
        assert_eq!(
            upstream_authority(&request).as_deref(),
            Some("ads.example.com:443")
        );
    }

    #[test]
    fn rewrites_absolute_form_to_origin_form() {
        let request = parse(
            "GET http://ads.example.com/a/b?c=1 HTTP/1.1\r\nHost: ads.example.com\r\nUser-Agent: t\r\n\r\n",
        );
        let head = build_upstream_head(&request, "ads.example.com:80");
        assert!(head.starts_with("GET /a/b?c=1 HTTP/1.1\r\n"));
        assert!(head.contains("Host: ads.example.com:80\r\n"));
        assert!(head.contains("User-Agent: t\r\n"));
        // The absolute form must not leak upstream.
        assert!(!head.contains("http://ads.example.com/a/b"));
    }

    #[test]
    fn drops_hop_by_hop_headers() {
        let request = parse(
            "GET http://a.com/ HTTP/1.1\r\nHost: a.com\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\n\r\n",
        );
        let head = build_upstream_head(&request, "a.com:80");
        let lower = head.to_ascii_lowercase();
        assert!(!lower.contains("proxy-connection"));
        assert!(!lower.contains("connection: keep-alive"));
        assert!(lower.contains("connection: close"));
    }

    #[test]
    fn adds_a_host_header_when_the_client_omitted_it() {
        let request = parse("GET http://a.com/x HTTP/1.1\r\nUser-Agent: t\r\n\r\n");
        let head = build_upstream_head(&request, "a.com:80");
        assert!(head.contains("Host: a.com:80\r\n"));
    }

    #[test]
    fn block_response_advertises_the_host_and_rule() {
        let response = build_block_response(Some("||ads.example.com^"), "ads.example.com");
        assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        assert!(response.contains("X-NullAD-Blocked: 1\r\n"));
        assert!(response.contains("X-NullAD-Host: ads.example.com\r\n"));
        assert!(response.contains("||ads.example.com^"));
    }

    #[test]
    fn classifies_resource_types() {
        let request = parse("GET http://a.com/ HTTP/1.1\r\nAccept: text/html\r\n\r\n");
        assert_eq!(request.resource_type(), ResourceType::Document);

        let request = parse("GET http://a.com/x.js HTTP/1.1\r\nAccept: */*\r\n\r\n");
        assert_eq!(request.resource_type(), ResourceType::Other);

        let request = parse("POST http://a.com/api HTTP/1.1\r\n\r\n");
        assert_eq!(request.resource_type(), ResourceType::Xhr);

        let request = parse("CONNECT a.com:443 HTTP/1.1\r\n\r\n");
        assert_eq!(request.resource_type(), ResourceType::Document);
    }

    #[test]
    fn error_responses_are_well_formed() {
        let response = build_error_response(502, "Bad Gateway", "upstream refused");
        assert!(response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
        assert!(response.contains("Content-Length: 16\r\n"));
        assert!(response.ends_with("upstream refused"));
    }
}
