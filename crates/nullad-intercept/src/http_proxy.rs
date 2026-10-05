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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

use nullad_engine::ResourceType;

use crate::lifecycle::{stop_children, stopped};
use crate::prefixed::PrefixedIo;
use crate::upstream::{split_authority, UpstreamProxy};
use crate::{is_local_address, DecisionSource, EngineHandle};

/// Maximum bytes of request head we will buffer.
const MAX_HEAD: usize = 64 * 1024;
/// Timeout for reading a request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(15);
/// Timeout for establishing an upstream connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 256;

/// Configuration for the HTTP proxy.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address to accept connections on.
    pub listen: SocketAddr,
    /// How long to wait for a request head.
    pub head_timeout: Duration,
    /// How long to wait for an upstream connection.
    pub connect_timeout: Duration,
    /// Explicit route through an existing proxy. None connects directly.
    pub upstream: Option<UpstreamProxy>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".parse().expect("valid literal address"),
            head_timeout: HEAD_TIMEOUT,
            connect_timeout: CONNECT_TIMEOUT,
            upstream: None,
        }
    }
}

/// The outcome of reading a request head.
#[derive(Debug)]
enum HeadOutcome {
    /// A complete request was parsed.
    Request(Box<ProxyRequest>, Vec<u8>),
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
            return split_authority(self.target.trim())
                .ok()
                .map(|(host, _)| host);
        }
        if self.target.contains("://") {
            return nullad_engine::request::extract_host(&self.target);
        }
        self.header("host").and_then(|host| {
            nullad_engine::request::extract_host(&format!("http://{}/", host.trim()))
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
            let path = if self.target == "*" {
                "/"
            } else {
                &self.target
            };
            format!("http://{host}{path}")
        }
    }

    /// Reads browser destination metadata, then falls back to MIME/URL hints.
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
        if let Some(destination) = self.header("sec-fetch-dest") {
            let resource = match destination.trim() {
                "document" => Some(ResourceType::Document),
                "iframe" | "frame" => Some(ResourceType::Subdocument),
                "script" | "worker" | "sharedworker" | "serviceworker" => {
                    Some(ResourceType::Script)
                }
                "image" => Some(ResourceType::Image),
                "style" => Some(ResourceType::Stylesheet),
                "font" => Some(ResourceType::Font),
                "audio" | "video" | "track" => Some(ResourceType::Media),
                "object" | "embed" => Some(ResourceType::Object),
                "empty" if self.header("sec-fetch-mode") == Some("websocket") => {
                    Some(ResourceType::Websocket)
                }
                "empty" => Some(ResourceType::Xhr),
                _ => None,
            };
            if let Some(resource) = resource {
                return resource;
            }
        }
        if self.header("sec-fetch-mode") == Some("navigate") {
            return ResourceType::Document;
        }
        let accept = self
            .header("accept")
            .unwrap_or_default()
            .to_ascii_lowercase();
        if accept.contains("text/html") || accept.contains("application/xhtml+xml") {
            return ResourceType::Document;
        }
        if accept.contains("image/") {
            return ResourceType::Image;
        }
        if accept.contains("text/css") {
            return ResourceType::Stylesheet;
        }
        if accept.contains("javascript") {
            return ResourceType::Script;
        }
        let path = self
            .target
            .split(['?', '#'])
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if path.ends_with(".js") || path.ends_with(".mjs") {
            return ResourceType::Script;
        }
        if path.ends_with(".css") {
            return ResourceType::Stylesheet;
        }
        if [".png", ".gif", ".jpg", ".jpeg", ".webp", ".svg", ".ico"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
        {
            return ResourceType::Image;
        }
        if [".woff", ".woff2", ".ttf", ".otf"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
        {
            return ResourceType::Font;
        }
        if [".mp4", ".webm", ".mp3", ".ogg", ".m4a"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
        {
            return ResourceType::Media;
        }
        match self.method.to_ascii_uppercase().as_str() {
            "GET" | "HEAD" => ResourceType::Other,
            _ => ResourceType::Xhr,
        }
    }

    /// Uses only a valid HTTP(S) Referer or Origin as initiating context.
    /// Missing or opaque origins stay unknown; CONNECT has no page context.
    #[must_use]
    pub fn page_for_filtering(&self) -> Option<&str> {
        if self.is_connect() {
            return None;
        }
        ["referer", "origin"].iter().find_map(|name| {
            let value = self.header(name)?.trim();
            ((value.starts_with("http://") || value.starts_with("https://"))
                && !value.chars().any(char::is_whitespace)
                && nullad_engine::request::extract_host(value).is_some())
            .then_some(value)
        })
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
    let (authority, default_port) = if request.is_connect() {
        (request.target.trim(), None)
    } else if let Some((scheme, rest)) = request.target.split_once("://") {
        let port = if scheme.eq_ignore_ascii_case("http") {
            80
        } else if scheme.eq_ignore_ascii_case("https") {
            443
        } else {
            return None;
        };
        (rest.split(['/', '?', '#']).next()?, Some(port))
    } else {
        (request.header("host")?.trim(), Some(80))
    };
    let needs_port = if authority.starts_with('[') {
        authority.ends_with(']')
    } else {
        !authority.contains(':')
    };
    let normalized = if needs_port {
        format!("{authority}:{}", default_port?)
    } else {
        authority.to_owned()
    };
    let (host, port) = split_authority(&normalized).ok()?;
    Some(if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
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
            Some((_, rest)) => match rest.find(['/', '?']) {
                Some(query) if rest.as_bytes()[query] == b'?' => format!("/{}", &rest[query..]),
                Some(slash) => rest[slash..].to_owned(),
                None if request.method.eq_ignore_ascii_case("OPTIONS") => "*".to_owned(),
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
            "proxy-connection"
                | "connection"
                | "keep-alive"
                | "proxy-authorization"
                | "te"
                | "upgrade"
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
    build_effective_block_response(rule, None, host)
}

fn build_effective_block_response(rule: Option<&str>, reason: Option<&str>, host: &str) -> String {
    let detail = match rule {
        Some(rule) => format!("Blocked by NullAD rule: {rule}"),
        None => reason.map_or_else(
            || "Blocked by NullAD".to_owned(),
            |reason| format!("Blocked by NullAD detection: {reason}"),
        ),
    };
    let escape = |value: &str| {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    };
    let safe_host = escape(host);
    let detail = escape(&detail);
    let header_host: String = host
        .chars()
        .filter(|character| !character.is_control())
        .collect();
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Blocked</title></head>\
         <body style=\"font-family:system-ui;margin:4rem auto;max-width:40rem\">\
         <h1>Blocked by NullAD</h1><p>{safe_host}</p><pre>{detail}</pre></body></html>"
    );

    format!(
        "HTTP/1.1 403 Forbidden\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         X-NullAD-Blocked: 1\r\n\
         X-NullAD-Host: {header_host}\r\n\
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
    listener: Mutex<Option<TcpListener>>,
    address: SocketAddr,
    handle: EngineHandle,
    config: ProxyConfig,
}

impl ProxyServer {
    /// Binds the listener.
    pub async fn bind(mut config: ProxyConfig, handle: EngineHandle) -> std::io::Result<Self> {
        let listener = TcpListener::bind(config.listen).await?;
        let address = listener.local_addr()?;
        if let Some(upstream) = &config.upstream {
            let (host, port) = upstream.endpoint();
            if port == address.port()
                && (host.parse().is_ok_and(is_local_address)
                    || matches!(host, "localhost" | "localhost.localdomain"))
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "upstream proxy points back to NullAD",
                ));
            }
        }
        config.listen = address;
        Ok(Self {
            listener: Mutex::new(Some(listener)),
            address,
            handle,
            config,
        })
    }

    /// The address actually bound.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.address)
    }

    /// Runs the accept loop until cancelled.
    pub async fn run(self: Arc<Self>) {
        let (_keep_alive, stop) = watch::channel(false);
        if let Err(err) = self.run_until(stop).await {
            tracing::warn!(error = %err, "proxy listener stopped");
        }
    }

    /// Runs with owned connections until true is sent or the sender closes.
    /// Completion means every child has exited and the listening port is free.
    pub async fn run_until(
        self: Arc<Self>,
        mut stop: watch::Receiver<bool>,
    ) -> std::io::Result<()> {
        let listener = self
            .listener
            .lock()
            .map_err(|_| std::io::Error::other("proxy listener lock poisoned"))?
            .take()
            .ok_or_else(|| std::io::Error::other("proxy listener already running or stopped"))?;
        let mut children = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = stopped(&mut stop) => break,
                result = children.join_next(), if !children.is_empty() => {
                    if let Some(Ok(Err(err))) = result {
                        tracing::debug!(error = %err, "proxy connection ended");
                    }
                }
                accepted = listener.accept(), if children.len() < MAX_CONNECTIONS => {
                    match accepted {
                        Ok((stream, peer)) => {
                            let _ = stream.set_nodelay(true);
                            let this = Arc::clone(&self);
                            children.spawn(async move {
                                tracing::trace!(%peer, "proxy connection accepted");
                                this.serve_connection(stream).await
                            });
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "proxy accept failed");
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
        drop(listener);
        Ok(())
    }

    /// Serves one client connection.
    pub async fn serve_connection(&self, mut client: TcpStream) -> std::io::Result<()> {
        let (request, prefix) = match self.read_head(&mut client).await? {
            HeadOutcome::Request(request, prefix) => (*request, prefix),
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

        let decision = self.handle.decide_result(
            &target_url,
            request.resource_type(),
            request.page_for_filtering(),
            if request.is_connect() {
                DecisionSource::Connect
            } else {
                DecisionSource::Proxy
            },
        );

        if decision.blocked {
            let rule = decision.matched_rule.as_ref().map(|rule| rule.raw.as_str());
            let response = build_effective_block_response(rule, decision.reason.as_deref(), &host);
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

        // No direct fallback: silently bypassing a failed existing proxy would
        // break its routing/privacy guarantees. Timeout includes negotiation.
        let upstream = match tokio::time::timeout(
            self.config.connect_timeout,
            self.connect_upstream(&authority, request.is_connect()),
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
        let client = PrefixedIo::new(prefix, client);
        if request.is_connect() {
            self.tunnel(client, upstream).await
        } else {
            self.forward(client, upstream, &request, &authority).await
        }
    }

    async fn connect_upstream(
        &self,
        authority: &str,
        tunnel: bool,
    ) -> std::io::Result<PrefixedIo<TcpStream>> {
        match &self.config.upstream {
            Some(proxy) => proxy.connect(authority, tunnel, self.config.listen).await,
            None => {
                let stream = TcpStream::connect(authority).await?;
                let _ = stream.set_nodelay(true);
                Ok(PrefixedIo::new(Vec::new(), stream))
            }
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
                    Ok(Some(request)) => {
                        if request.head_len > MAX_HEAD {
                            return Ok(HeadOutcome::Reject(build_error_response(
                                431,
                                "Request Header Fields Too Large",
                                "The request head exceeded NullAD's buffer limit.",
                            )));
                        }
                        let prefix = buffer.split_off(request.head_len);
                        return Ok(HeadOutcome::Request(Box::new(request), prefix));
                    }
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
    async fn tunnel(
        &self,
        mut client: PrefixedIo<TcpStream>,
        mut upstream: PrefixedIo<TcpStream>,
    ) -> std::io::Result<()> {
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
        mut client: PrefixedIo<TcpStream>,
        mut upstream: PrefixedIo<TcpStream>,
        request: &ProxyRequest,
        authority: &str,
    ) -> std::io::Result<()> {
        let head = if self
            .config
            .upstream
            .as_ref()
            .is_some_and(UpstreamProxy::uses_absolute_form)
        {
            let origin_head = build_upstream_head(request, authority);
            let (_, headers) = origin_head
                .split_once("\r\n")
                .expect("generated request head");
            let target = if request.method.eq_ignore_ascii_case("OPTIONS") && request.target == "*"
            {
                format!("http://{authority}")
            } else {
                request.url_for_filtering()
            };
            format!("{} {} HTTP/1.1\r\n{headers}", request.method, target)
        } else {
            build_upstream_head(request, authority)
        };
        upstream.write_all(head.as_bytes()).await?;
        upstream.flush().await?;

        // From here the proxy is a byte pump. Response headers are not rewritten
        // because nothing in them needs correcting for a client that asked in
        // absolute form.
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        Ok(())
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
        match host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
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
    fn server_options_preserves_asterisk_and_host() {
        let origin = parse("OPTIONS * HTTP/1.1\r\nHost: example.com:8081\r\n\r\n");
        assert_eq!(origin.url_for_filtering(), "http://example.com:8081/");
        assert_eq!(
            upstream_authority(&origin).as_deref(),
            Some("example.com:8081")
        );
        assert!(
            build_upstream_head(&origin, "example.com:8081").starts_with("OPTIONS * HTTP/1.1\r\n")
        );
        let absolute = parse("OPTIONS http://example.com:8081 HTTP/1.1\r\n\r\n");
        assert!(build_upstream_head(&absolute, "example.com:8081")
            .starts_with("OPTIONS * HTTP/1.1\r\n"));
    }

    #[test]
    fn heuristic_block_page_does_not_claim_a_rule_match() {
        let response =
            build_effective_block_response(None, Some("heuristic_ad_host"), "adserver.example");
        assert!(response.contains("NullAD detection: heuristic_ad_host"));
        assert!(!response.contains("NullAD rule:"));
        let rule_response = build_block_response(Some("path<script>"), "example.com");
        assert!(rule_response.contains("path&lt;script&gt;"));
    }

    #[test]
    fn parses_absolute_form_request() {
        let request = parse(
            "GET http://ads.example.com/banner.gif HTTP/1.1\r\nHost: ads.example.com\r\n\r\n",
        );
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
        let request =
            parse("CONNECT ads.example.com:443 HTTP/1.1\r\nHost: ads.example.com:443\r\n\r\n");
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
        let request =
            parse("GET http://ads.example.com/x HTTP/1.1\r\nHost: ads.example.com\r\n\r\n");
        assert_eq!(
            upstream_authority(&request).as_deref(),
            Some("ads.example.com:80")
        );

        let request = parse(
            "GET http://ads.example.com:8080/x HTTP/1.1\r\nHost: ads.example.com:8080\r\n\r\n",
        );
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
        assert_eq!(request.resource_type(), ResourceType::Script);

        let request = parse("POST http://a.com/api HTTP/1.1\r\n\r\n");
        assert_eq!(request.resource_type(), ResourceType::Xhr);

        let request = parse("CONNECT a.com:443 HTTP/1.1\r\n\r\n");
        assert_eq!(request.resource_type(), ResourceType::Document);
    }

    #[test]
    fn browser_destination_metadata_precedes_url_and_mime_hints() {
        for (destination, resource) in [
            ("document", ResourceType::Document),
            ("iframe", ResourceType::Subdocument),
            ("script", ResourceType::Script),
            ("image", ResourceType::Image),
            ("style", ResourceType::Stylesheet),
            ("font", ResourceType::Font),
            ("video", ResourceType::Media),
            ("object", ResourceType::Object),
            ("empty", ResourceType::Xhr),
        ] {
            let request = parse(&format!("GET http://a.com/x.js HTTP/1.1\r\nSec-Fetch-Dest: {destination}\r\nAccept: text/html\r\n\r\n"));
            assert_eq!(request.resource_type(), resource, "{destination}");
        }
        let request = parse("GET http://a.com/x.js HTTP/1.1\r\nSec-Fetch-Mode: navigate\r\n\r\n");
        assert_eq!(request.resource_type(), ResourceType::Document);
        let request = parse("GET http://a.com/x HTTP/1.1\r\nSec-Fetch-Dest: empty\r\nSec-Fetch-Mode: websocket\r\n\r\n");
        assert_eq!(request.resource_type(), ResourceType::Websocket);
        let request =
            parse("GET http://a.com/PIC.PNG?x=1 HTTP/1.1\r\nSec-Fetch-Dest: future-value\r\n\r\n");
        assert_eq!(request.resource_type(), ResourceType::Image);
        let request = parse("GET http://a.com/x HTTP/1.1\r\nAccept: */*\r\n\r\n");
        assert_eq!(request.resource_type(), ResourceType::Other);
    }

    #[test]
    fn initiating_context_requires_a_valid_referer_or_non_opaque_origin() {
        let request = parse("GET http://a.com/x HTTP/1.1\r\nReferer: https://publisher.example/page\r\nOrigin: https://other.example\r\n\r\n");
        assert_eq!(
            request.page_for_filtering(),
            Some("https://publisher.example/page")
        );
        let request = parse("GET http://a.com/x HTTP/1.1\r\nReferer: malformed\r\nOrigin: https://publisher.example\r\n\r\n");
        assert_eq!(
            request.page_for_filtering(),
            Some("https://publisher.example")
        );
        for headers in [
            "",
            "Origin: null\r\n",
            "Referer: https:///\r\n",
            "Referer: https://a.com/has space\r\n",
            "Sec-Fetch-Site: cross-site\r\n",
        ] {
            let request = parse(&format!("GET http://a.com/x HTTP/1.1\r\n{headers}\r\n"));
            assert_eq!(request.page_for_filtering(), None, "{headers}");
        }
        let request =
            parse("CONNECT a.com:443 HTTP/1.1\r\nReferer: https://publisher.example\r\n\r\n");
        assert_eq!(request.page_for_filtering(), None);
    }

    #[test]
    fn error_responses_are_well_formed() {
        let response = build_error_response(502, "Bad Gateway", "upstream refused");
        assert!(response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
        assert!(response.contains("Content-Length: 16\r\n"));
        assert!(response.ends_with("upstream refused"));
    }
}
