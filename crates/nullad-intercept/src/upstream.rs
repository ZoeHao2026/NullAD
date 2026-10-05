//! Explicit upstream chaining. The browser extension needs no proxy changes;
//! these transports let clients of the local proxy retain an existing route.

use std::io;
use std::net::IpAddr;
use std::str::FromStr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::prefixed::PrefixedIo;

/// An unauthenticated HTTP or SOCKS5 proxy endpoint. Credentials are rejected
/// rather than accidentally sent to an origin or retained in diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamProxy {
    /// HTTP absolute-form forwarding and CONNECT tunnels.
    Http { host: String, port: u16 },
    /// SOCKS5 CONNECT with domain names resolved by the upstream.
    Socks5 { host: String, port: u16 },
}

impl FromStr for UpstreamProxy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (scheme, rest) = value.trim().split_once("://").ok_or_else(|| {
            "upstream proxy must be http://host:port or socks5://host:port".to_owned()
        })?;
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        let (host, port) = split_authority(authority)?;
        match scheme.to_ascii_lowercase().as_str() {
            "http" => Ok(Self::Http { host, port }),
            "socks5" => Ok(Self::Socks5 { host, port }),
            _ => Err("supported upstream proxy protocols: http, socks5".to_owned()),
        }
    }
}

/// Validate an authority without resolving it. Both transports preserve the
/// target hostname so split DNS and remote SOCKS resolution continue to work.
pub(crate) fn split_authority(value: &str) -> Result<(String, u16), String> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| "proxy authority requires an explicit port".to_owned())?;
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| "proxy port must be between 1 and 65535".to_owned())?;
    let host = if host.starts_with('[') {
        let ip = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .and_then(|host| host.parse::<std::net::Ipv6Addr>().ok())
            .ok_or_else(|| "invalid bracketed IPv6 proxy host".to_owned())?;
        ip.to_string()
    } else {
        if host.is_empty()
            || host.len() > 253
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
        {
            return Err(
                "invalid proxy host (URLs, credentials and paths are not hosts)".to_owned(),
            );
        }
        host.to_ascii_lowercase()
    };
    Ok((host, port))
}

impl UpstreamProxy {
    /// Host and port without DNS resolution.
    #[must_use]
    pub fn endpoint(&self) -> (&str, u16) {
        match self {
            Self::Http { host, port } | Self::Socks5 { host, port } => (host, *port),
        }
    }

    /// HTTP requests use absolute form; SOCKS5 exposes a target byte stream.
    #[must_use]
    pub const fn uses_absolute_form(&self) -> bool {
        matches!(self, Self::Http { .. })
    }

    /// Establish a route, with handshake bytes excluded from the target stream.
    /// The caller applies one timeout covering DNS, connection and handshake.
    pub(crate) async fn connect(
        &self,
        target: &str,
        tunnel: bool,
        listener: std::net::SocketAddr,
    ) -> io::Result<PrefixedIo<TcpStream>> {
        let (host, port) = self.endpoint();
        let mut stream = TcpStream::connect((host, port)).await?;
        if stream.peer_addr()? == listener {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "upstream proxy resolves back to NullAD",
            ));
        }
        let _ = stream.set_nodelay(true);
        match self {
            Self::Http { .. } if tunnel => {
                split_authority(target).map_err(invalid_input)?;
                stream
                    .write_all(
                        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes(),
                    )
                    .await?;
                let mut bytes = Vec::with_capacity(2048);
                let mut head_bytes = 0;
                let mut informational = 0;
                loop {
                    let mut headers = [httparse::EMPTY_HEADER; 64];
                    let mut response = httparse::Response::new(&mut headers);
                    match response.parse(&bytes) {
                        Ok(httparse::Status::Complete(end)) => {
                            head_bytes += end;
                            if head_bytes > 16384 {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "upstream CONNECT response heads too large",
                                ));
                            }
                            let code = response.code.unwrap_or(0);
                            if (100..200).contains(&code) {
                                informational += 1;
                                if informational > 16 {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "too many upstream informational responses",
                                    ));
                                }
                                bytes.drain(..end);
                                continue;
                            }
                            if !(200..300).contains(&code) {
                                return Err(io::Error::new(
                                    io::ErrorKind::ConnectionRefused,
                                    format!(
                                        "upstream HTTP CONNECT refused (status {})",
                                        response.code.unwrap_or(0)
                                    ),
                                ));
                            }
                            return Ok(PrefixedIo::new(bytes.split_off(end), stream));
                        }
                        Ok(httparse::Status::Partial) => {}
                        Err(_) => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid upstream HTTP CONNECT response",
                            ))
                        }
                    }
                    if head_bytes + bytes.len() >= 16384 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "upstream CONNECT response head too large",
                        ));
                    }
                    let mut chunk = [0; 1024];
                    let length = stream.read(&mut chunk).await?;
                    if length == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "upstream closed during CONNECT",
                        ));
                    }
                    bytes.extend_from_slice(&chunk[..length]);
                }
            }
            Self::Http { .. } => {}
            Self::Socks5 { .. } => {
                let (host, port) = split_authority(target).map_err(invalid_input)?;
                stream.write_all(&[5, 1, 0]).await?;
                let mut greeting = [0; 2];
                stream.read_exact(&mut greeting).await?;
                if greeting != [5, 0] {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "upstream SOCKS5 requires unsupported authentication",
                    ));
                }
                let mut request = vec![5, 1, 0];
                match host.parse::<IpAddr>() {
                    Ok(IpAddr::V4(ip)) => {
                        request.push(1);
                        request.extend_from_slice(&ip.octets());
                    }
                    Ok(IpAddr::V6(ip)) => {
                        request.push(4);
                        request.extend_from_slice(&ip.octets());
                    }
                    Err(_) => {
                        request.extend_from_slice(&[3, host.len() as u8]);
                        request.extend_from_slice(host.as_bytes());
                    }
                }
                request.extend_from_slice(&port.to_be_bytes());
                stream.write_all(&request).await?;
                let mut reply = [0; 4];
                stream.read_exact(&mut reply).await?;
                if reply[0] != 5 || reply[2] != 0 || reply[1] != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("upstream SOCKS5 CONNECT refused (code {})", reply[1]),
                    ));
                }
                let length = match reply[3] {
                    1 => 4,
                    4 => 16,
                    3 => stream.read_u8().await? as usize,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid SOCKS5 address type",
                        ))
                    }
                };
                if length == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "empty SOCKS5 address",
                    ));
                }
                let mut address = vec![0; length + 2];
                stream.read_exact(&mut address).await?;
            }
        }
        Ok(PrefixedIo::new(Vec::new(), stream))
    }
}

fn invalid_input(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_accept_http_socks_and_ipv6() {
        assert_eq!(
            "http://localhost:7890/"
                .parse::<UpstreamProxy>()
                .unwrap()
                .endpoint(),
            ("localhost", 7890)
        );
        assert_eq!(
            "socks5://[::1]:1080"
                .parse::<UpstreamProxy>()
                .unwrap()
                .endpoint(),
            ("::1", 1080)
        );
    }

    #[test]
    fn malformed_endpoints_and_credentials_are_rejected() {
        for value in [
            "http://localhost",
            "http://a:0",
            "https://a:443",
            "http://user:secret@a:80",
            "http://a:80/path",
            "http://a:80?x",
            "socks5://::1:80",
            "http://a\r\n:80",
        ] {
            assert!(value.parse::<UpstreamProxy>().is_err(), "{value:?}");
        }
    }
}
