//! Real local proxy transports; no system proxy, resolver or personal browser changes.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use nullad_engine::FilterEngine;
use nullad_intercept::{EngineHandle, ProxyConfig, ProxyServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("operation timed out")
}

async fn head(stream: &mut TcpStream) -> Vec<u8> {
    let mut result = Vec::new();
    while !result.ends_with(b"\r\n\r\n") {
        result.push(bounded(stream.read_u8()).await.unwrap());
        assert!(result.len() < 16384);
    }
    result
}

async fn start(
    endpoint: String,
) -> (
    Arc<ProxyServer>,
    watch::Sender<bool>,
    JoinHandle<std::io::Result<()>>,
) {
    let server = Arc::new(
        ProxyServer::bind(
            ProxyConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstream: Some(endpoint.parse().unwrap()),
                ..Default::default()
            },
            EngineHandle::new(Arc::new(FilterEngine::new())),
        )
        .await
        .unwrap(),
    );
    let (stop, receiver) = watch::channel(false);
    let task = tokio::spawn(Arc::clone(&server).run_until(receiver));
    (server, stop, task)
}

async fn finish(
    server: Arc<ProxyServer>,
    stop: watch::Sender<bool>,
    task: JoinHandle<std::io::Result<()>>,
) {
    stop.send(true).unwrap();
    bounded(task).await.unwrap().unwrap();
    let listener = TcpListener::bind(server.local_addr().unwrap())
        .await
        .unwrap();
    drop(listener);
}

#[tokio::test]
async fn http_proxy_receives_absolute_form_and_binary_body_without_local_dns() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", upstream.local_addr().unwrap());
    let expected = vec![0, 0xff, 1, 0x80, b'A'];
    let copy = expected.clone();
    let fixture = tokio::spawn(async move {
        let (mut stream, _) = bounded(upstream.accept()).await.unwrap();
        let headers = String::from_utf8(head(&mut stream).await).unwrap();
        assert!(headers
            .starts_with("POST http://nonexistent-route.invalid:7777/upload?x=1 HTTP/1.1\r\n"));
        assert!(headers.contains("Host: nonexistent-route.invalid:7777\r\n"));
        assert!(!headers.to_ascii_lowercase().contains("proxy-authorization"));
        let mut body = vec![0; copy.len()];
        bounded(stream.read_exact(&mut body)).await.unwrap();
        assert_eq!(body, copy);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });
    let (server, stop, task) = start(endpoint).await;
    let mut client = TcpStream::connect(server.local_addr().unwrap())
        .await
        .unwrap();
    let mut request = b"POST http://nonexistent-route.invalid:7777/upload?x=1 HTTP/1.1\r\nHost: nonexistent-route.invalid:7777\r\nContent-Length: 5\r\nProxy-Authorization: secret-not-forwarded\r\n\r\n".to_vec();
    request.extend_from_slice(&expected);
    client.write_all(&request).await.unwrap();
    let mut response = Vec::new();
    bounded(client.read_to_end(&mut response)).await.unwrap();
    assert!(response.ends_with(b"\r\n\r\nOK"));
    bounded(fixture).await.unwrap();
    finish(server, stop, task).await;
}

#[tokio::test]
async fn http_connect_retains_both_handshake_prefixes() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", upstream.local_addr().unwrap());
    let fixture = tokio::spawn(async move {
        let (mut stream, _) = bounded(upstream.accept()).await.unwrap();
        let headers = String::from_utf8(head(&mut stream).await).unwrap();
        assert!(headers.starts_with("CONNECT nonexistent-route.invalid:443 HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n\x80UP")
            .await
            .unwrap();
        let mut payload = [0; 3];
        bounded(stream.read_exact(&mut payload)).await.unwrap();
        assert_eq!(payload, [0, 255, 7]);
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let (server, stop, task) = start(endpoint).await;
    let mut client = TcpStream::connect(server.local_addr().unwrap())
        .await
        .unwrap();
    client.write_all(b"CONNECT nonexistent-route.invalid:443 HTTP/1.1\r\nHost: nonexistent-route.invalid:443\r\n\r\n\x00\xff\x07").await.unwrap();
    assert!(head(&mut client).await.starts_with(b"HTTP/1.1 200 "));
    let mut bytes = Vec::new();
    bounded(client.read_to_end(&mut bytes)).await.unwrap();
    assert_eq!(bytes, b"\x80UP\x00\xff\x07");
    bounded(fixture).await.unwrap();
    finish(server, stop, task).await;
}

#[tokio::test]
async fn socks5_preserves_remote_domain_resolution_and_http_content() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("socks5://{}", upstream.local_addr().unwrap());
    let fixture = tokio::spawn(async move {
        let (mut stream, _) = bounded(upstream.accept()).await.unwrap();
        let mut greeting = [0; 3];
        bounded(stream.read_exact(&mut greeting)).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).await.unwrap();
        let mut header = [0; 5];
        bounded(stream.read_exact(&mut header)).await.unwrap();
        assert_eq!(&header[..4], &[5, 1, 0, 3]);
        let mut name = vec![0; header[4] as usize];
        bounded(stream.read_exact(&mut name)).await.unwrap();
        assert_eq!(name, b"nonexistent-route.invalid");
        assert_eq!(bounded(stream.read_u16()).await.unwrap(), 7777);
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        let headers = String::from_utf8(head(&mut stream).await).unwrap();
        assert!(headers.starts_with("GET /normal?query=1 HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });
    let (server, stop, task) = start(endpoint).await;
    let mut client = TcpStream::connect(server.local_addr().unwrap())
        .await
        .unwrap();
    client.write_all(b"GET http://nonexistent-route.invalid:7777/normal?query=1 HTTP/1.1\r\nHost: nonexistent-route.invalid:7777\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    bounded(client.read_to_end(&mut response)).await.unwrap();
    assert!(response.ends_with(b"\r\n\r\nOK"));
    bounded(fixture).await.unwrap();
    finish(server, stop, task).await;
}

#[tokio::test]
async fn socks5_ipv6_tunnel_sends_binary_address_and_retains_payload() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("socks5://{}", upstream.local_addr().unwrap());
    let fixture = tokio::spawn(async move {
        let (mut stream, _) = bounded(upstream.accept()).await.unwrap();
        let mut greeting = [0; 3];
        bounded(stream.read_exact(&mut greeting)).await.unwrap();
        stream.write_all(&[5, 0]).await.unwrap();
        let mut request = [0; 22];
        bounded(stream.read_exact(&mut request)).await.unwrap();
        assert_eq!(&request[..4], &[5, 1, 0, 4]);
        assert_eq!(
            &request[4..20],
            &"2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(&request[20..], &443u16.to_be_bytes());
        stream
            .write_all(&[
                5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187,
            ])
            .await
            .unwrap();
        let byte = bounded(stream.read_u8()).await.unwrap();
        stream.write_all(&[byte]).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let (server, stop, task) = start(endpoint).await;
    let mut client = TcpStream::connect(server.local_addr().unwrap())
        .await
        .unwrap();
    client
        .write_all(b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n\xab")
        .await
        .unwrap();
    assert!(head(&mut client).await.starts_with(b"HTTP/1.1 200 "));
    assert_eq!(bounded(client.read_u8()).await.unwrap(), 0xab);
    bounded(fixture).await.unwrap();
    finish(server, stop, task).await;
}

#[tokio::test]
async fn refused_upstream_does_not_fall_back_to_direct_origin() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", upstream.local_addr().unwrap());
    let fixture = tokio::spawn(async move {
        let (mut stream, _) = bounded(upstream.accept()).await.unwrap();
        head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 407 Authentication Required\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let (server, stop, task) = start(endpoint).await;
    let mut client = TcpStream::connect(server.local_addr().unwrap())
        .await
        .unwrap();
    client
        .write_all(format!("CONNECT {} HTTP/1.1\r\n\r\n", origin.local_addr().unwrap()).as_bytes())
        .await
        .unwrap();
    assert!(head(&mut client).await.starts_with(b"HTTP/1.1 502 "));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), origin.accept())
            .await
            .is_err()
    );
    bounded(fixture).await.unwrap();
    finish(server, stop, task).await;
}

#[tokio::test]
async fn upstream_self_loop_fails_before_listening() {
    let reserve = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reserve.local_addr().unwrap();
    drop(reserve);
    let result = ProxyServer::bind(
        ProxyConfig {
            listen: address,
            upstream: Some(format!("http://{address}").parse().unwrap()),
            ..Default::default()
        },
        EngineHandle::new(Arc::new(FilterEngine::new())),
    )
    .await;
    assert!(result.is_err());
    TcpListener::bind(address).await.unwrap();
}

#[tokio::test]
async fn http_connect_accepts_informational_then_other_success_code() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", upstream.local_addr().unwrap());
    let fixture = tokio::spawn(async move {
        let (mut stream, _) = bounded(upstream.accept()).await.unwrap();
        head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 Connected\r\n\r\nPREFIX")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });
    let (server, stop, task) = start(endpoint).await;
    let mut client = TcpStream::connect(server.local_addr().unwrap())
        .await
        .unwrap();
    client
        .write_all(b"CONNECT nonexistent-route.invalid:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    assert!(head(&mut client).await.starts_with(b"HTTP/1.1 200 "));
    let mut bytes = Vec::new();
    bounded(client.read_to_end(&mut bytes)).await.unwrap();
    assert_eq!(bytes, b"PREFIX");
    bounded(fixture).await.unwrap();
    finish(server, stop, task).await;
}

#[tokio::test]
async fn resolved_upstream_alias_cannot_loop_to_own_listener() {
    let reserve = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reserve.local_addr().unwrap();
    drop(reserve);
    let server = Arc::new(
        ProxyServer::bind(
            ProxyConfig {
                listen: address,
                upstream: Some(format!("http://127.1:{}", address.port()).parse().unwrap()),
                ..Default::default()
            },
            EngineHandle::new(Arc::new(FilterEngine::new())),
        )
        .await
        .unwrap(),
    );
    let (stop, receiver) = watch::channel(false);
    let task = tokio::spawn(Arc::clone(&server).run_until(receiver));
    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(b"GET http://nonexistent-route.invalid/ HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    assert!(head(&mut client).await.starts_with(b"HTTP/1.1 502 "));
    finish(server, stop, task).await;
}
