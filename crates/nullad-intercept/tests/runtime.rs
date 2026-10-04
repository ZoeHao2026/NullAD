//! Real socket regression checks. Every upstream is local and deterministic.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use nullad_engine::{FilterEngine, RuleSetBuilder};
use nullad_intercept::{
    DnsConfig, DnsServer, EngineHandle, ProxyConfig, ProxyServer, SniConfig, SniListener,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("socket operation timed out")
}

fn handle() -> EngineHandle {
    let mut builder = RuleSetBuilder::new();
    builder.add_list_auto("||blocked.example^");
    EngineHandle::new(Arc::new(FilterEngine::from_rule_set(
        builder.build().unwrap(),
    )))
}

async fn read_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        bounded(stream.read_exact(&mut byte)).await.unwrap();
        head.push(byte[0]);
        assert!(head.len() <= 65536);
    }
    head
}

fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut packet = Vec::from(id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet
}

fn response(query: &[u8]) -> Vec<u8> {
    let mut packet = query.to_vec();
    packet[2] = 0x81;
    packet[3] = 0x80;
    packet
}

async fn udp_receive(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut packet = vec![0; 65535];
    let (length, peer) = bounded(socket.recv_from(&mut packet)).await.unwrap();
    packet.truncate(length);
    (packet, peer)
}

async fn tcp_query(stream: &mut TcpStream, packet: &[u8]) -> Vec<u8> {
    stream
        .write_all(&(packet.len() as u16).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(packet).await.unwrap();
    let mut length = [0; 2];
    bounded(stream.read_exact(&mut length)).await.unwrap();
    let mut answer = vec![0; u16::from_be_bytes(length) as usize];
    bounded(stream.read_exact(&mut answer)).await.unwrap();
    answer
}

async fn socket_closed(stream: &mut TcpStream) {
    let mut byte = [0];
    match bounded(stream.read(&mut byte)).await {
        Ok(0) => {}
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ) => {}
        result => panic!("connection remained open after stop: {result:?}"),
    }
}

#[tokio::test]
async fn proxy_preserves_coalesced_split_binary_and_chunked_bodies() {
    for (body, chunked, split) in [
        (b"hello".to_vec(), false, false),
        (vec![0, 1, 0xff, 0, 0x80], false, false),
        (b"separate-body".to_vec(), false, true),
        (
            b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n".to_vec(),
            true,
            false,
        ),
    ] {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = origin.local_addr().unwrap();
        let proxy = Arc::new(
            ProxyServer::bind(
                ProxyConfig {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    ..Default::default()
                },
                handle(),
            )
            .await
            .unwrap(),
        );
        let mut client = TcpStream::connect(proxy.local_addr().unwrap())
            .await
            .unwrap();
        let framing = if chunked {
            "Transfer-Encoding: chunked\r\n".to_owned()
        } else {
            format!("Content-Length: {}\r\n", body.len())
        };
        let head =
            format!("POST http://{target}/upload HTTP/1.1\r\nHost: {target}\r\n{framing}\r\n");
        let mut outbound = head.into_bytes();
        if !split {
            outbound.extend_from_slice(&body);
        }
        // Queue the complete write before starting the handler so its first read
        // can consume both the request head and the body.
        client.write_all(&outbound).await.unwrap();
        let (stop, receiver) = watch::channel(false);
        let serving = tokio::spawn(proxy.run_until(receiver));
        let (mut upstream, _) = bounded(origin.accept()).await.unwrap();
        let forwarded_head = read_head(&mut upstream).await;
        assert!(forwarded_head.starts_with(b"POST /upload HTTP/1.1\r\n"));
        if split {
            client.write_all(&body).await.unwrap();
        }
        let mut received = vec![0; body.len()];
        bounded(upstream.read_exact(&mut received)).await.unwrap();
        assert_eq!(received, body);
        upstream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await
            .unwrap();
        upstream.shutdown().await.unwrap();
        let mut reply = Vec::new();
        bounded(client.read_to_end(&mut reply)).await.unwrap();
        assert!(reply.ends_with(b"\r\n\r\nOK"));
        stop.send(true).unwrap();
        bounded(serving).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn connect_preserves_early_payload_and_stop_closes_both_streams() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = origin.local_addr().unwrap();
    let proxy = Arc::new(
        ProxyServer::bind(
            ProxyConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                ..Default::default()
            },
            handle(),
        )
        .await
        .unwrap(),
    );
    let mut client = TcpStream::connect(proxy.local_addr().unwrap())
        .await
        .unwrap();
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").into_bytes();
    request.extend_from_slice(b"\x16\x03\x01hello");
    client.write_all(&request).await.unwrap();
    let (stop, receiver) = watch::channel(false);
    let serving = tokio::spawn(proxy.run_until(receiver));
    let (mut upstream, _) = bounded(origin.accept()).await.unwrap();
    assert!(read_head(&mut client).await.starts_with(b"HTTP/1.1 200"));
    let mut prefix = [0; 8];
    bounded(upstream.read_exact(&mut prefix)).await.unwrap();
    assert_eq!(&prefix, b"\x16\x03\x01hello");
    upstream.write_all(b"echo").await.unwrap();
    let mut echo = [0; 4];
    bounded(client.read_exact(&mut echo)).await.unwrap();
    assert_eq!(&echo, b"echo");
    stop.send(true).unwrap();
    bounded(serving).await.unwrap().unwrap();
    socket_closed(&mut client).await;
    socket_closed(&mut upstream).await;
}

#[tokio::test]
async fn block_response_uses_the_original_resource_type_and_only_one_check() {
    let mut builder = RuleSetBuilder::new();
    builder.add_list_auto("||blocked.example^$xmlhttprequest");
    let engine = Arc::new(FilterEngine::from_rule_set(builder.build().unwrap()));
    let handle = EngineHandle::new(engine.clone());
    let proxy = Arc::new(
        ProxyServer::bind(
            ProxyConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                ..Default::default()
            },
            handle.clone(),
        )
        .await
        .unwrap(),
    );
    let (stop, receiver) = watch::channel(false);
    let address = proxy.local_addr().unwrap();
    let serving = tokio::spawn(proxy.run_until(receiver));
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(b"POST http://blocked.example/x HTTP/1.1\r\nHost: blocked.example\r\nContent-Length: 0\r\n\r\n").await.unwrap();
    let mut reply = String::new();
    bounded(client.read_to_string(&mut reply)).await.unwrap();
    assert!(reply.starts_with("HTTP/1.1 403"));
    assert!(reply.contains("$xmlhttprequest"));
    assert_eq!(engine.stats_snapshot().queries, 1);
    assert_eq!(handle.stats.proxy_requests(), 1);
    stop.send(true).unwrap();
    bounded(serving).await.unwrap().unwrap();
}

#[tokio::test]
async fn slow_dns_query_does_not_delay_blocked_or_fast_queries() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = Arc::new(
        DnsServer::bind(
            DnsConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstream: upstream.local_addr().unwrap(),
                ..Default::default()
            },
            handle(),
        )
        .await
        .unwrap(),
    );
    let address = server.local_addr().unwrap();
    let (stop, receiver) = watch::channel(false);
    let serving = tokio::spawn(server.run_until(receiver));
    let slow = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    slow.send_to(&query(10, "slow.example", 1), address)
        .await
        .unwrap();
    let (slow_query, slow_peer) = udp_receive(&upstream).await;
    let blocked = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    blocked
        .send_to(&query(11, "blocked.example", 1), address)
        .await
        .unwrap();
    let blocked_reply = tokio::time::timeout(Duration::from_secs(1), udp_receive(&blocked))
        .await
        .unwrap()
        .0;
    assert_eq!(&blocked_reply[..2], &11u16.to_be_bytes());
    assert_eq!(u16::from_be_bytes([blocked_reply[6], blocked_reply[7]]), 1);
    let fast = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    fast.send_to(&query(12, "fast.example", 1), address)
        .await
        .unwrap();
    let (fast_query, fast_peer) =
        tokio::time::timeout(Duration::from_secs(1), udp_receive(&upstream))
            .await
            .unwrap();
    assert_eq!(&fast_query[..2], &12u16.to_be_bytes());
    upstream
        .send_to(&response(&fast_query), fast_peer)
        .await
        .unwrap();
    assert_eq!(udp_receive(&fast).await.0, response(&fast_query));
    upstream
        .send_to(&response(&slow_query), slow_peer)
        .await
        .unwrap();
    assert_eq!(udp_receive(&slow).await.0, response(&slow_query));
    stop.send(true).unwrap();
    bounded(serving).await.unwrap().unwrap();
}

#[tokio::test]
async fn dns_concurrency_is_bounded_and_saturation_returns_servfail() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = Arc::new(
        DnsServer::bind(
            DnsConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstream: upstream.local_addr().unwrap(),
                ..Default::default()
            },
            handle(),
        )
        .await
        .unwrap(),
    );
    let address = server.local_addr().unwrap();
    let (stop, receiver) = watch::channel(false);
    let serving = tokio::spawn(server.run_until(receiver));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Await each upstream arrival: this avoids assumptions about UDP kernel
    // buffer capacity while filling all 128 slots with unanswered exchanges.
    for id in 0..128 {
        client
            .send_to(&query(id, "pending.example", 1), address)
            .await
            .unwrap();
        udp_receive(&upstream).await;
    }
    client
        .send_to(&query(9000, "overflow.example", 1), address)
        .await
        .unwrap();
    let (reply, _) = tokio::time::timeout(Duration::from_secs(1), udp_receive(&client))
        .await
        .unwrap();
    assert_eq!(&reply[..2], &9000u16.to_be_bytes());
    assert_eq!(reply[3] & 0x0f, 2);
    stop.send(true).unwrap();
    bounded(serving).await.unwrap().unwrap();
}

#[tokio::test]
async fn dns_retries_truncated_udp_over_tcp_and_preserves_large_tcp_answers() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(upstream_address).await.unwrap();
    let server = Arc::new(
        DnsServer::bind(
            DnsConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstream: upstream_address,
                ..Default::default()
            },
            handle(),
        )
        .await
        .unwrap(),
    );
    let address = server.local_addr().unwrap();
    let (stop, receiver) = watch::channel(false);
    let serving = tokio::spawn(server.run_until(receiver));
    let udp_upstream = tokio::spawn(async move {
        let (packet, peer) = udp_receive(&udp).await;
        let mut truncated = response(&packet);
        truncated[2] |= 0x02;
        udp.send_to(&truncated, peer).await.unwrap();
    });
    let tcp_upstream = tokio::spawn(async move {
        let mut last = Vec::new();
        for exchange in 0..2 {
            let (mut stream, _) = bounded(tcp.accept()).await.unwrap();
            let mut prefix = [0; 2];
            bounded(stream.read_exact(&mut prefix)).await.unwrap();
            let mut packet = vec![0; u16::from_be_bytes(prefix) as usize];
            bounded(stream.read_exact(&mut packet)).await.unwrap();
            let mut reply = response(&packet);
            if exchange == 1 {
                reply[7] = 1; // One valid TXT answer with more than 4096 bytes.
                let mut txt = Vec::new();
                for _ in 0..24 {
                    txt.push(250);
                    txt.extend_from_slice(&[b'x'; 250]);
                }
                reply.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60]);
                reply.extend_from_slice(&(txt.len() as u16).to_be_bytes());
                reply.extend_from_slice(&txt);
                last = reply.clone();
            }
            stream
                .write_all(&(reply.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&reply).await.unwrap();
        }
        last
    });
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let first = query(33, "safe.example", 16);
    client.send_to(&first, address).await.unwrap();
    assert_eq!(udp_receive(&client).await.0, response(&first));
    let mut client = TcpStream::connect(address).await.unwrap();
    let large = tcp_query(&mut client, &query(34, "large.example", 16)).await;
    assert!(large.len() > 4096);
    assert_eq!(large, bounded(tcp_upstream).await.unwrap());
    bounded(udp_upstream).await.unwrap();
    stop.send(true).unwrap();
    bounded(serving).await.unwrap().unwrap();
}

async fn upstream_round_trip(bind: &str) {
    let upstream = UdpSocket::bind(bind)
        .await
        .expect("upstream loopback must be available");
    let server = Arc::new(
        DnsServer::bind(
            DnsConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstream: upstream.local_addr().unwrap(),
                ..Default::default()
            },
            handle(),
        )
        .await
        .unwrap(),
    );
    let address = server.local_addr().unwrap();
    let (stop, receiver) = watch::channel(false);
    let serving = tokio::spawn(server.run_until(receiver));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packet = query(41, "ipv6.example", 1);
    client.send_to(&packet, address).await.unwrap();
    let (received, peer) = udp_receive(&upstream).await;
    upstream.send_to(&response(&received), peer).await.unwrap();
    assert_eq!(udp_receive(&client).await.0, response(&packet));
    client
        .send_to(&query(42, "bad-id.example", 1), address)
        .await
        .unwrap();
    let (received, peer) = udp_receive(&upstream).await;
    let mut wrong_id = response(&received);
    wrong_id[1] ^= 1;
    upstream.send_to(&wrong_id, peer).await.unwrap();
    let reply = udp_receive(&client).await.0;
    assert_eq!(&reply[..2], &42u16.to_be_bytes());
    assert_eq!(reply[3] & 0x0f, 2);
    stop.send(true).unwrap();
    bounded(serving).await.unwrap().unwrap();
}

#[tokio::test]
async fn dns_rejects_wrong_upstream_response_ids() {
    upstream_round_trip("127.0.0.1:0").await;
}

#[tokio::test]
#[cfg_attr(
    target_os = "windows",
    ignore = "requires a working IPv6 UDP loopback path; run explicitly on an IPv6-capable Windows host"
)]
async fn dns_supports_ipv6_upstreams() {
    upstream_round_trip("[::1]:0").await;
}

#[tokio::test]
async fn all_listeners_release_their_ports_and_children_for_twenty_restarts() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut proxy_address = "127.0.0.1:0".parse().unwrap();
    let mut dns_address = "127.0.0.1:0".parse().unwrap();
    let mut sni_address = "127.0.0.1:0".parse().unwrap();
    for iteration in 0..20 {
        let proxy = Arc::new(
            ProxyServer::bind(
                ProxyConfig {
                    listen: proxy_address,
                    ..Default::default()
                },
                handle(),
            )
            .await
            .unwrap(),
        );
        let dns = Arc::new(
            DnsServer::bind(
                DnsConfig {
                    listen: dns_address,
                    upstream: upstream.local_addr().unwrap(),
                    ..Default::default()
                },
                handle(),
            )
            .await
            .unwrap(),
        );
        let sni = Arc::new(
            SniListener::bind(
                SniConfig {
                    listen: sni_address,
                    ..Default::default()
                },
                handle(),
            )
            .await
            .unwrap(),
        );
        proxy_address = proxy.local_addr().unwrap();
        dns_address = dns.local_addr().unwrap();
        sni_address = sni.local_addr().unwrap();
        let (stop, receiver) = watch::channel(false);
        let proxy_task = tokio::spawn(proxy.clone().run_until(receiver.clone()));
        let dns_task = tokio::spawn(dns.clone().run_until(receiver.clone()));
        let sni_task = tokio::spawn(sni.clone().run_until(receiver));
        let mut proxy_client = TcpStream::connect(proxy_address).await.unwrap();
        let mut dns_client = TcpStream::connect(dns_address).await.unwrap();
        let mut sni_client = TcpStream::connect(sni_address).await.unwrap();
        proxy_client.write_all(b"G").await.unwrap();
        sni_client.write_all(b"\x16").await.unwrap();
        let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp_client
            .send_to(&query(iteration, "pending.example", 1), dns_address)
            .await
            .unwrap();
        udp_receive(&upstream).await; // An upstream child is now in flight.
        stop.send(true).unwrap();
        bounded(proxy_task).await.unwrap().unwrap();
        bounded(dns_task).await.unwrap().unwrap();
        bounded(sni_task).await.unwrap().unwrap();
        socket_closed(&mut proxy_client).await;
        socket_closed(&mut dns_client).await;
        socket_closed(&mut sni_client).await;
        // Server Arcs deliberately remain alive: completion alone must free
        // listeners, not require the UI to drop every retained server handle.
        let rebound_proxy = TcpListener::bind(proxy_address).await.unwrap();
        let rebound_dns_udp = UdpSocket::bind(dns_address).await.unwrap();
        let rebound_dns_tcp = TcpListener::bind(dns_address).await.unwrap();
        let rebound_sni = TcpListener::bind(sni_address).await.unwrap();
        drop((rebound_proxy, rebound_dns_udp, rebound_dns_tcp, rebound_sni));
    }
}

#[tokio::test]
async fn initially_stopped_and_dropped_senders_release_listeners() {
    for initial in [true, false] {
        let proxy = Arc::new(
            ProxyServer::bind(
                ProxyConfig {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    ..Default::default()
                },
                handle(),
            )
            .await
            .unwrap(),
        );
        let address = proxy.local_addr().unwrap();
        let (sender, receiver) = watch::channel(initial);
        if !initial {
            drop(sender);
        }
        bounded(proxy.clone().run_until(receiver)).await.unwrap();
        TcpListener::bind(address).await.unwrap();
    }
}
