//! Offline heuristic decisions over real sockets, with local upstreams only.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nullad_engine::{FilterEngine, RuleSetBuilder};
use nullad_intercept::{
    Decision, DecisionSink, DecisionSource, DetectionPolicy, DnsConfig, DnsServer, EngineHandle,
    HeuristicMode, ProxyConfig, ProxyServer,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;

#[derive(Debug, Default)]
struct Collector(Mutex<Vec<Decision>>);

impl DecisionSink for Collector {
    fn record(&self, decision: Decision) {
        self.0.lock().unwrap().push(decision);
    }
}

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("local socket operation timed out")
}

async fn head(stream: &mut TcpStream) -> String {
    let mut buffer = Vec::new();
    while !buffer.ends_with(b"\r\n\r\n") {
        buffer.push(bounded(stream.read_u8()).await.unwrap());
        assert!(buffer.len() < 16384);
    }
    String::from_utf8(buffer).unwrap()
}

async fn http_request(
    address: std::net::SocketAddr,
    host: &str,
    path: &str,
    headers: &str,
) -> String {
    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(
            format!("GET http://{host}{path} HTTP/1.1\r\nHost: {host}\r\n{headers}\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut response = String::new();
    bounded(client.read_to_string(&mut response)).await.unwrap();
    response
}

#[tokio::test]
async fn zero_rule_http_combines_context_and_protects_navigation_and_generic_tracking() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let fixture = tokio::spawn(async move {
        let mut forwarded = Vec::new();
        for _ in 0..4 {
            let (mut stream, _) = bounded(upstream.accept()).await.unwrap();
            forwarded.push(head(&mut stream).await);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        }
        forwarded
    });
    let collector = Arc::new(Collector::default());
    let handle = EngineHandle::new(Arc::new(FilterEngine::new())).with_sink(collector.clone());
    let server = Arc::new(
        ProxyServer::bind(
            ProxyConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstream: Some(format!("http://{upstream_address}").parse().unwrap()),
                ..Default::default()
            },
            handle.clone(),
        )
        .await
        .unwrap(),
    );
    let address = server.local_addr().unwrap();
    let (stop, receiver) = watch::channel(false);
    let task = tokio::spawn(server.run_until(receiver));
    let cases = [
        (
            "ads.vendor.example",
            "/banner.gif",
            "Sec-Fetch-Dest: image\r\n",
            false,
            None,
        ),
        (
            "ads.vendor.example",
            "/banner.gif",
            "Sec-Fetch-Dest: image\r\nReferer: https://publisher.example/\r\n",
            true,
            Some("heuristic_ad_request"),
        ),
        (
            "telemetry.vendor.example",
            "/collect?campaign_id=42",
            "Sec-Fetch-Dest: empty\r\nOrigin: https://publisher.example\r\n",
            false,
            None,
        ),
        (
            "adserver.vendor.example",
            "/ad-loader.js",
            "Sec-Fetch-Dest: document\r\nReferer: https://publisher.example/\r\n",
            false,
            None,
        ),
        (
            "adserver.vendor.example",
            "/ad-loader.js",
            "Sec-Fetch-Dest: script\r\n",
            true,
            Some("heuristic_ad_host"),
        ),
        (
            "ads.vendor.example",
            "/ad-loader.js",
            "Sec-Fetch-Dest: script\r\nOrigin: https://publisher.example\r\n",
            true,
            Some("heuristic_ad_request"),
        ),
        (
            "adserver.vendor.example",
            "/docs/ad-loader.js",
            "Sec-Fetch-Dest: script\r\nReferer: https://publisher.example/\r\n",
            false,
            None,
        ),
    ];
    for (host, path, headers, blocked, reason) in cases {
        let response = http_request(address, host, path, headers).await;
        assert!(
            response.starts_with(if blocked {
                "HTTP/1.1 403"
            } else {
                "HTTP/1.1 200"
            }),
            "{host}{path}: {response}"
        );
        let events = collector.0.lock().unwrap();
        let event = events.last().unwrap();
        assert_eq!(event.blocked, blocked);
        assert_eq!(event.reason.as_deref(), reason);
        assert!(event.rule.is_none());
        assert_eq!(event.source, DecisionSource::Proxy);
    }
    let forwarded = bounded(fixture).await.unwrap();
    assert_eq!(forwarded.len(), 4);
    assert_eq!(handle.engine.rule_count(), 0);
    assert_eq!(handle.engine.stats_snapshot().queries, 7);
    assert_eq!(handle.engine.stats_snapshot().blocked, 0);
    assert_eq!(handle.stats.proxy_requests(), 7);
    assert_eq!(handle.stats.proxy_blocked(), 3);
    stop.send(true).unwrap();
    bounded(task).await.unwrap().unwrap();
}

#[tokio::test]
async fn http_rule_exception_and_explicit_allow_forward_through_local_upstream() {
    for explicit in [false, true] {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = upstream.local_addr().unwrap();
        let fixture = tokio::spawn(async move {
            let (mut stream, _) = bounded(upstream.accept()).await.unwrap();
            assert!(head(&mut stream)
                .await
                .starts_with("GET http://adserver.vendor.example/ad-loader.js HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut builder = RuleSetBuilder::new();
        builder.add_list_auto(if explicit {
            "||adserver.vendor.example^$important"
        } else {
            "@@||adserver.vendor.example^"
        });
        let collector = Arc::new(Collector::default());
        let handle = EngineHandle::new(Arc::new(FilterEngine::from_rule_set(
            builder.build().unwrap(),
        )))
        .with_policy(DetectionPolicy {
            mode: HeuristicMode::Balanced,
            allowed_hosts: if explicit {
                vec!["vendor.example".into()]
            } else {
                Vec::new()
            },
        })
        .with_sink(collector.clone());
        let server = Arc::new(
            ProxyServer::bind(
                ProxyConfig {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    upstream: Some(format!("http://{endpoint}").parse().unwrap()),
                    ..Default::default()
                },
                handle,
            )
            .await
            .unwrap(),
        );
        let address = server.local_addr().unwrap();
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(server.run_until(receiver));
        assert!(http_request(
            address,
            "adserver.vendor.example",
            "/ad-loader.js",
            "Sec-Fetch-Dest: script\r\n"
        )
        .await
        .starts_with("HTTP/1.1 200"));
        bounded(fixture).await.unwrap();
        {
            let events = collector.0.lock().unwrap();
            assert_eq!(events.len(), 1);
            assert!(!events[0].blocked);
            assert_eq!(
                events[0].reason.as_deref(),
                Some(if explicit { "allow_host" } else { "exception" })
            );
            assert_eq!(events[0].rule.is_some(), !explicit);
            assert!(events[0].score.is_none());
        }
        stop.send(true).unwrap();
        bounded(task).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn zero_rule_connect_uses_only_host_and_records_proxy_counters() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let collector = Arc::new(Collector::default());
    let handle = EngineHandle::new(Arc::new(FilterEngine::new())).with_sink(collector.clone());
    let server = Arc::new(
        ProxyServer::bind(
            ProxyConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstream: Some(
                    format!("http://{}", upstream.local_addr().unwrap())
                        .parse()
                        .unwrap(),
                ),
                ..Default::default()
            },
            handle.clone(),
        )
        .await
        .unwrap(),
    );
    let address = server.local_addr().unwrap();
    let (stop, receiver) = watch::channel(false);
    let task = tokio::spawn(server.run_until(receiver));
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(b"CONNECT adserver.vendor.example:443 HTTP/1.1\r\nHost: adserver.vendor.example:443\r\n\r\n").await.unwrap();
    let mut response = String::new();
    bounded(client.read_to_string(&mut response)).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 403"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), upstream.accept())
            .await
            .is_err()
    );
    assert_eq!(handle.stats.proxy_requests(), 1);
    assert_eq!(handle.stats.proxy_blocked(), 1);
    let event = collector.0.lock().unwrap()[0].clone();
    assert_eq!(event.source, DecisionSource::Connect);
    assert_eq!(event.reason.as_deref(), Some("heuristic_ad_host"));
    assert!(event.rule.is_none());
    stop.send(true).unwrap();
    bounded(task).await.unwrap().unwrap();
}

fn query(host: &str) -> Vec<u8> {
    let mut packet = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in host.split('.') {
        packet.push(u8::try_from(label.len()).unwrap());
        packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    packet
}

#[tokio::test]
async fn dns_zero_rules_blocks_only_dedicated_hosts_and_respects_exception_and_allow() {
    for scenario in 0..4 {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let collector = Arc::new(Collector::default());
        let engine = if scenario < 2 {
            Arc::new(FilterEngine::new())
        } else {
            let mut builder = RuleSetBuilder::new();
            builder.add_list_auto(if scenario == 2 {
                "@@||adserver.vendor.example^"
            } else {
                "||adserver.vendor.example^$important"
            });
            Arc::new(FilterEngine::from_rule_set(builder.build().unwrap()))
        };
        let handle = EngineHandle::new(engine)
            .with_policy(DetectionPolicy {
                mode: HeuristicMode::Balanced,
                allowed_hosts: if scenario == 3 {
                    vec!["vendor.example".into()]
                } else {
                    Vec::new()
                },
            })
            .with_sink(collector.clone());
        let server = Arc::new(
            DnsServer::bind(
                DnsConfig {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    upstream: upstream.local_addr().unwrap(),
                    ..Default::default()
                },
                handle.clone(),
            )
            .await
            .unwrap(),
        );
        let address = server.local_addr().unwrap();
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(server.run_until(receiver));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let packet = query(if scenario == 1 {
            "ads.vendor.example"
        } else {
            "adserver.vendor.example"
        });
        client.send_to(&packet, address).await.unwrap();
        let mut buffer = [0; 512];
        if scenario == 0 {
            let (length, _) = bounded(client.recv_from(&mut buffer)).await.unwrap();
            assert_eq!(&buffer[length - 4..length], &[0, 0, 0, 0]);
            assert_eq!(u16::from_be_bytes([buffer[6], buffer[7]]), 1);
            assert!(tokio::time::timeout(
                Duration::from_millis(100),
                upstream.recv_from(&mut buffer)
            )
            .await
            .is_err());
            assert_eq!(handle.engine.rule_count(), 0);
            assert_eq!(handle.stats.dns_blocked(), 1);
        } else {
            let (length, peer) = bounded(upstream.recv_from(&mut buffer)).await.unwrap();
            assert_eq!(&buffer[..length], packet.as_slice());
            let mut response = packet.clone();
            response[2] |= 0x80;
            upstream.send_to(&response, peer).await.unwrap();
            let (length, _) = bounded(client.recv_from(&mut buffer)).await.unwrap();
            assert_eq!(&buffer[..length], response.as_slice());
            assert_eq!(handle.stats.dns_forwarded(), 1);
        }
        {
            let events = collector.0.lock().unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].source, DecisionSource::Dns);
            assert_eq!(events[0].blocked, scenario == 0);
            let expected = [
                Some("heuristic_ad_host"),
                None,
                Some("exception"),
                Some("allow_host"),
            ][scenario];
            assert_eq!(events[0].reason.as_deref(), expected);
            assert_eq!(events[0].rule.is_some(), scenario == 2);
        }
        stop.send(true).unwrap();
        bounded(task).await.unwrap().unwrap();
    }
}
