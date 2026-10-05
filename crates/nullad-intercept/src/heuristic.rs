//! Bounded, offline advertising features. No domain reputation list or remote lookup.
//!
//! These are deliberately selective: an isolated word such as `ads`, `banner`,
//! `metrics` or `track` is not enough. Scores describe feature strength, not a
//! calibrated probability, and encrypted connection decisions use hostname only.

use nullad_api::HeuristicMode;
use nullad_engine::{Request, ResourceType};
use std::borrow::Cow;

use crate::DecisionSource;

/// Additional interception policy independent of downloaded rule lists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetectionPolicy {
    pub mode: HeuristicMode,
    pub allowed_hosts: Vec<String>,
}

impl DetectionPolicy {
    /// Explicit domains include their subdomains, only on label boundaries.
    /// An IP literal matches exactly; wildcard and URL entries are not accepted.
    #[must_use]
    pub fn allows_host(&self, host: &str) -> bool {
        self.allowed_hosts.iter().any(|allowed| {
            let allowed = allowed.trim().trim_end_matches('.');
            let ip_literal = if allowed.starts_with('[') {
                allowed
                    .strip_prefix('[')
                    .and_then(|value| value.strip_suffix(']'))
            } else {
                Some(allowed)
            };
            if let Some(allowed_ip) =
                ip_literal.and_then(|value| value.parse::<std::net::IpAddr>().ok())
            {
                return host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    == Ok(allowed_ip);
            }
            // Settings and with_policy normalize IDN once. Matching performs no
            // allocation and rejects URL/wildcard/port entries rather than
            // silently broadening the explicitly permitted scope.
            if allowed.is_empty()
                || !allowed
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
            {
                return false;
            }
            host.eq_ignore_ascii_case(allowed)
                || (host.len() > allowed.len()
                    && host.as_bytes()[host.len() - allowed.len() - 1] == b'.'
                    && host
                        .get(host.len() - allowed.len()..)
                        .is_some_and(|suffix| suffix.eq_ignore_ascii_case(allowed)))
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Detection {
    pub reason: &'static str,
    pub score: u8,
}

const AD_SERVICE_LABELS: &[&str] = &[
    "adserver",
    "adservers",
    "adserving",
    "ad-serving",
    "adservice",
    "adservices",
    "ad-delivery",
    "adnetwork",
    "adnetworks",
    "adexchange",
    "adexchanges",
];

fn is_ip(host: &str) -> bool {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .is_ok()
}

fn safe_host(host: &str) -> bool {
    host.is_empty()
        || is_ip(host)
        || !host.contains('.')
        || host == "localhost"
        || [".localhost", ".local", ".lan", ".internal", ".home"]
            .iter()
            .any(|suffix| host.ends_with(suffix))
        || host
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')))
}

fn service_host(host: &str) -> bool {
    // Require a service subdomain, never a registrable site's name itself.
    // Include PSL private suffixes (github.io, pages.dev, etc.). A hosted
    // user's apex must not become a whole-site DNS/CONNECT/SNI block. The
    // embedded PSL performs no network lookup and does not change ABP party
    // matching, which retains its established engine semantics.
    psl::domain_str(host).is_some_and(|domain| host != domain)
        && host
            .split('.')
            .next()
            .is_some_and(|label| AD_SERVICE_LABELS.contains(&label))
}

fn advertising_host(host: &str) -> bool {
    psl::domain_str(host).is_some_and(|domain| host != domain)
        && matches!(host.split('.').next(), Some("ads" | "ad"))
}

/// Extract path and query from an absolute URL without inspecting arbitrary
/// nested URL/query values. Only ASCII unreserved escapes are decoded once.
fn path_and_query(url: &str) -> Option<(Cow<'_, str>, &str)> {
    let (_, authority) = url.split_once("://")?;
    let end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
    let tail = authority.get(end..)?;
    let without_fragment = tail.split('#').next()?;
    let (path, query) = without_fragment
        .split_once('?')
        .unwrap_or((without_fragment, ""));
    let path = if path.is_empty() { "/" } else { path };
    if path.len() > 8192 || query.len() > 8192 {
        return None;
    }
    Some((decode_unreserved(path), query))
}

/// Decode ASCII unreserved escapes once and lowercase ASCII in the same pass.
/// Borrow the original input when neither operation would change its bytes.
fn decode_unreserved(value: &str) -> Cow<'_, str> {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    fn decoded_at(bytes: &[u8], offset: usize) -> Option<u8> {
        bytes.get(offset..offset + 3).and_then(|triplet| {
            if triplet[0] != b'%' {
                return None;
            }
            let byte = hex(triplet[1])? * 16 + hex(triplet[2])?;
            (byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
                .then_some(byte)
        })
    }
    let bytes = value.as_bytes();
    let mut offset = 0;
    while offset < bytes.len()
        && !bytes[offset].is_ascii_uppercase()
        && decoded_at(bytes, offset).is_none()
    {
        offset += 1;
    }
    if offset == bytes.len() {
        return Cow::Borrowed(value);
    }
    // Both possible changes start at ASCII characters, so this prefix ends on
    // a UTF-8 boundary. Capacity cannot grow: decoding only shortens the input.
    let mut output = Vec::with_capacity(bytes.len());
    output.extend_from_slice(&bytes[..offset]);
    while offset < bytes.len() {
        if let Some(byte) = decoded_at(bytes, offset) {
            output.push(byte.to_ascii_lowercase());
            offset += 3;
        } else {
            output.push(bytes[offset].to_ascii_lowercase());
            offset += 1;
        }
    }
    // The original UTF-8 is copied intact, with only complete ASCII sequences replaced.
    Cow::Owned(String::from_utf8(output).expect("decoding ASCII escapes preserves UTF-8"))
}

fn has_path_token(path: &str, tokens: &[&str]) -> bool {
    path.split('/').any(|segment| {
        let stem = segment.split('.').next().unwrap_or(segment);
        tokens.contains(&stem)
    })
}

fn protected_path(path: &str) -> bool {
    matches!(path, "/ads.txt" | "/app-ads.txt" | "/sellers.json")
        || has_path_token(
            path,
            &[
                "docs",
                "documentation",
                "examples",
                "tutorial",
                "login",
                "signin",
                "checkout",
                "payment",
                "captcha",
            ],
        )
}

fn ad_query_schema(query: &str) -> bool {
    let mut placement = false;
    let mut creative = false;
    for parameter in query.split('&').take(64) {
        let key = parameter.split('=').next().unwrap_or("");
        let key = decode_unreserved(key);
        match key.as_ref() {
            "adslot" | "ad_slot" | "adunit" | "ad_unit" | "adformat" | "ad_format" => {
                placement = true
            }
            "creativeid" | "creative_id" | "adid" | "ad_id" | "campaignid" | "campaign_id" => {
                creative = true
            }
            _ => {}
        }
    }
    placement && creative
}

fn subresource(resource: ResourceType, path: &str) -> bool {
    resource.intersects(
        ResourceType::Script
            .union(ResourceType::Image)
            .union(ResourceType::Subdocument)
            .union(ResourceType::Xhr)
            .union(ResourceType::Media)
            .union(ResourceType::Ping),
    ) || (resource == ResourceType::Other
        && [
            ".js", ".mjs", ".png", ".gif", ".jpg", ".jpeg", ".webp", ".svg", ".mp4", ".webm",
        ]
        .iter()
        .any(|suffix| path.ends_with(suffix)))
}

pub(crate) fn detect(
    request: &Request,
    source: DecisionSource,
    mode: HeuristicMode,
) -> Option<Detection> {
    if mode == HeuristicMode::Off || safe_host(&request.host) {
        return None;
    }
    let dedicated_host = service_host(&request.host);
    if source != DecisionSource::Proxy {
        return dedicated_host.then_some(Detection {
            reason: "heuristic_ad_host",
            score: 85,
        });
    }
    // Never infer that a top-level navigation is an advertising subresource.
    if request.resource_type.intersects(ResourceType::Document) {
        return None;
    }
    let (path, query) = path_and_query(&request.url)?;
    if protected_path(&path) {
        return None;
    }
    if dedicated_host {
        return Some(Detection {
            reason: "heuristic_ad_host",
            score: 85,
        });
    }
    let ad_host = advertising_host(&request.host);
    let strong_path = has_path_token(
        &path,
        &[
            "adserver",
            "ad-serving",
            "adserving",
            "ad-delivery",
            "adrequest",
            "ad-request",
            "ad-loader",
            "ad-banner",
            "advertisement",
            "vast",
            "vmap",
        ],
    );
    let weak_path = has_path_token(&path, &["ads", "ad", "adslot", "ad-unit", "banner"]);
    let schema = ad_query_schema(query);
    let subresource = subresource(request.resource_type, &path);
    let third_party = request.page_host.is_some() && request.third_party;
    // Conservative HTTP decisions require both explicit host/path advertising
    // semantics and a third-party subresource. Missing context is not fabricated.
    if mode == HeuristicMode::Conservative {
        return (ad_host && strong_path && subresource && third_party).then_some(Detection {
            reason: "heuristic_ad_request",
            score: 95,
        });
    }
    let score: u8 = (if ad_host { 30 } else { 0 })
        + (if strong_path {
            40
        } else if weak_path {
            15
        } else {
            0
        })
        + (if schema { 25 } else { 0 })
        + (if subresource { 15 } else { 0 })
        + (if third_party { 20 } else { 0 });
    // Require an advertising path and either specific ad-query structure or
    // corroborating host/source context, rather than accumulated generic words.
    ((strong_path || weak_path) && subresource && score >= 75).then_some(Detection {
        reason: "heuristic_ad_request",
        score: score.min(100),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detected(
        url: &str,
        resource: ResourceType,
        page: Option<&str>,
        source: DecisionSource,
        mode: HeuristicMode,
    ) -> bool {
        let mut request = Request::new(url, resource);
        if let Some(page) = page {
            request = request.with_page(page);
        }
        detect(&request, source, mode).is_some()
    }

    #[test]
    fn host_only_requires_dedicated_service_labels() {
        for source in [
            DecisionSource::Dns,
            DecisionSource::Sni,
            DecisionSource::Connect,
        ] {
            for mode in [HeuristicMode::Conservative, HeuristicMode::Balanced] {
                assert!(detected(
                    "https://adserver.vendor.example/",
                    ResourceType::Document,
                    None,
                    source,
                    mode
                ));
                for host in [
                    "ads.vendor.example",
                    "metrics.vendor.example",
                    "telemetry.vendor.example",
                    "adserver.com",
                    "download.example",
                    "shadow.example",
                    "advice.example",
                    "adserver.local",
                    "127.0.0.1",
                    "[::1]",
                ] {
                    assert!(
                        !detected(
                            &format!("https://{host}/"),
                            ResourceType::Document,
                            None,
                            source,
                            mode
                        ),
                        "{host}"
                    );
                }
            }
        }
    }

    #[test]
    fn balanced_combines_http_features_and_modes_are_distinct() {
        let url = "http://ads.vendor.example/banner.gif";
        assert!(detected(
            url,
            ResourceType::Image,
            Some("https://publisher.example/"),
            DecisionSource::Proxy,
            HeuristicMode::Balanced
        ));
        assert!(!detected(
            url,
            ResourceType::Image,
            None,
            DecisionSource::Proxy,
            HeuristicMode::Balanced
        ));
        assert!(!detected(
            url,
            ResourceType::Image,
            Some("https://publisher.example/"),
            DecisionSource::Proxy,
            HeuristicMode::Conservative
        ));
        assert!(detected(
            "http://ads.vendor.example/ad-loader.js",
            ResourceType::Script,
            Some("https://publisher.example/"),
            DecisionSource::Proxy,
            HeuristicMode::Conservative
        ));
        assert!(detected(
            "http://cdn.vendor.example/vast?ad_slot=video&creative_id=42",
            ResourceType::Xhr,
            Some("https://publisher.example/"),
            DecisionSource::Proxy,
            HeuristicMode::Balanced
        ));
        assert!(!detected(
            url,
            ResourceType::Image,
            Some("https://publisher.example/"),
            DecisionSource::Proxy,
            HeuristicMode::Off
        ));
    }

    #[test]
    fn navigation_documentation_and_generic_tracking_are_protected() {
        for url in [
            "http://adserver.vendor.example/",
            "http://ads.vendor.example/banner.gif",
        ] {
            assert!(!detected(
                url,
                ResourceType::Document,
                Some("https://publisher.example"),
                DecisionSource::Proxy,
                HeuristicMode::Balanced
            ));
        }
        for path in [
            "/ads.txt",
            "/app-ads.txt",
            "/sellers.json",
            "/docs/ad-loader.js",
            "/examples/vast.js",
            "/checkout/ad-banner.js",
            "/login/ad-request.js",
        ] {
            assert!(
                !detected(
                    &format!("http://adserver.vendor.example{path}"),
                    ResourceType::Script,
                    Some("https://publisher.example"),
                    DecisionSource::Proxy,
                    HeuristicMode::Balanced
                ),
                "{path}"
            );
        }
        for url in [
            "http://cdn.vendor.example/banner.gif",
            "http://metrics.vendor.example/collect?campaign_id=42",
            "http://vendor.example/downloads.js",
            "http://cdn.vendor.example/track?url=https://ads.example/ad-banner.js",
            "http://vendor.example/search?q=advertisement",
        ] {
            assert!(
                !detected(
                    url,
                    ResourceType::Image,
                    Some("https://publisher.example"),
                    DecisionSource::Proxy,
                    HeuristicMode::Balanced
                ),
                "{url}"
            );
        }
    }

    #[test]
    fn path_tokens_query_groups_and_encoding_have_boundaries() {
        assert!(detected(
            "http://ads.vendor.example/%61d-loader.js",
            ResourceType::Script,
            None,
            DecisionSource::Proxy,
            HeuristicMode::Balanced
        ));
        for url in [
            "http://ads.vendor.example/download.js",
            "http://vendor.example/advertisement.js?adslot=1&ad_unit=2",
            "http://ads.vendor.example/%2561d-loader.js",
            "http://cdn.vendor.example/vast?url=https://x/ad_slot=1&something=creative_id=2",
        ] {
            assert!(
                !detected(
                    url,
                    ResourceType::Script,
                    None,
                    DecisionSource::Proxy,
                    HeuristicMode::Balanced
                ),
                "{url}"
            );
        }
    }

    #[test]
    fn unchanged_paths_and_query_keys_borrow_the_original_input() {
        for value in [
            "",
            "/ad-loader.js",
            "ad_slot",
            "creative_id",
            "/广告/é.js",
            "/%2f/%ff/%25/%zz",
        ] {
            let decoded = decode_unreserved(value);
            assert!(matches!(decoded, Cow::Borrowed(_)), "{value}");
            assert_eq!(decoded.as_ptr(), value.as_ptr());
            assert_eq!(decoded, value);
        }
        let (path, query) =
            path_and_query("http://example.com/ad-loader.js?ad_slot=1#ignored").unwrap();
        assert!(matches!(path, Cow::Borrowed("/ad-loader.js")));
        assert_eq!(query, "ad_slot=1");
        assert_eq!(
            path_and_query("http://example.com?x=1").unwrap(),
            (Cow::Borrowed("/"), "x=1")
        );
    }

    #[test]
    fn escaped_and_uppercase_inputs_keep_unicode_and_decode_only_once() {
        for (input, expected) in [
            ("/AD-LOADER.JS", "/ad-loader.js"),
            ("/%41d%5FUNIT.js", "/ad_unit.js"),
            ("/ÜBER/%C3%84/%2541/%41/%2F", "/Über/%c3%84/%2541/a/%2f"),
            ("/广告/Ä%61.JS", "/广告/Äa.js"),
            ("/%/%4/%G1/%4Z", "/%/%4/%g1/%4z"),
        ] {
            let decoded = decode_unreserved(input);
            assert!(matches!(decoded, Cow::Owned(_)), "{input}");
            assert_eq!(decoded, expected);
        }
        assert!(ad_query_schema("%41D_SLOT=one&CREATIVE%5FID=two"));
        assert!(!ad_query_schema("%2541D_SLOT=one&CREATIVE_ID=two"));
    }

    #[test]
    fn every_percent_byte_retains_the_previous_decoding_semantics() {
        // Reference the former decode-then-to_ascii_lowercase transformation.
        fn previous(value: &str) -> String {
            let bytes = value.as_bytes();
            let mut output = Vec::new();
            let mut offset = 0;
            while offset < bytes.len() {
                let decoded = bytes.get(offset..offset + 3).and_then(|triplet| {
                    if triplet[0] != b'%' {
                        return None;
                    }
                    let hex = std::str::from_utf8(&triplet[1..]).ok()?;
                    let byte = u8::from_str_radix(hex, 16).ok()?;
                    (byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
                        .then_some(byte)
                });
                if let Some(byte) = decoded {
                    output.push(byte);
                    offset += 3;
                } else {
                    output.push(bytes[offset]);
                    offset += 1;
                }
            }
            String::from_utf8(output).unwrap().to_ascii_lowercase()
        }
        for byte in 0..=255 {
            for prefix in ["", "Ä/广告/"] {
                let input = format!("{prefix}%{byte:02X}/Ad_Loader/%2561/%2F");
                assert_eq!(decode_unreserved(&input), previous(&input), "{input}");
            }
        }
    }

    #[test]
    fn hosted_apex_is_not_an_ad_service_subdomain() {
        for host in [
            "adserver.github.io",
            "adservice.pages.dev",
            "ads.github.io",
            "adserver.com",
            "github.io",
        ] {
            assert!(!service_host(host), "{host}");
            assert!(!advertising_host(host), "{host}");
            for source in [
                DecisionSource::Connect,
                DecisionSource::Dns,
                DecisionSource::Sni,
            ] {
                assert!(
                    !detected(
                        &format!("https://{host}/"),
                        ResourceType::Other,
                        None,
                        source,
                        HeuristicMode::Balanced
                    ),
                    "{host} {source:?}"
                );
            }
        }
        assert!(service_host("adserver.publisher.github.io"));
        assert!(service_host("adservice.publisher.pages.dev"));
        assert!(advertising_host("ads.publisher.github.io"));
    }

    #[test]
    fn allowed_domains_match_only_exact_hosts_or_label_boundaries() {
        let policy = DetectionPolicy {
            mode: HeuristicMode::Balanced,
            allowed_hosts: vec![
                "EXAMPLE.com.".into(),
                "[::1]".into(),
                "*.invalid".into(),
                "port.example:443".into(),
                "https://url.example/".into(),
                "xn--bcher-kva.example".into(),
            ],
        };
        for host in [
            "example.com",
            "ADS.EXAMPLE.COM",
            "[::1]",
            "[0:0:0:0:0:0:0:1]",
            "xn--bcher-kva.example",
            "ads.xn--bcher-kva.example",
        ] {
            assert!(policy.allows_host(host));
        }
        for host in [
            "notexample.com",
            "example.com.evil",
            "evil.[::1]",
            "other.invalid",
            "[::2]",
            "port.example",
            "url.example",
            "notxn--bcher-kva.example",
            "xn--bcher-kva.example.evil",
        ] {
            assert!(!policy.allows_host(host));
        }
    }
}
