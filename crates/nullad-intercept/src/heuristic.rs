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
                "doc",
                "documentation",
                "example",
                "examples",
                "tutorial",
                "tutorials",
                "auth",
                "oauth",
                "oauth2",
                "authorize",
                "authentication",
                "login",
                "signin",
                "sign-in",
                "signup",
                "sign-up",
                "logout",
                "signout",
                "account",
                "accounts",
                "session",
                "sessions",
                "checkout",
                "payment",
                "payments",
                "billing",
                "purchase",
                "cart",
                "captcha",
                "recaptcha",
            ],
        )
}

fn ad_query_schema(query: &str) -> bool {
    let mut placement = false;
    let mut generic_placement = false;
    let mut creative = false;
    let mut specific_creative = false;
    for parameter in query.split('&').take(64) {
        let Some((key, value)) = parameter.split_once('=') else {
            continue;
        };
        if value.trim().is_empty() {
            continue;
        }
        let key = decode_unreserved(key);
        match key.as_ref() {
            "adslot" | "ad_slot" | "adunit" | "ad_unit" | "adformat" | "ad_format"
            | "ad_placement" | "ad_placement_id" => placement = true,
            "placementid" | "placement_id" => generic_placement = true,
            "creativeid" | "creative_id" | "adid" | "ad_id" => {
                creative = true;
                specific_creative = true;
            }
            "campaignid" | "campaign_id" => creative = true,
            _ => {}
        }
    }
    (placement && creative) || (generic_placement && specific_creative)
}

fn ad_sdk_script(path: &str) -> bool {
    // Identifiable SDK filenames, not host reputation or generic words such as
    // gpt/analytics/ads. GPT and IMA also require their published loader paths:
    // developers.google.com/publisher-tag/guides/general-best-practices
    // developers.google.com/interactive-media-ads/docs/sdks/html5/client-side/get-started
    // docs.prebid.org/prebid/prebidjs.html
    let file = path.rsplit('/').next().unwrap_or_default();
    matches!(
        file,
        "adsbygoogle.js" | "adsbygoogle.min.js" | "prebid.js" | "prebid.min.js"
    ) || path.ends_with("/tag/js/gpt.js")
        || path.ends_with("/js/sdkloader/ima3.js")
}

fn ad_delivery_path(path: &str) -> bool {
    // Require a namespace/action pair. Bid, auction, click and display alone
    // occur in normal commerce and UI APIs and never supply this signal.
    let namespaces = [
        "ads",
        "ad",
        "adserver",
        "adserving",
        "ad-delivery",
        "advertising",
        "pagead",
        "openrtb",
        "openrtb2",
    ];
    let actions = [
        "serve",
        "show",
        "render",
        "display",
        "impression",
        "click",
        "delivery",
        "auction",
        "bid",
        "bids",
        "request",
    ];
    let mut namespace_before = false;
    for segment in path.split('/').filter(|segment| !segment.is_empty()) {
        let stem = segment.split('.').next().unwrap_or(segment);
        if namespace_before && actions.contains(&stem) {
            return true;
        }
        namespace_before = namespaces.contains(&stem);
    }
    false
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
    let delivery = ad_delivery_path(&path);
    let strong_path = delivery
        || has_path_token(
            &path,
            &[
                "adserver",
                "ad-serving",
                "adserving",
                "ad-delivery",
                "adrequest",
                "ad-request",
                "ad_request",
                "ad-loader",
                "ad_loader",
                "ad-banner",
                "ad_banner",
                "ad-impression",
                "ad_impression",
                "ad-auction",
                "ad_auction",
                "ad-bid",
                "ad_bid",
                "advertisement",
                "vast",
                "vmap",
            ],
        );
    let weak_path = has_path_token(&path, &["ads", "ad", "adslot", "ad-unit", "banner"]);
    let schema = ad_query_schema(query);
    let subresource = subresource(request.resource_type, &path);
    let third_party = request.page_host.is_some() && request.third_party;
    let sdk = request.resource_type.intersects(ResourceType::Script) && ad_sdk_script(&path);
    // Both modes require observed third-party context for SDK filenames. A
    // same-site or context-free file is not treated as an advertising SDK just
    // because it shares a loader name. Conservative delivery decisions also
    // require a third-party subresource rather than fabricated page context.
    if mode == HeuristicMode::Conservative {
        return (third_party
            && (sdk || (subresource && (delivery || (ad_host && (strong_path || schema))))))
            .then_some(Detection {
                reason: "heuristic_ad_request",
                score: 95,
            });
    }
    if (sdk && third_party)
        || (subresource
            && ((delivery && (third_party || ad_host || schema))
                || (schema && (third_party || ad_host))))
    {
        return Some(Detection {
            reason: "heuristic_ad_request",
            score: 90,
        });
    }
    // A cross-site ad-labelled host corroborates active script/frame/beacon
    // loading. Ordinary XHR, image and media URLs still need advertising paths
    // or structured ad parameters; generic metrics/telemetry hosts never count.
    if !strong_path
        && !weak_path
        && !schema
        && ad_host
        && third_party
        && request.resource_type.intersects(
            ResourceType::Script
                .union(ResourceType::Subdocument)
                .union(ResourceType::Ping),
        )
    {
        return Some(Detection {
            reason: "heuristic_ad_request",
            score: 80,
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
    fn advertising_sdks_need_exact_filename_path_type_and_third_party_context() {
        for mode in [HeuristicMode::Conservative, HeuristicMode::Balanced] {
            for path in [
                "/js/adsbygoogle.js",
                "/js/adsbygoogle.min.js",
                "/prebid.js",
                "/bundle/prebid.min.js",
                "/tag/js/gpt.js",
                "/js/sdkloader/ima3.js",
            ] {
                let url = format!("https://cdn.vendor.example{path}?v=7");
                assert!(
                    detected(
                        &url,
                        ResourceType::Script,
                        Some("https://publisher.example/"),
                        DecisionSource::Proxy,
                        mode
                    ),
                    "{path} {mode:?}"
                );
                for page in [None, Some("https://www.vendor.example/")] {
                    assert!(
                        !detected(
                            &url,
                            ResourceType::Script,
                            page,
                            DecisionSource::Proxy,
                            mode
                        ),
                        "{path} {page:?} {mode:?}"
                    );
                }
                for resource in [
                    ResourceType::Document,
                    ResourceType::Stylesheet,
                    ResourceType::Image,
                    ResourceType::Xhr,
                    ResourceType::Other,
                ] {
                    assert!(
                        !detected(
                            &url,
                            resource,
                            Some("https://publisher.example/"),
                            DecisionSource::Proxy,
                            mode
                        ),
                        "{path} {resource:?} {mode:?}"
                    );
                }
            }
            for path in [
                "/gpt.js",
                "/tag/gpt.js",
                "/js/gpt.js",
                "/sdk/ima3.js",
                "/js/sdkloader/ima3.js.map",
                "/prebidder.js",
                "/prebid.js.map",
                "/prebid.js.txt",
                "/prebid-client.js",
                "/myadsbygoogle.js",
                "/script.js?next=/prebid.js",
                "/js/%2570rebid.js",
            ] {
                assert!(
                    !detected(
                        &format!("https://cdn.vendor.example{path}"),
                        ResourceType::Script,
                        Some("https://publisher.example/"),
                        DecisionSource::Proxy,
                        mode
                    ),
                    "{path} {mode:?}"
                );
            }
        }
        assert!(!detected(
            "https://ads.vendor.example/tag/js/gpt.js",
            ResourceType::Script,
            Some("https://publisher.vendor.example/"),
            DecisionSource::Proxy,
            HeuristicMode::Balanced
        ));
        assert!(detected(
            "https://cdn.vendor.example/%70rebid.js",
            ResourceType::Script,
            Some("https://publisher.example/"),
            DecisionSource::Proxy,
            HeuristicMode::Balanced
        ));
    }

    #[test]
    fn delivery_and_bidding_paths_require_advertising_namespaces_and_context() {
        for path in [
            "/ads/serve",
            "/api/ads/render",
            "/pagead/impression.gif",
            "/adserver/auction",
            "/openrtb2/auction",
            "/openrtb/bid",
            "/ads/click?ad_slot=one&creative_id=two",
        ] {
            let url = format!("https://cdn.vendor.example{path}");
            for mode in [HeuristicMode::Conservative, HeuristicMode::Balanced] {
                assert!(
                    detected(
                        &url,
                        ResourceType::Xhr,
                        Some("https://publisher.example/"),
                        DecisionSource::Proxy,
                        mode
                    ),
                    "{path} {mode:?}"
                );
                assert!(!detected(
                    &url,
                    ResourceType::Document,
                    Some("https://publisher.example/"),
                    DecisionSource::Proxy,
                    mode
                ));
            }
        }
        for path in [
            "/api/auction",
            "/api/bid",
            "/products/display",
            "/ui/render",
            "/button/click",
            "/openrtb-doc/auction",
            "/notads/serve",
            "/ads/catalog/serve",
            "/%2561ds/serve",
            "/%61ds%2fserve",
            "/api?redirect=/ads/serve",
        ] {
            assert!(
                !detected(
                    &format!("https://cdn.vendor.example{path}"),
                    ResourceType::Xhr,
                    Some("https://publisher.example/"),
                    DecisionSource::Proxy,
                    HeuristicMode::Balanced
                ),
                "{path}"
            );
        }
        assert!(!detected(
            "https://cdn.vendor.example/ads/serve",
            ResourceType::Xhr,
            None,
            DecisionSource::Proxy,
            HeuristicMode::Balanced
        ));
        assert!(!detected(
            "https://cdn.vendor.example/ads/serve",
            ResourceType::Xhr,
            Some("https://publisher.vendor.example/"),
            DecisionSource::Proxy,
            HeuristicMode::Balanced
        ));
        assert!(detected(
            "https://cdn.vendor.example/ads/serve?placement_id=one&creative_id=two",
            ResourceType::Xhr,
            None,
            DecisionSource::Proxy,
            HeuristicMode::Balanced
        ));
    }

    #[test]
    fn placement_creative_queries_require_distinct_explicit_keys_with_values() {
        for query in [
            "ad_slot=top&creative_id=7",
            "placement_id=top&ad_id=7",
            "ad_placement_id=top&campaign_id=7",
            "%41D_UNIT=top&%43REATIVE_ID=7",
        ] {
            assert!(ad_query_schema(query), "{query}");
            assert!(
                detected(
                    &format!("https://cdn.vendor.example/content?{query}"),
                    ResourceType::Xhr,
                    Some("https://publisher.example/"),
                    DecisionSource::Proxy,
                    HeuristicMode::Balanced
                ),
                "{query}"
            );
            assert!(!detected(
                &format!("https://cdn.vendor.example/content?{query}"),
                ResourceType::Xhr,
                None,
                DecisionSource::Proxy,
                HeuristicMode::Balanced
            ));
        }
        for query in [
            "ad_slot=top",
            "creative_id=7",
            "ad_slot=top&ad_unit=side",
            "placement_id=top&campaign_id=7",
            "ad_slot=&creative_id=7",
            "ad_slot=top&creative_id=",
            "ad_slot&creative_id",
            "notad_slot=top&creative_id=7",
            "ad_slot=top&creative_ids=7",
            "next=ad_slot=top&then=creative_id=7",
            "%2541D_SLOT=top&creative_id=7",
        ] {
            assert!(!ad_query_schema(query), "{query}");
            assert!(
                !detected(
                    &format!("https://cdn.vendor.example/content?{query}"),
                    ResourceType::Xhr,
                    Some("https://publisher.example/"),
                    DecisionSource::Proxy,
                    HeuristicMode::Balanced
                ),
                "{query}"
            );
        }
        let beyond_budget = format!("{}ad_slot=top&creative_id=7", "x=1&".repeat(64));
        assert!(!ad_query_schema(&beyond_budget));
    }

    #[test]
    fn business_paths_navigation_and_hostname_only_sources_keep_their_protection() {
        for mode in [HeuristicMode::Conservative, HeuristicMode::Balanced] {
            for path in [
                "/docs/prebid.js",
                "/documentation/ads/serve",
                "/examples/tag/js/gpt.js",
                "/login/prebid.js",
                "/oauth/ads/serve",
                "/oauth2/openrtb/auction",
                "/auth/js/sdkloader/ima3.js",
                "/account/ads/serve",
                "/session/ads/serve",
                "/payments/ads/serve",
                "/billing/ads/serve",
                "/checkout/prebid.js",
                "/cart/ads/serve",
                "/captcha/tag/js/gpt.js",
            ] {
                assert!(
                    !detected(
                        &format!("https://cdn.vendor.example{path}?ad_slot=one&creative_id=two"),
                        ResourceType::Script,
                        Some("https://publisher.example/"),
                        DecisionSource::Proxy,
                        mode
                    ),
                    "{path} {mode:?}"
                );
            }
            for source in [
                DecisionSource::Dns,
                DecisionSource::Connect,
                DecisionSource::Sni,
            ] {
                for host in [
                    "ads.vendor.example",
                    "metrics.vendor.example",
                    "telemetry.vendor.example",
                    "adserver.github.io",
                    "adservice.pages.dev",
                ] {
                    assert!(
                        !detected(
                            &format!("https://{host}/tag/js/gpt.js?ad_slot=one&creative_id=two"),
                            ResourceType::Script,
                            Some("https://publisher.example/"),
                            source,
                            mode
                        ),
                        "{host} {source:?} {mode:?}"
                    );
                }
            }
        }
        for resource in [ResourceType::Xhr, ResourceType::Image, ResourceType::Media] {
            assert!(!detected(
                "https://ads.vendor.example/api/config",
                resource,
                Some("https://publisher.example/"),
                DecisionSource::Proxy,
                HeuristicMode::Balanced
            ));
        }
        for resource in [
            ResourceType::Script,
            ResourceType::Subdocument,
            ResourceType::Ping,
        ] {
            assert!(detected(
                "https://ads.vendor.example/delivery-config",
                resource,
                Some("https://publisher.example/"),
                DecisionSource::Proxy,
                HeuristicMode::Balanced
            ));
        }
    }

    #[test]
    fn new_http_signals_keep_explicit_allow_and_abp_exception_priority() {
        use crate::EngineHandle;
        use nullad_engine::{FilterEngine, RuleSetBuilder};
        use std::sync::Arc;
        let url = "https://cdn.vendor.example/tag/js/gpt.js";
        let page = Some("https://publisher.example/");
        let zero = EngineHandle::new(Arc::new(FilterEngine::new()));
        let detected = zero.evaluate(url, ResourceType::Script, page, DecisionSource::Proxy);
        assert!(detected.blocked);
        assert_eq!(detected.reason.as_deref(), Some("heuristic_ad_request"));
        assert!(detected.matched_rule.is_none());
        assert!(detected.matched_rule_ids.is_empty());
        assert_eq!(zero.stats.proxy_requests(), 0);
        assert_eq!(zero.engine.stats_snapshot().blocked, 0);
        assert!(
            !zero
                .clone()
                .with_policy(DetectionPolicy {
                    mode: HeuristicMode::Off,
                    allowed_hosts: Vec::new()
                })
                .evaluate(url, ResourceType::Script, page, DecisionSource::Proxy)
                .blocked
        );
        let mut builder = RuleSetBuilder::new();
        builder.add_list_auto("@@||cdn.vendor.example^$script");
        let handle = EngineHandle::new(Arc::new(FilterEngine::from_rule_set(
            builder.build().unwrap(),
        )));
        let exception = handle.evaluate(url, ResourceType::Script, page, DecisionSource::Proxy);
        assert!(!exception.blocked);
        assert!(exception.is_exception());
        assert_eq!(exception.reason.as_deref(), Some("exception"));
        let mut builder = RuleSetBuilder::new();
        builder.add_list_auto("||cdn.vendor.example^$important");
        let allowed = EngineHandle::new(Arc::new(FilterEngine::from_rule_set(
            builder.build().unwrap(),
        )))
        .with_policy(DetectionPolicy {
            mode: HeuristicMode::Balanced,
            allowed_hosts: vec!["vendor.example".into()],
        })
        .evaluate(url, ResourceType::Script, page, DecisionSource::Proxy);
        assert!(!allowed.blocked);
        assert_eq!(allowed.reason.as_deref(), Some("allow_host"));
        assert!(allowed.matched_rule.is_none());
    }

    #[tokio::test]
    async fn new_sdk_signal_reaches_real_http_decisions_without_subscription_rules() {
        use crate::{Decision, DecisionSink, EngineHandle, ProxyConfig, ProxyServer};
        use nullad_engine::{FilterEngine, RuleSetBuilder};
        use std::sync::{Arc, Mutex};
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};
        use tokio::sync::watch;

        #[derive(Debug, Default)]
        struct Collector(Mutex<Vec<Decision>>);
        impl DecisionSink for Collector {
            fn record(&self, decision: Decision) {
                self.0.lock().unwrap().push(decision);
            }
        }
        async fn head(stream: &mut TcpStream) -> String {
            let mut buffer = Vec::new();
            while !buffer.ends_with(b"\r\n\r\n") {
                buffer.push(stream.read_u8().await.unwrap());
                assert!(buffer.len() < 16384);
            }
            String::from_utf8(buffer).unwrap()
        }
        for scenario in 0..4 {
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = upstream.local_addr().unwrap();
            let fixture = if scenario == 0 {
                None
            } else {
                Some(tokio::spawn(async move {
                    let (mut stream, _) = upstream.accept().await.unwrap();
                    assert!(head(&mut stream)
                        .await
                        .starts_with("GET http://cdn.vendor.example/tag/js/gpt.js HTTP/1.1\r\n"));
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                        )
                        .await
                        .unwrap();
                    stream.shutdown().await.unwrap();
                }))
            };
            let engine = if scenario < 2 {
                Arc::new(FilterEngine::new())
            } else {
                let mut builder = RuleSetBuilder::new();
                builder.add_list_auto(if scenario == 2 {
                    "@@||cdn.vendor.example^$script"
                } else {
                    "||cdn.vendor.example^$important"
                });
                Arc::new(FilterEngine::from_rule_set(builder.build().unwrap()))
            };
            let collector = Arc::new(Collector::default());
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
                ProxyServer::bind(
                    ProxyConfig {
                        listen: "127.0.0.1:0".parse().unwrap(),
                        upstream: Some(format!("http://{endpoint}").parse().unwrap()),
                        ..Default::default()
                    },
                    handle.clone(),
                )
                .await
                .unwrap(),
            );
            let address = server.local_addr().unwrap();
            let (stop, receiver) = watch::channel(false);
            let serving = tokio::spawn(server.run_until(receiver));
            let mut client = TcpStream::connect(address).await.unwrap();
            let destination = if scenario == 1 { "document" } else { "script" };
            client.write_all(format!("GET http://cdn.vendor.example/tag/js/gpt.js HTTP/1.1\r\nHost: cdn.vendor.example\r\nSec-Fetch-Dest: {destination}\r\nReferer: https://publisher.example/\r\n\r\n").as_bytes()).await.unwrap();
            let mut reply = String::new();
            tokio::time::timeout(Duration::from_secs(5), client.read_to_string(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert!(
                reply.starts_with(if scenario == 0 {
                    "HTTP/1.1 403"
                } else {
                    "HTTP/1.1 200"
                }),
                "{scenario}: {reply}"
            );
            if let Some(fixture) = fixture {
                tokio::time::timeout(Duration::from_secs(5), fixture)
                    .await
                    .unwrap()
                    .unwrap();
            }
            if scenario < 2 {
                assert_eq!(handle.engine.rule_count(), 0);
            }
            {
                let events = collector.0.lock().unwrap();
                assert_eq!(events.len(), 1);
                assert_eq!(events[0].source, DecisionSource::Proxy);
                assert_eq!(events[0].blocked, scenario == 0);
                assert_eq!(
                    events[0].reason.as_deref(),
                    [
                        Some("heuristic_ad_request"),
                        None,
                        Some("exception"),
                        Some("allow_host")
                    ][scenario]
                );
                assert_eq!(events[0].rule.is_some(), scenario == 2);
                assert_eq!(events[0].score.is_some(), scenario == 0);
            }
            assert_eq!(handle.stats.proxy_requests(), 1);
            assert_eq!(handle.stats.proxy_blocked(), u64::from(scenario == 0));
            stop.send(true).unwrap();
            tokio::time::timeout(Duration::from_secs(5), serving)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
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
