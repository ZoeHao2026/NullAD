//! The request model and its URL parsing helpers.

use crate::rule::ResourceType;
/// A network request reduced to the fields the engine needs to decide on.
///
/// Constructing a `Request` is deliberately cheap: the URL is parsed once for
/// its host and scheme, and the lowercase URL text is produced on demand and
/// cached by the caller's `MatchScratch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The full URL as observed on the wire.
    pub url: String,
    /// The URL's hostname, lowercase, without a port.
    pub host: String,
    /// The resource type being fetched.
    pub resource_type: ResourceType,
    /// Hostname of the page that initiated this request, if known.
    pub page_host: Option<String>,
    /// Whether the request target differs in domain from the initiator.
    pub third_party: bool,
}

impl Request {
    /// Builds a request from a URL and resource type.
    ///
    /// Host and third-party status are derived automatically. If the URL cannot
    /// be parsed the host is left empty, which means domain-anchored rules
    /// simply will not match — a safe failure mode that never blocks something
    /// the engine failed to understand.
    #[must_use]
    pub fn new(url: impl Into<String>, resource_type: ResourceType) -> Self {
        let url = url.into();
        let host = extract_host(&url).unwrap_or_default();
        Self {
            url,
            host,
            resource_type,
            page_host: None,
            third_party: false,
        }
    }

    /// Attaches the initiating page hostname and recomputes third-party status.
    #[must_use]
    pub fn with_page(mut self, page_url_or_host: &str) -> Self {
        let page_host = extract_host(page_url_or_host)
            .unwrap_or_else(|| page_url_or_host.trim().to_ascii_lowercase());
        self.third_party = !same_site(&self.host, &page_host);
        self.page_host = Some(page_host);
        self
    }

    /// Overrides third-party detection explicitly.
    #[must_use]
    pub fn with_third_party(mut self, third_party: bool) -> Self {
        self.third_party = third_party;
        self
    }

    /// Returns the request's lowercased URL text.
    ///
    /// Most lists are written in lowercase, so matching is done on the lowered
    /// form. `$match-case` rules are compared against [`Self::url`] instead.
    #[must_use]
    pub fn lowercase_url(&self) -> String {
        self.url.to_ascii_lowercase()
    }
}

/// Extracts a bare lowercase hostname from either a full URL or a bare host.
///
/// Handles `http://user:pass@host:port/path`, IPv6 literals in brackets, and
/// bare hostnames. Returns `None` when nothing host-like is present.
#[must_use]
pub fn extract_host(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Strip a scheme if present.
    let after_scheme = match trimmed.find("://") {
        Some(pos) => {
            let scheme = &trimmed[..pos];
            if scheme.is_empty()
                || !scheme
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
            {
                // Not a real scheme; treat the whole thing as authority.
                trimmed
            } else {
                &trimmed[pos + 3..]
            }
        }
        None => trimmed,
    };

    // Authority ends at the first '/', '?', or '#'.
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let mut authority = &after_scheme[..authority_end];

    // Drop userinfo.
    if let Some(at) = authority.rfind('@') {
        authority = &authority[at + 1..];
    }

    // IPv6 literal.
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        return Some(authority[..=end].to_ascii_lowercase());
    }

    // Drop the port.
    if let Some(colon) = authority.rfind(':') {
        // Guard against a bare hostname that legitimately has no port.
        if authority[colon + 1..].bytes().all(|b| b.is_ascii_digit()) {
            authority = &authority[..colon];
        }
    }

    let host = authority.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }

    // Convert IDN to punycode so unicode and ASCII forms compare equal.
    if host.is_ascii() {
        Some(host)
    } else {
        idna::domain_to_ascii(&host).ok()
    }
}

/// Returns `true` when two hosts belong to the same site.
///
/// A pragmatic eTLD+1 comparison: the last two labels must agree, except for
/// two-part public suffixes such as `co.uk` where three labels are compared.
/// This mirrors the practical behaviour of "third-party" in filter lists
/// without requiring the full public suffix list.
#[must_use]
pub fn same_site(a: &str, b: &str) -> bool {
    if a.is_empty() || b.is_empty() {
        return true;
    }
    if a == b {
        return true;
    }
    registrable_domain(a) == registrable_domain(b)
}

/// Returns the registrable domain (eTLD+1 approximation) of a host.
///
/// This walks labels from the right rather than counting from the left, which
/// is the only correct way to handle a host such as `example.co.uk` where the
/// public suffix itself occupies two labels.
#[must_use]
pub fn registrable_domain(host: &str) -> &str {
    const TWO_PART_SUFFIXES: &[&str] = &[
        "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "or.jp", "ne.jp", "com.au", "net.au",
        "org.au", "co.nz", "com.br", "com.cn", "com.tw", "co.kr", "co.in", "com.mx", "co.za",
        "com.tr", "com.sg", "com.hk", "co.il", "com.ar", "com.pl", "co.id",
    ];

    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 2 {
        return host;
    }

    // Does the host end in a known two-label public suffix?
    let last_two = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    let take = if TWO_PART_SUFFIXES.contains(&last_two.as_str()) {
        3
    } else {
        2
    };

    // Fewer labels than required: the whole host is the best answer available.
    if labels.len() <= take {
        return host;
    }

    // The registrable domain starts at the label that has (labels.len() - take)
    // dots before it, so walk to that dot and slice one byte past it.
    let dots_before = labels.len() - take;
    let mut seen_dots = 0usize;
    for (i, ch) in host.char_indices() {
        if ch == '.' {
            seen_dots += 1;
            if seen_dots == dots_before {
                return host.get(i + 1..).unwrap_or(host);
            }
        }
    }

    host
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_host_from_urls() {
        assert_eq!(
            extract_host("http://example.com/x").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            extract_host("https://ads.example.com:8080/x?y=1").as_deref(),
            Some("ads.example.com")
        );
        assert_eq!(
            extract_host("http://user:pass@example.com/x").as_deref(),
            Some("example.com")
        );
        assert_eq!(extract_host("EXAMPLE.COM").as_deref(), Some("example.com"));
        assert_eq!(extract_host("example.com.").as_deref(), Some("example.com"));
    }

    #[test]
    fn handles_ipv6_literals() {
        assert_eq!(extract_host("http://[::1]:80/x").as_deref(), Some("[::1]"));
    }

    #[test]
    fn bare_hostname_is_accepted() {
        assert_eq!(
            extract_host("ads.example.com").as_deref(),
            Some("ads.example.com")
        );
    }

    #[test]
    fn empty_input_has_no_host() {
        assert_eq!(extract_host(""), None);
        assert_eq!(extract_host("   "), None);
    }

    #[test]
    fn idn_is_converted_to_punycode() {
        let host = extract_host("http://例え.jp/x").unwrap();
        assert!(host.starts_with("xn--"), "got {host}");
    }

    #[test]
    fn third_party_detection() {
        let req = Request::new("https://cdn.example.com/x", ResourceType::Script)
            .with_page("https://www.example.com/");
        assert!(!req.third_party);

        let req = Request::new("https://tracker.other.com/x", ResourceType::Script)
            .with_page("https://www.example.com/");
        assert!(req.third_party);
    }

    #[test]
    fn registrable_domain_handles_two_part_suffixes() {
        assert_eq!(registrable_domain("www.example.co.uk"), "example.co.uk");
        assert_eq!(registrable_domain("www.example.com"), "example.com");
        assert_eq!(registrable_domain("example.com"), "example.com");
        assert_eq!(registrable_domain("a.b.c.example.com"), "example.com");
    }

    #[test]
    fn same_site_across_subdomains() {
        assert!(same_site("a.example.com", "b.example.com"));
        assert!(!same_site("example.com", "example.org"));
        assert!(same_site("a.example.co.uk", "b.example.co.uk"));
        assert!(!same_site("a.example.co.uk", "a.other.co.uk"));
    }
}
