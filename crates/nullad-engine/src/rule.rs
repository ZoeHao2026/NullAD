//! The rule model: parsed representation of a single Adblock Plus filter.

use std::fmt;

use smallvec::SmallVec;

/// What an engine should do when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// Block the request (`||ads.example.com^`).
    Block,
    /// Allow the request, overriding any block rule (`@@||ads.example.com^`).
    Allow,
}

impl Action {
    /// Returns `true` for [`Action::Allow`].
    #[must_use]
    pub const fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns `true` for [`Action::Block`].
    #[must_use]
    pub const fn is_block(self) -> bool {
        matches!(self, Self::Block)
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Block => "block",
            Self::Allow => "allow",
        })
    }
}

/// Bitmask of resource types a rule applies to.
///
/// A mask of [`ResourceType::All`] means "unrestricted", which is the common
/// case and is treated as a fast path during matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResourceType(u16);

// These are bit flags rather than global constants, so PascalCase reads better
// at the call site (`ResourceType::Script`) than SCREAMING_SNAKE_CASE would.
#[allow(non_upper_case_globals)]
impl ResourceType {
    /// No resource types. A rule restricted to this mask matches nothing.
    pub const None: Self = Self(0);
    /// `script`
    pub const Script: Self = Self(1 << 0);
    /// `image`
    pub const Image: Self = Self(1 << 1);
    /// `stylesheet` (also `css`)
    pub const Stylesheet: Self = Self(1 << 2);
    /// `object`
    pub const Object: Self = Self(1 << 3);
    /// `xmlhttprequest` (also `xhr`, `fetch`)
    pub const Xhr: Self = Self(1 << 4);
    /// `subdocument` (also `frame`)
    pub const Subdocument: Self = Self(1 << 5);
    /// `document` (also `doc`)
    pub const Document: Self = Self(1 << 6);
    /// `font`
    pub const Font: Self = Self(1 << 7);
    /// `media`
    pub const Media: Self = Self(1 << 8);
    /// `websocket`
    pub const Websocket: Self = Self(1 << 9);
    /// `ping` (also `beacon`)
    pub const Ping: Self = Self(1 << 10);
    /// `other` — the catch-all bucket for anything unclassified.
    pub const Other: Self = Self(1 << 11);
    /// `popup`
    pub const Popup: Self = Self(1 << 12);
    /// `webrtc`
    pub const Webrtc: Self = Self(1 << 13);

    /// Every type except the pseudo-types `popup` and `webrtc`, which cannot be
    /// observed from an HTTP request and are therefore only ever matched
    /// explicitly.
    pub const All: Self = Self(
        Self::Script.0
            | Self::Image.0
            | Self::Stylesheet.0
            | Self::Object.0
            | Self::Xhr.0
            | Self::Subdocument.0
            | Self::Document.0
            | Self::Font.0
            | Self::Media.0
            | Self::Websocket.0
            | Self::Ping.0
            | Self::Other.0,
    );

    /// Returns the raw bitmask.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Builds a mask from raw bits, masking off anything undefined.
    #[must_use]
    pub const fn from_bits_truncate(bits: u16) -> Self {
        Self(bits & (Self::All.0 | Self::Popup.0 | Self::Webrtc.0))
    }

    /// Union of two masks.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns `true` if no bits are set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if `self` and `other` share at least one bit.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    /// Parses a rule option keyword such as `script` or `xmlhttprequest`.
    ///
    /// Returns `None` for keywords that are not resource types.
    #[must_use]
    pub fn from_keyword(word: &str) -> Option<Self> {
        Some(match word {
            "script" => Self::Script,
            "image" | "img" => Self::Image,
            "stylesheet" | "css" => Self::Stylesheet,
            "object" | "obj" => Self::Object,
            "xmlhttprequest" | "xhr" | "fetch" => Self::Xhr,
            "subdocument" | "frame" => Self::Subdocument,
            "document" | "doc" => Self::Document,
            "font" => Self::Font,
            "media" => Self::Media,
            "websocket" => Self::Websocket,
            "ping" | "beacon" => Self::Ping,
            "other" => Self::Other,
            "popup" => Self::Popup,
            "webrtc" => Self::Webrtc,
            _ => return None,
        })
    }
}

impl Default for ResourceType {
    fn default() -> Self {
        Self::All
    }
}

impl fmt::Display for ResourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: [(ResourceType, &str); 14] = [
            (ResourceType::Script, "script"),
            (ResourceType::Image, "image"),
            (ResourceType::Stylesheet, "stylesheet"),
            (ResourceType::Object, "object"),
            (ResourceType::Xhr, "xmlhttprequest"),
            (ResourceType::Subdocument, "subdocument"),
            (ResourceType::Document, "document"),
            (ResourceType::Font, "font"),
            (ResourceType::Media, "media"),
            (ResourceType::Websocket, "websocket"),
            (ResourceType::Ping, "ping"),
            (ResourceType::Other, "other"),
            (ResourceType::Popup, "popup"),
            (ResourceType::Webrtc, "webrtc"),
        ];

        if *self == Self::All {
            return f.write_str("all");
        }
        if self.is_empty() {
            return f.write_str("none");
        }

        let mut first = true;
        for (flag, name) in NAMES {
            if self.intersects(flag) {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        Ok(())
    }
}

/// The parsed pattern of a rule, ready for index insertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RulePattern {
    /// `||example.com^` — anchored to a hostname label boundary.
    ///
    /// The stored value is the lowercased domain suffix, and `separator`
    /// records whether a `^` separator was required.
    DomainAnchor {
        /// The domain suffix to match, lowercased, without leading `||`.
        domain: String,
        /// `true` when the rule ended with `^`, meaning the match must be
        /// followed by a separator or the end of the URL.
        separator: bool,
    },

    /// `||example.com/path/*` — a domain anchor that also constrains the path.
    ///
    /// This is distinct from [`Self::DomainAnchor`] because the host must be
    /// verified against the request host *and* the remainder matched against
    /// the URL text that follows it. Treating it as a plain `|`-anchored
    /// pattern would silently require the fragment at the very start of the
    /// URL, which is never true, so the rule would never fire.
    DomainPath {
        /// The domain suffix to match, lowercased, without leading `||`.
        domain: String,
        /// `true` when a `^` separator was required after the domain.
        separator: bool,
        /// Path fragments separated by `*`, matched against the URL text that
        /// begins immediately after the host.
        fragments: SmallVec<[String; 4]>,
        /// `true` when the original pattern ended with `*`.
        trailing_wildcard: bool,
        /// `true` when the original pattern ended with `^`.
        trailing_separator: bool,
    },

    /// A pattern containing `*` that is not reducible to a domain anchor.
    Wildcard {
        /// Alternating literal fragments, split on `*`.
        fragments: SmallVec<[String; 4]>,
        /// `true` when the original pattern started with `*`.
        leading_wildcard: bool,
        /// `true` when the original pattern ended with `*`.
        trailing_wildcard: bool,
        /// `true` when the pattern was anchored to the URL start with a single `|`.
        start_anchored: bool,
        /// `true` when the pattern was anchored to the URL end with a single `|`.
        end_anchored: bool,
    },

    /// A plain substring with no wildcards and no anchors.
    Substring(String),

    /// `/regex/` — matched with the linear-time `regex` crate.
    Regex(String),

    /// The rule constrains only options (for example `$domain=a.com`), with an
    /// empty pattern that matches every URL.
    OptionsOnly,
}

/// Options attached to a rule via the `$` suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleOptions {
    /// Resource types this rule applies to.
    pub resource_types: ResourceType,
    /// `third-party` / `~third-party`. `None` means "either".
    pub third_party: Option<bool>,
    /// `domain=a.com|~b.com` — required and excluded initiator domains.
    pub domains: DomainConstraint,
    /// `match-case` — make matching case sensitive.
    pub match_case: bool,
    /// `~important` / `important` — `important` rules survive exceptions.
    pub important: bool,
}

impl Default for RuleOptions {
    fn default() -> Self {
        Self {
            resource_types: ResourceType::All,
            third_party: None,
            domains: DomainConstraint::default(),
            match_case: false,
            important: false,
        }
    }
}

/// The `$domain=` constraint: a set of included and excluded initiator domains.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainConstraint {
    /// Domains that permit the rule to apply. Empty means "any".
    pub include: SmallVec<[String; 2]>,
    /// Domains that prevent the rule from applying.
    pub exclude: SmallVec<[String; 2]>,
}

impl DomainConstraint {
    /// Returns `true` when there is no constraint at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }

    /// Evaluates the constraint against an initiator (page) hostname.
    ///
    /// Domain matching is suffix-based on label boundaries, so `domain=a.com`
    /// matches `a.com` and `sub.a.com` but not `nota.com`.
    #[must_use]
    pub fn permits(&self, page_host: Option<&str>) -> bool {
        if self.is_empty() {
            return true;
        }

        let Some(host) = page_host else {
            // A rule that requires an initiator cannot apply to a request with
            // no initiator (for example a top-level navigation).
            return self.include.is_empty();
        };

        if self
            .exclude
            .iter()
            .any(|domain| domain_suffix_match(host, domain))
        {
            return false;
        }

        if self.include.is_empty() {
            return true;
        }

        self.include
            .iter()
            .any(|domain| domain_suffix_match(host, domain))
    }
}

/// Returns `true` when `host` equals `domain` or is a subdomain of it.
///
/// Both arguments are expected to be lowercase. The comparison is done on label
/// boundaries so `nota.com` does not match `a.com`.
#[must_use]
pub fn domain_suffix_match(host: &str, domain: &str) -> bool {
    if host == domain {
        return true;
    }
    if host.len() <= domain.len() {
        return false;
    }
    // The host must end with ".{domain}".
    let split = host.len() - domain.len();
    if !host.is_char_boundary(split) {
        return false;
    }
    let (prefix, suffix) = host.split_at(split);
    suffix == domain && prefix.ends_with('.')
}

/// Where a rule came from, for reporting and for enable/disable toggling.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RuleOrigin {
    /// One of the bundled or user-subscribed filter lists.
    #[default]
    List,
    /// Hand-written by the user and therefore never treated as disposable.
    UserDefined,
}

/// A single parsed and indexed filter rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The original rule text, exactly as it appeared in the source list.
    pub raw: String,
    /// Whether the rule blocks or allows.
    pub action: Action,
    /// The parsed match pattern.
    pub pattern: RulePattern,
    /// The parsed `$` options.
    pub options: RuleOptions,
    /// Rule provenance.
    pub origin: RuleOrigin,
    /// Original 1-based line number in the source list.
    pub source_line: usize,
    /// Identifier of the list this rule came from.
    pub list_id: u32,
    /// `$csp=` payload. Parsed and retained, not applied in the MVP.
    pub csp: Option<String>,
    /// `$redirect=` payload. Parsed and retained, not applied in the MVP.
    pub redirect: Option<String>,
    /// `$removeparam=` payload. Parsed and retained, not applied in the MVP.
    pub removeparam: Option<String>,
}

impl Rule {
    /// Returns `true` when this rule applies to the given resource type.
    #[must_use]
    pub fn applies_to_type(&self, resource: ResourceType) -> bool {
        self.options.resource_types.intersects(resource)
    }

    /// Returns `true` when this rule applies given a page hostname.
    #[must_use]
    pub fn applies_to_page(&self, page_host: Option<&str>) -> bool {
        self.options.domains.permits(page_host)
    }

    /// Returns `true` when this rule's third-party constraint is satisfied.
    #[must_use]
    pub fn applies_to_party(&self, third_party: bool) -> bool {
        match self.options.third_party {
            None => true,
            Some(required) => required == third_party,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_type_keywords_round_trip() {
        for (kw, expected) in [
            ("script", ResourceType::Script),
            ("image", ResourceType::Image),
            ("img", ResourceType::Image),
            ("stylesheet", ResourceType::Stylesheet),
            ("css", ResourceType::Stylesheet),
            ("xmlhttprequest", ResourceType::Xhr),
            ("xhr", ResourceType::Xhr),
            ("subdocument", ResourceType::Subdocument),
            ("frame", ResourceType::Subdocument),
            ("document", ResourceType::Document),
            ("other", ResourceType::Other),
        ] {
            assert_eq!(
                ResourceType::from_keyword(kw),
                Some(expected),
                "keyword {kw}"
            );
        }
        assert_eq!(ResourceType::from_keyword("bogus"), None);
    }

    #[test]
    fn all_mask_excludes_pseudo_types() {
        assert!(!ResourceType::All.intersects(ResourceType::Popup));
        assert!(!ResourceType::All.intersects(ResourceType::Webrtc));
        assert!(ResourceType::All.intersects(ResourceType::Script));
        assert!(ResourceType::All.intersects(ResourceType::Other));
    }

    #[test]
    fn suffix_match_respects_label_boundaries() {
        assert!(domain_suffix_match("a.com", "a.com"));
        assert!(domain_suffix_match("sub.a.com", "a.com"));
        assert!(domain_suffix_match("deep.sub.a.com", "a.com"));
        // Must not match on a partial label.
        assert!(!domain_suffix_match("nota.com", "a.com"));
        assert!(!domain_suffix_match("abc.com", "a.com"));
        // Shorter host cannot contain a longer domain.
        assert!(!domain_suffix_match("a.com", "sub.a.com"));
    }

    #[test]
    fn domain_constraint_semantics() {
        let mut c = DomainConstraint::default();
        assert!(c.is_empty());
        assert!(c.permits(Some("anything.com")));
        assert!(c.permits(None));

        c.include.push("good.com".into());
        assert!(c.permits(Some("good.com")));
        assert!(c.permits(Some("sub.good.com")));
        assert!(!c.permits(Some("evil.com")));
        // A rule requiring an initiator cannot apply without one.
        assert!(!c.permits(None));

        c.exclude.push("bad.good.com".into());
        assert!(c.permits(Some("good.com")));
        assert!(!c.permits(Some("bad.good.com")));
    }

    #[test]
    fn exclusion_only_constraint_allows_anonymous_requests() {
        let c = DomainConstraint {
            include: SmallVec::new(),
            exclude: smallvec::smallvec!["bad.com".into()],
        };
        assert!(c.permits(Some("good.com")));
        assert!(!c.permits(Some("bad.com")));
        // No include list means a missing initiator is acceptable.
        assert!(c.permits(None));
    }
}

#[cfg(test)]
mod zz_probe {
    use crate::rule::ResourceType;
    #[test]
    fn probe_constants() {
        let _ = ResourceType::Script;
        let _ = ResourceType::All;
    }
}
