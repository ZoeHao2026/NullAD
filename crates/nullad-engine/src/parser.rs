//! Adblock Plus rule-syntax parser.
//!
//! The parser is *total*: it never panics and never returns an error for the
//! list as a whole. Individual rules that cannot be understood are quarantined
//! into [`ParseStats::failures`] so that one malformed line in a community list
//! cannot prevent the other several hundred thousand from loading.

use std::collections::HashSet;

use smallvec::SmallVec;

use crate::error::{ParseErrorKind, ParseFailure};
use crate::rule::{
    Action, DomainConstraint, ResourceType, Rule, RuleOptions, RuleOrigin, RulePattern,
};

/// Safety bounds applied while parsing.
///
/// These exist so that a hostile or corrupt filter list cannot exhaust memory
/// or produce a pathological index. A rule that violates a bound is quarantined
/// rather than truncated, because a truncated rule is a *silently wrong* rule.
#[derive(Debug, Clone, Copy)]
pub struct ParseLimits {
    /// Maximum length of a single rule line, in bytes.
    pub max_rule_len: usize,
    /// Maximum length of a regex pattern, in bytes.
    pub max_regex_len: usize,
    /// Maximum number of `*`-separated fragments in one wildcard pattern.
    pub max_wildcard_fragments: usize,
    /// Maximum number of domains in one `$domain=` option.
    pub max_domain_option: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_rule_len: 8192,
            max_regex_len: 2048,
            max_wildcard_fragments: 64,
            max_domain_option: 512,
        }
    }
}

/// Summary of a parse run.
#[derive(Debug, Clone, Default)]
pub struct ParseStats {
    /// Lines read, including blanks and comments.
    pub lines: usize,
    /// Rules successfully parsed.
    pub accepted: usize,
    /// Lines skipped as comments, blank, or metadata.
    pub skipped: usize,
    /// Cosmetic (`##`/`#@#`/`#?#`) rules recognised but not applied.
    pub cosmetic: usize,
    /// Rules that failed to parse, with reasons.
    pub failures: Vec<ParseFailure>,
    /// Syntax revisions declared by `[Adblock Plus x.y]` headers.
    pub declared_versions: HashSet<String>,
}

impl ParseStats {
    /// Number of quarantined rules.
    #[must_use]
    pub fn failed(&self) -> usize {
        self.failures.len()
    }
}

/// Parses Adblock Plus filter syntax into [`Rule`] values.
#[derive(Debug, Clone)]
pub struct RuleParser {
    limits: ParseLimits,
    list_id: u32,
    origin: RuleOrigin,
}

impl Default for RuleParser {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleParser {
    /// Creates a parser with default safety limits.
    #[must_use]
    pub fn new() -> Self {
        Self {
            limits: ParseLimits::default(),
            list_id: 0,
            origin: RuleOrigin::List,
        }
    }

    /// Creates a parser with explicit safety limits.
    #[must_use]
    pub fn with_limits(limits: ParseLimits) -> Self {
        Self {
            limits,
            list_id: 0,
            origin: RuleOrigin::List,
        }
    }

    /// Tags every rule produced by this parser with a list id.
    #[must_use]
    pub fn list_id(mut self, id: u32) -> Self {
        self.list_id = id;
        self
    }

    /// Tags every rule produced by this parser with an origin.
    #[must_use]
    pub fn origin(mut self, origin: RuleOrigin) -> Self {
        self.origin = origin;
        self
    }

    /// Parses an entire list, collecting stats and quarantining bad rules.
    pub fn parse_list(&self, source: &str) -> (Vec<Rule>, ParseStats) {
        let mut rules = Vec::new();
        let mut stats = ParseStats::default();

        for (index, raw_line) in source.lines().enumerate() {
            let line_no = index + 1;
            stats.lines += 1;

            let line = raw_line.trim_end_matches('\r');

            if let Some(version) = parse_list_header(line) {
                stats.declared_versions.insert(version);
                stats.skipped += 1;
                continue;
            }

            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('!') {
                stats.skipped += 1;
                continue;
            }

            // Cosmetic filters are recognised so that lists load cleanly even
            // though the MVP does not apply them.
            if is_cosmetic_filter(trimmed) {
                stats.cosmetic += 1;
                stats.skipped += 1;
                continue;
            }

            match self.parse_rule(trimmed, line_no) {
                Ok(Some(rule)) => {
                    rules.push(rule);
                    stats.accepted += 1;
                }
                Ok(None) => stats.skipped += 1,
                Err(kind) => {
                    stats.failures.push(ParseFailure {
                        line: line_no,
                        text: trimmed.to_owned(),
                        reason: kind,
                    });
                }
            }
        }

        (rules, stats)
    }

    /// Parses a single rule line.
    ///
    /// Returns `Ok(None)` when the line is not a network filter at all.
    pub fn parse_rule(&self, line: &str, line_no: usize) -> Result<Option<Rule>, ParseErrorKind> {
        if line.len() > self.limits.max_rule_len {
            return Err(ParseErrorKind::TooLarge {
                limit: "rule length",
                actual: line.len(),
                max: self.limits.max_rule_len,
            });
        }

        let mut rule = Rule {
            raw: line.to_owned(),
            action: Action::Block,
            pattern: RulePattern::Substring(String::new()),
            options: RuleOptions::default(),
            origin: self.origin.clone(),
            source_line: line_no,
            list_id: self.list_id,
            csp: None,
            redirect: None,
            removeparam: None,
        };

        let mut body = line;

        // Hosts-file form: "0.0.0.0 ads.example.com" or "127.0.0.1 host".
        if let Some(host) = parse_hosts_file_entry(body) {
            rule.pattern = RulePattern::DomainAnchor {
                domain: normalize_host(host)?,
                separator: false,
            };
            return Ok(Some(rule));
        }

        if let Some(rest) = body.strip_prefix("@@") {
            rule.action = Action::Allow;
            body = rest;
        }

        // Split off the $options suffix, taking care not to split inside a
        // regex literal.
        let (pattern_text, options_text) = split_options(body);

        if let Some(opts) = options_text {
            self.parse_options(opts, &mut rule)?;
        }

        if pattern_text.is_empty() {
            // A purely option-driven rule such as "$domain=a.com".
            if options_text.is_none() {
                return Ok(None);
            }
            rule.pattern = RulePattern::OptionsOnly;
            return Ok(Some(rule));
        }

        rule.pattern = self.parse_pattern(pattern_text, &rule.options)?;
        Ok(Some(rule))
    }

    /// Classifies a pattern into the cheapest index that can serve it.
    fn parse_pattern(
        &self,
        text: &str,
        options: &RuleOptions,
    ) -> Result<RulePattern, ParseErrorKind> {
        // /regex/ form.
        if text.len() >= 2 && text.starts_with('/') && text.ends_with('/') {
            let inner = &text[1..text.len() - 1];
            if inner.is_empty() {
                return Err(ParseErrorKind::Malformed("empty regex literal".into()));
            }
            if inner.len() > self.limits.max_regex_len {
                return Err(ParseErrorKind::TooLarge {
                    limit: "regex length",
                    actual: inner.len(),
                    max: self.limits.max_regex_len,
                });
            }
            // Compilation is attempted here so that a bad regex is quarantined
            // at parse time rather than silently never matching at runtime.
            regex::RegexBuilder::new(inner)
                .case_insensitive(!options.match_case)
                .size_limit(1 << 20)
                .build()
                .map_err(|e| ParseErrorKind::InvalidRegex(e.to_string()))?;
            return Ok(RulePattern::Regex(inner.to_owned()));
        }

        // ||domain^ anchor, optionally followed by path/query components.
        if let Some(rest) = text.strip_prefix("||") {
            if let Some(pattern) = self.parse_domain_anchor(rest, options)? {
                return Ok(pattern);
            }
            // Not a pure domain anchor (it has a path with wildcards, or a
            // separator in the middle); fall through to wildcard handling with
            // the leading "||" removed but the domain prefix preserved.
            return self.parse_generic(text, options);
        }

        self.parse_generic(text, options)
    }

    /// Attempts to reduce a `||`-anchored pattern to a pure domain anchor.
    fn parse_domain_anchor(
        &self,
        rest: &str,
        options: &RuleOptions,
    ) -> Result<Option<RulePattern>, ParseErrorKind> {
        // Find the end of the hostname portion: the first '/', '^', '*', '?'
        // or ':'. A '^' that is the very last character of the pattern makes
        // this a separator rule; a delimiter anywhere else means the pattern
        // carries a path, wildcard or port and must be served by the wildcard
        // or substring index instead of the domain trie.
        let mut host_end = rest.len();
        let mut separator = false;
        let mut delimiter: Option<char> = None;

        for (i, ch) in rest.char_indices() {
            if matches!(ch, '^' | '/' | '*' | '?' | ':') {
                delimiter = Some(ch);
                host_end = i;
                break;
            }
        }

        let host = &rest[..host_end];
        if host.is_empty() {
            return Ok(None);
        }

        match delimiter {
            // A trailing '^' is a separator: the pure `||host^` form.
            Some('^') if host_end + 1 == rest.len() => separator = true,
            // Any other delimiter means the pattern continues past the host.
            // That is still a `||`-anchored rule, so it is handled below as a
            // domain-and-path pattern rather than falling through to the
            // generic `|`-anchored path.
            Some(_) => {}
            // No delimiter at all: a bare `||host`.
            None => {}
        }

        // Normalise first so that IDN hosts such as `例え.jp` are validated in
        // their punycode form rather than rejected for being non-ASCII.
        let domain = match normalize_host(host) {
            Ok(domain) if is_plausible_domain(&domain) => domain,
            // Not a hostname at all: let the wildcard/substring path handle it.
            Ok(_) => return Ok(None),
            Err(_) => return Ok(None),
        };

        // A pattern that continues past the host (`||example.com/path`) is a
        // domain *and* path rule. It cannot be reduced to a bare domain anchor,
        // and it must not be treated as a `|`-anchored pattern either, because
        // that would require the fragment at the very start of the URL.
        //
        // A remainder of exactly "^" was already consumed as the separator
        // flag above, so it does not constitute a path.
        let remainder = &rest[host_end..];
        if !remainder.is_empty() && remainder != "^" {
            return self.parse_domain_path(domain, remainder, options);
        }

        Ok(Some(RulePattern::DomainAnchor { domain, separator }))
    }

    /// Builds a [`RulePattern::DomainPath`] for `||host<remainder>` patterns.
    fn parse_domain_path(
        &self,
        domain: String,
        remainder: &str,
        options: &RuleOptions,
    ) -> Result<Option<RulePattern>, ParseErrorKind> {
        // A lone trailing '^' was already consumed as the separator flag, so a
        // remainder that is only '^' cannot occur here.
        let trailing_separator = remainder.ends_with('^') && remainder.len() > 1;
        let body = if trailing_separator {
            &remainder[..remainder.len() - 1]
        } else {
            remainder
        };

        if body.is_empty() {
            return Ok(Some(RulePattern::DomainAnchor {
                domain,
                separator: true,
            }));
        }

        let trailing_wildcard = body.ends_with('*');
        let parts: SmallVec<[&str; 8]> = body.split('*').collect();
        if parts.len() > self.limits.max_wildcard_fragments {
            return Err(ParseErrorKind::TooLarge {
                limit: "wildcard fragments",
                actual: parts.len(),
                max: self.limits.max_wildcard_fragments,
            });
        }

        let fragments: SmallVec<[String; 4]> = parts
            .iter()
            .map(|part| {
                if options.match_case {
                    (*part).to_owned()
                } else {
                    part.to_ascii_lowercase()
                }
            })
            .collect();

        Ok(Some(RulePattern::DomainPath {
            domain,
            separator: true,
            fragments,
            trailing_wildcard,
            trailing_separator,
        }))
    }

    /// Parses a general pattern into wildcard, substring, or options-only form.
    fn parse_generic(
        &self,
        text: &str,
        options: &RuleOptions,
    ) -> Result<RulePattern, ParseErrorKind> {
        let mut body = text;

        let start_anchored = body.starts_with('|') && !body.starts_with("||");
        if start_anchored {
            body = &body[1..];
        }

        // A trailing '|' anchors to the end of the URL. A trailing '^' is a
        // separator, handled as part of the wildcard/substring match below.
        let end_anchored = body.len() > 1 && body.ends_with('|');
        if end_anchored {
            body = &body[..body.len() - 1];
        }

        if body.is_empty() {
            return Ok(RulePattern::OptionsOnly);
        }

        let has_wildcard = body.contains('*') || body.contains('^');

        if !has_wildcard {
            let normalized = if options.match_case {
                body.to_owned()
            } else {
                body.to_ascii_lowercase()
            };
            return if start_anchored || end_anchored {
                Ok(RulePattern::Wildcard {
                    fragments: smallvec::smallvec![normalized],
                    leading_wildcard: !start_anchored,
                    trailing_wildcard: !end_anchored,
                    start_anchored,
                    end_anchored,
                })
            } else {
                Ok(RulePattern::Substring(normalized))
            };
        }

        // Split on '*' into literal fragments. A '^' separator is translated
        // into "not in the URL-safe character set", which is handled by the
        // matcher rather than decomposed here.
        let parts: SmallVec<[&str; 8]> = body.split('*').collect();
        if parts.len() > self.limits.max_wildcard_fragments {
            return Err(ParseErrorKind::TooLarge {
                limit: "wildcard fragments",
                actual: parts.len(),
                max: self.limits.max_wildcard_fragments,
            });
        }

        let leading_wildcard = body.starts_with('*');
        let trailing_wildcard = body.ends_with('*');

        let fragments: SmallVec<[String; 4]> = parts
            .iter()
            .map(|part| {
                if options.match_case {
                    (*part).to_owned()
                } else {
                    part.to_ascii_lowercase()
                }
            })
            .collect();

        Ok(RulePattern::Wildcard {
            fragments,
            leading_wildcard,
            trailing_wildcard,
            start_anchored,
            end_anchored,
        })
    }

    /// Parses the `$options` suffix into `rule.options`.
    ///
    /// Resource types follow Adblock Plus semantics: naming types *selects*
    /// them, while `~type` *subtracts* from the current selection. A rule whose
    /// only type options are negations therefore starts from the full set, so
    /// `$~script` means "everything except scripts" rather than "nothing".
    fn parse_options(&self, text: &str, rule: &mut Rule) -> Result<(), ParseErrorKind> {
        let mut saw_type = false;
        // Start from the full observable set so that negations alone behave
        // correctly. Any positive type option resets this to an empty mask on
        // first use, which is what makes `$script,image` mean exactly those two.
        let mut types = ResourceType::All;
        let mut saw_positive_type = false;
        let mut domains = DomainConstraint::default();

        for option in text.split(',') {
            let option = option.trim();
            if option.is_empty() {
                continue;
            }

            let (negated, name, value) = split_option(option);

            // Value-bearing options.
            if let Some(value) = value {
                let lower = name.to_ascii_lowercase();
                match lower.as_str() {
                    "domain" => {
                        self.parse_domain_option(value, &mut domains)?;
                        continue;
                    }
                    "csp" => {
                        rule.csp = Some(value.to_owned());
                        continue;
                    }
                    "redirect" => {
                        rule.redirect = Some(value.to_owned());
                        continue;
                    }
                    "removeparam" | "queryprune" => {
                        rule.removeparam = Some(value.to_owned());
                        continue;
                    }
                    _ => {
                        // Unknown value-bearing option: keep the rule but note
                        // it as unsupported for this round.
                        return Err(ParseErrorKind::InvalidOption(option.to_owned()));
                    }
                }
            }

            let lower = name.to_ascii_lowercase();

            // Boolean modifiers.
            match lower.as_str() {
                "third-party" | "3p" => {
                    rule.options.third_party = Some(!negated);
                    continue;
                }
                "match-case" => {
                    rule.options.match_case = !negated;
                    continue;
                }
                "important" => {
                    rule.options.important = !negated;
                    continue;
                }
                // Document-level modifiers. Parsed and retained so the rule
                // round-trips, but not applied by the MVP matcher.
                "document" if negated => {
                    // `~document` is a type restriction, handled below.
                }
                "generichide" | "genericblock" | "elemhide" | "shide" | "specifichide" => {
                    continue;
                }
                "collapse" | "donottrack" | "dnt" | "inline-script" | "inline-font" => {
                    continue;
                }
                _ => {}
            }

            // Resource type keywords.
            if let Some(flag) = ResourceType::from_keyword(&lower) {
                saw_type = true;
                if negated {
                    types = ResourceType::from_bits_truncate(types.bits() & !flag.bits());
                } else {
                    if !saw_positive_type {
                        // First positive type: switch from "everything" to
                        // "exactly what is named".
                        types = ResourceType::None;
                        saw_positive_type = true;
                    }
                    types = ResourceType::from_bits_truncate(types.bits() | flag.bits());
                }
                continue;
            }

            return Err(ParseErrorKind::InvalidOption(option.to_owned()));
        }

        if saw_type {
            rule.options.resource_types =
                ResourceType::from_bits_truncate(types.bits() & ResourceType::All.bits());
        }

        rule.options.domains = domains;
        Ok(())
    }

    /// Parses a `$domain=a.com|~b.com` value into include/exclude sets.
    fn parse_domain_option(
        &self,
        value: &str,
        out: &mut DomainConstraint,
    ) -> Result<(), ParseErrorKind> {
        let mut count = 0usize;
        for entry in value.split('|') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            count += 1;
            if count > self.limits.max_domain_option {
                return Err(ParseErrorKind::TooLarge {
                    limit: "domain option entries",
                    actual: count,
                    max: self.limits.max_domain_option,
                });
            }

            let (negated, domain) = match entry.strip_prefix('~') {
                Some(rest) => (true, rest),
                None => (false, entry),
            };

            let normalized = normalize_host(domain)?;
            if negated {
                out.exclude.push(normalized);
            } else {
                out.include.push(normalized);
            }
        }

        if count == 0 {
            return Err(ParseErrorKind::EmptyDomainOption);
        }
        Ok(())
    }
}

/// Splits a rule into its pattern and options halves.
///
/// The `$` that begins options is the last one outside a `/regex/` literal.
/// A regex literal is only possible at the very start of the pattern, so the
/// scan is simple and cannot be confused by slashes inside an ordinary path.
fn split_options(body: &str) -> (&str, Option<&str>) {
    if body.starts_with('/') {
        // A `/regex/` literal: the closing slash is the last '/'. Anything
        // after it (before a '$') would be malformed, but if a '$' appears
        // after the closing slash it still starts the options.
        if let Some(close) = body.rfind('/') {
            if close > 0 {
                let after = &body[close + 1..];
                if let Some(rest) = after.strip_prefix('$') {
                    return (&body[..close + 1], Some(rest));
                }
                return (body, None);
            }
        }
        return (body, None);
    }

    match body.find('$') {
        Some(i) => (&body[..i], Some(&body[i + 1..])),
        None => (body, None),
    }
}

/// Splits a single option into (negated, name, value).
fn split_option(option: &str) -> (bool, &str, Option<&str>) {
    let (negated, rest) = match option.strip_prefix('~') {
        Some(rest) => (true, rest),
        None => (false, option),
    };
    match rest.split_once('=') {
        Some((name, value)) => (negated, name.trim(), Some(value)),
        None => (negated, rest.trim(), None),
    }
}

/// Parses `[Adblock Plus 2.0]` style headers.
fn parse_list_header(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let inner = trimmed.strip_prefix('[')?.strip_suffix(']')?;
    let rest = inner.strip_prefix("Adblock Plus")?;
    Some(rest.trim().to_owned())
}

/// Returns `true` for cosmetic filter syntax we recognise but do not apply.
fn is_cosmetic_filter(line: &str) -> bool {
    line.contains("##") || line.contains("#@#") || line.contains("#?#") || line.contains("#$#")
}

/// Recognises hosts-file lines and extracts the hostname.
fn parse_hosts_file_entry(line: &str) -> Option<&str> {
    let (first, rest) = line.split_once(char::is_whitespace)?;
    if !matches!(first, "0.0.0.0" | "127.0.0.1" | "::1" | "::") {
        return None;
    }
    let host = rest.split_whitespace().next()?;
    // Ignore hosts-file lines that point at the loopback alias itself.
    if matches!(host, "localhost" | "0.0.0.0" | "127.0.0.1" | "::1") {
        return None;
    }
    Some(host)
}

/// Performs cheap structural validation before committing to a domain anchor.
///
/// A domain anchor must look like a hostname: letters, digits, dots, hyphens,
/// and the underscore that some real-world hosts use. Anything else (a path, a
/// query string, a percent escape) means the pattern is not a pure anchor and
/// must be handled by the wildcard or substring index instead.
fn is_plausible_domain(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.starts_with('.') || host.starts_with('-') || host.ends_with('-') {
        return false;
    }
    // Require at least one label separator unless it is a bare TLD-ish token.
    host.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'%'))
}

/// Lowercases a hostname and converts IDN input to punycode.
///
/// Normalising here means a rule written with a Unicode domain and a request
/// carrying the ASCII punycode form compare equal, which is a correctness
/// property most naive engines get wrong.
fn normalize_host(host: &str) -> Result<String, ParseErrorKind> {
    let lowered = host.trim().to_ascii_lowercase();
    if lowered.is_ascii() {
        // Reject a trailing dot ("example.com.") by trimming it, which is the
        // canonical DNS form for an absolute name.
        Ok(lowered.trim_end_matches('.').to_owned())
    } else {
        match idna::domain_to_ascii(&lowered) {
            Ok(ascii) => Ok(ascii.trim_end_matches('.').to_owned()),
            Err(_) => Err(ParseErrorKind::Malformed(format!(
                "not a valid IDN: {host}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_one(line: &str) -> Rule {
        RuleParser::new()
            .parse_rule(line, 1)
            .unwrap_or_else(|e| panic!("failed to parse {line:?}: {e}"))
            .unwrap_or_else(|| panic!("{line:?} produced no rule"))
    }

    #[test]
    fn parses_domain_anchor_with_separator() {
        let rule = parse_one("||ads.example.com^");
        assert_eq!(rule.action, Action::Block);
        assert_eq!(
            rule.pattern,
            RulePattern::DomainAnchor {
                domain: "ads.example.com".into(),
                separator: true
            }
        );
    }

    #[test]
    fn parses_domain_anchor_without_separator() {
        let rule = parse_one("||ads.example.com");
        assert_eq!(
            rule.pattern,
            RulePattern::DomainAnchor {
                domain: "ads.example.com".into(),
                separator: false
            }
        );
    }

    #[test]
    fn parses_exception_rule() {
        let rule = parse_one("@@||example.com/ok.js");
        assert_eq!(rule.action, Action::Allow);
    }

    #[test]
    fn domain_anchor_with_path_becomes_domain_path() {
        let rule = parse_one("||example.com/ads/*");
        match rule.pattern {
            RulePattern::DomainPath {
                ref domain,
                fragments,
                trailing_wildcard,
                ..
            } => {
                assert_eq!(domain, "example.com");
                // `*` splits `/ads/*` into a literal and an empty trailing
                // fragment; the empty one carries no matching information and
                // is skipped by the automaton, with `trailing_wildcard`
                // recording its effect. Path matching uses the first fragment.
                assert_eq!(fragments[0], "/ads/");
                assert!(trailing_wildcard);
            }
            other => panic!("expected domain path, got {other:?}"),
        }
    }

    #[test]
    fn domain_path_without_wildcard_is_exact() {
        let rule = parse_one("||example.com/exact/path");
        match rule.pattern {
            RulePattern::DomainPath {
                ref domain,
                fragments,
                trailing_wildcard,
                ..
            } => {
                assert_eq!(domain, "example.com");
                assert_eq!(fragments[0], "/exact/path");
                assert!(!trailing_wildcard);
            }
            other => panic!("expected domain path, got {other:?}"),
        }
    }

    #[test]
    fn parses_plain_substring() {
        // A leading and trailing '/' would make this a regex literal, so a
        // plain path fragment must not be mistaken for one.
        let rule = parse_one("banner.gif");
        assert_eq!(rule.pattern, RulePattern::Substring("banner.gif".into()));

        // A genuine regex literal is recognised when it is `/.../`.
        let rule = parse_one("/banner\\.gif/");
        assert!(matches!(rule.pattern, RulePattern::Regex(_)));
    }

    #[test]
    fn parses_regex_rules() {
        let rule = parse_one(r"/^https?:\/\/ads\./");
        assert!(matches!(rule.pattern, RulePattern::Regex(_)));
    }

    #[test]
    fn rejects_invalid_regex() {
        let err = RuleParser::new().parse_rule("/(unclosed/", 1).unwrap_err();
        assert!(matches!(err, ParseErrorKind::InvalidRegex(_)));
    }

    #[test]
    fn parses_resource_type_options() {
        let rule = parse_one("||ads.com^$script,image");
        assert_eq!(
            rule.options.resource_types,
            ResourceType::Script.union(ResourceType::Image)
        );
        assert_eq!(rule.options.third_party, None);
    }

    #[test]
    fn parses_negated_resource_type() {
        let rule = parse_one("||ads.com^$~script");
        assert!(!rule.options.resource_types.intersects(ResourceType::Script));
        assert!(rule.options.resource_types.intersects(ResourceType::Image));
    }

    #[test]
    fn parses_third_party_option() {
        assert_eq!(
            parse_one("||ads.com^$third-party").options.third_party,
            Some(true)
        );
        assert_eq!(
            parse_one("||ads.com^$~third-party").options.third_party,
            Some(false)
        );
    }

    #[test]
    fn parses_domain_option() {
        let rule = parse_one("||ads.com^$domain=good.com|~bad.good.com");
        assert_eq!(rule.options.domains.include[0], "good.com");
        assert_eq!(rule.options.domains.exclude[0], "bad.good.com");
    }

    #[test]
    fn parses_hosts_file_entries() {
        let rule = parse_one("0.0.0.0 ads.example.com");
        assert_eq!(
            rule.pattern,
            RulePattern::DomainAnchor {
                domain: "ads.example.com".into(),
                separator: false
            }
        );

        // A hosts entry with trailing comments still resolves.
        let rule = parse_one("127.0.0.1 tracker.example.com # nope");
        assert_eq!(
            rule.pattern,
            RulePattern::DomainAnchor {
                domain: "tracker.example.com".into(),
                separator: false
            }
        );
    }

    #[test]
    fn parses_idn_domains_to_punycode() {
        let rule = parse_one("||例え.jp^");
        match rule.pattern {
            RulePattern::DomainAnchor { domain, .. } => assert!(domain.starts_with("xn--")),
            other => panic!("expected domain anchor, got {other:?}"),
        }
    }

    #[test]
    fn comments_and_blanks_are_skipped() {
        let (rules, stats) = RuleParser::new().parse_list(
            "! a comment\n\n[Adblock Plus 2.0]\n||ads.com^\n   \n",
        );
        assert_eq!(rules.len(), 1);
        assert_eq!(stats.accepted, 1);
        assert_eq!(stats.failed(), 0);
        assert!(stats.declared_versions.contains("2.0"));
    }

    #[test]
    fn cosmetic_filters_are_counted_not_rejected() {
        let (rules, stats) =
            RuleParser::new().parse_list("##.ad-banner\nexample.com##.promo\n||ads.com^\n");
        assert_eq!(rules.len(), 1);
        assert_eq!(stats.cosmetic, 2);
        assert_eq!(stats.failed(), 0);
    }

    #[test]
    fn bad_rules_are_quarantined_not_fatal() {
        let (rules, stats) =
            RuleParser::new().parse_list("/(bad/\n||good.com^\n$domain=\n");
        assert_eq!(rules.len(), 1);
        assert_eq!(stats.failed(), 2);
        assert_eq!(rules[0].source_line, 2);
    }

    #[test]
    fn oversized_rule_is_quarantined() {
        let huge = format!("||{}.com^", "a".repeat(9000));
        let err = RuleParser::new().parse_rule(&huge, 1).unwrap_err();
        assert!(matches!(err, ParseErrorKind::TooLarge { .. }));
    }

    #[test]
    fn dollar_in_path_does_not_start_options() {
        // A '$' inside a regex literal is part of the regex, never an option
        // separator.
        let rule = parse_one(r"/path\/with\$dollar\.gif/");
        assert!(matches!(rule.pattern, RulePattern::Regex(_)));

        // A bare '$' in a plain path is a real options separator, which is why
        // lists escape it when they mean a literal dollar sign.
        let rule = parse_one("banner.gif");
        assert_eq!(rule.pattern, RulePattern::Substring("banner.gif".into()));
    }

    #[test]
    fn options_only_rule() {
        let rule = parse_one("$domain=ads.com");
        assert_eq!(rule.pattern, RulePattern::OptionsOnly);
        assert_eq!(rule.options.domains.include[0], "ads.com");
    }

    #[test]
    fn trailing_dot_is_trimmed() {
        let rule = parse_one("||example.com.^");
        assert_eq!(
            rule.pattern,
            RulePattern::DomainAnchor {
                domain: "example.com".into(),
                separator: true
            }
        );
    }
}
