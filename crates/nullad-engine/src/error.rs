//! Error and diagnostic types for the engine.

use std::fmt;

/// A non-fatal problem encountered while parsing a single filter rule.
///
/// Parse failures never abort a list load: the offending rule is quarantined
/// and counted, so one malformed line in a community list cannot brick the
/// whole filter set. This is a deliberate robustness property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseFailure {
    /// 1-based line number within the source list.
    pub line: usize,
    /// The raw text of the rule that failed.
    pub text: String,
    /// Human-readable reason.
    pub reason: ParseErrorKind,
}

/// Why a particular rule could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// A `/regex/` rule that `regex` refused to compile.
    InvalidRegex(String),
    /// A `$domain=` option contained no usable domains.
    EmptyDomainOption,
    /// A numeric option (for example `$generichide`) had a bad value.
    InvalidOption(String),
    /// The rule was structurally nonsense (for example an unmatched bracket).
    Malformed(String),
    /// The rule exceeded a configured safety limit.
    TooLarge {
        /// What limit was exceeded, for example `"pattern length"`.
        limit: &'static str,
        /// The observed size.
        actual: usize,
        /// The configured maximum.
        max: usize,
    },
}

impl fmt::Display for ParseErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRegex(e) => write!(f, "invalid regex: {e}"),
            Self::EmptyDomainOption => write!(f, "$domain= option matched no domains"),
            Self::InvalidOption(o) => write!(f, "invalid option: {o}"),
            Self::Malformed(m) => write!(f, "malformed rule: {m}"),
            Self::TooLarge { limit, actual, max } => {
                write!(f, "{limit} {actual} exceeds maximum {max}")
            }
        }
    }
}

impl fmt::Display for ParseFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {} ({})", self.line, self.text, self.reason)
    }
}

/// Top-level engine error.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// A rule set could not be compiled from its source text.
    #[error("failed to compile rule set: {0}")]
    Compile(String),

    /// A list name was empty or otherwise unusable.
    #[error("invalid list name: {0:?}")]
    InvalidListName(String),

    /// Every rule in the input was quarantined, leaving nothing to match with.
    #[error("no usable rules: {accepted} accepted out of {total} ({failures} failed)")]
    NoUsableRules {
        /// Rules accepted into the set.
        accepted: usize,
        /// Rules seen in total.
        total: usize,
        /// Rules quarantined.
        failures: usize,
    },

    /// An index build was asked to exceed a configured safety bound.
    #[error("rule set limit exceeded: {0}")]
    LimitExceeded(String),
}
