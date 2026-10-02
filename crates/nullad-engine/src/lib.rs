//! # NullAD Engine
//!
//! A pure, I/O-free ad-filtering engine.
//!
//! This crate contains the entire rule-parsing and request-matching core of
//! NullAD. It deliberately depends on **no** async runtime, no sockets, no
//! filesystem, and no platform API. Everything it does is a pure function of
//! `&self` plus an input request.
//!
//! That constraint is what makes NullAD's core reusable across the desktop GUI,
//! the headless CLI, and a future Android/iOS FFI binding without modification.
//!
//! ## Matching model
//!
//! A request is reduced to a [`Request`] (URL, host, resource type, and the
//! originating page domain). The engine then evaluates it against a
//! [`RuleSet`] using three specialised indexes, chosen per rule shape so that
//! cost scales with the *request*, not with the number of rules:
//!
//! | Index | Rule shape | Cost |
//! |---|---|---|
//! | [`DomainTrie`] | `\|\|domain^` anchors | O(labels) |
//! | [`SubstringIndex`] | `*` wildcard / literal fragments | O(url) via Aho–Corasick |
//! | [`RegexIndex`] | `/regex/` and option-heavy rules | O(url), bucket only |
//!
//! Exception rules (`@@`) are evaluated **first** and short-circuit, matching
//! Adblock Plus semantics where a whitelist always wins.
//!
//! ## Example
//!
//! ```
//! use nullad_engine::{FilterEngine, Request, ResourceType};
//!
//! let mut engine = FilterEngine::new();
//! engine.load_list("||ads.example.com^\n@@||ads.example.com/ok.js").unwrap();
//!
//! let blocked = Request::new("https://ads.example.com/banner.gif", ResourceType::Image);
//! assert!(engine.check(&blocked).is_blocked());
//!
//! let allowed = Request::new("https://ads.example.com/ok.js", ResourceType::Script);
//! assert!(!engine.check(&allowed).is_blocked());
//! ```

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(clippy::doc_markdown)]

mod domain_trie;
mod error;
mod engine;
mod parser;
mod regex_index;
pub mod request;
mod rule;
mod stats;
mod substring_index;

pub use domain_trie::DomainTrie;
pub use error::{EngineError, ParseFailure};
pub use engine::{CheckResult, FilterEngine, MatchScratch, RuleSet, RuleSetBuilder, RuleSetStats};pub use parser::{ParseStats, RuleParser};
pub use regex_index::RegexIndex;
pub use request::Request;
pub use rule::{Action, ResourceType, Rule, RuleOptions, RuleOrigin};
pub use stats::{EngineStats, StatsSnapshot};
pub use substring_index::SubstringIndex;

/// The Adblock Plus rule-syntax revision this engine targets.
///
/// Filters declaring a newer revision are still parsed, but the parser records
/// a warning so the UI can surface a compatibility note.
pub const SUPPORTED_SYNTAX_VERSION: &str = "2.0";
