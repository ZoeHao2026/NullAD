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
//! ## 中文说明
//!
//! 本 crate 是 NullAD 的规则解析与请求匹配核心，**不依赖任何异步运行时、
//! 套接字、文件系统或平台 API**。它的一切行为都是 `&self` 加一个输入请求的
//! 纯函数。正是这个约束，让内核可以不加改动地复用于桌面 GUI、无界面 CLI，
//! 以及未来的 Android/iOS FFI 绑定。
//!
//! 匹配模型：请求被归约为 [`Request`]（URL、主机名、资源类型、来源页面域名），
//! 再交给 [`RuleSet`] 评估。规则按其形态被分派到三套专用索引，
//! 因此开销取决于**请求**本身，而与规则条数无关：
//!
//! | 索引 | 规则形态 | 开销 |
//! |---|---|---|
//! | [`DomainTrie`] | `\|\|domain^` 锚点 | O(标签数) |
//! | [`SubstringIndex`] | `*` 通配 / 字面片段 | O(URL)，经 Aho–Corasick |
//! | [`RegexIndex`] | `/regex/` 及选项复杂的规则 | O(URL)，仅限正则桶 |
//!
//! 例外规则（`@@`）**最先**评估并短路返回，符合 Adblock Plus 中
//! 「白名单永远优先」的语义。
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
