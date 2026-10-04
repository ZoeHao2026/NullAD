//! The `check` command: evaluate one URL and explain the decision.

use anyhow::{bail, Result};
use nullad_engine::{FilterEngine, MatchScratch, Request, ResourceType};

/// Evaluates a URL and prints the outcome.
pub fn run(
    engine: &FilterEngine,
    url: &str,
    page: Option<&str>,
    resource_type: &str,
    verbose: bool,
) -> Result<()> {
    let Some(kind) = parse_resource_type(resource_type) else {
        bail!("unknown resource type `{resource_type}`");
    };

    let mut request = Request::new(url, kind);
    if let Some(page) = page {
        request = request.with_page(page);
    }

    let mut scratch = MatchScratch::new();
    let result = engine.check_with(&request, &mut scratch);

    println!();
    println!("url         {}", request.url);
    println!(
        "host        {}",
        if request.host.is_empty() {
            "(unparsed)"
        } else {
            &request.host
        }
    );
    println!("type        {}", kind);
    if let Some(page) = &request.page_host {
        println!("page        {page}");
        println!(
            "party       {}",
            if request.third_party {
                "third-party"
            } else {
                "first-party"
            }
        );
    }
    println!(
        "decision    {}",
        if result.blocked { "BLOCK" } else { "ALLOW" }
    );

    match &result.matched_rule {
        Some(rule) => {
            println!("by rule     {}", rule.raw);
            println!("as          {}", rule.action);
        }
        None => println!("by rule     (no rule matched)"),
    }

    if verbose && !result.matched_rule_ids.is_empty() {
        println!();
        println!("all matching rules ({}):", result.matched_rule_ids.len());
        let rule_set = engine.rule_set();
        for id in &result.matched_rule_ids {
            if let Some(rule) = rule_set.rule(*id) {
                println!("  [{id:>6}] {:<6} {}", rule.action.to_string(), rule.raw);
            }
        }
    }

    println!();
    println!("engine statistics:");
    let snap = engine.stats_snapshot();
    println!("  queries             {}", snap.queries);
    println!("  blocked             {}", snap.blocked);
    println!("  allowed             {}", snap.allowed);
    println!("  exceptions matched  {}", snap.exceptions_hit);

    Ok(())
}

/// Maps a user-supplied resource type name onto the engine's bitmask.
#[must_use]
pub fn parse_resource_type(name: &str) -> Option<ResourceType> {
    match name.to_ascii_lowercase().as_str() {
        "all" => Some(ResourceType::All),
        "script" | "js" => Some(ResourceType::Script),
        "image" | "img" => Some(ResourceType::Image),
        "stylesheet" | "css" => Some(ResourceType::Stylesheet),
        "object" => Some(ResourceType::Object),
        "xhr" | "xmlhttprequest" | "fetch" => Some(ResourceType::Xhr),
        "subdocument" | "frame" => Some(ResourceType::Subdocument),
        "document" | "doc" | "main_frame" => Some(ResourceType::Document),
        "font" => Some(ResourceType::Font),
        "media" | "video" | "audio" => Some(ResourceType::Media),
        "websocket" | "ws" => Some(ResourceType::Websocket),
        "ping" | "beacon" => Some(ResourceType::Ping),
        "other" | "unknown" => Some(ResourceType::Other),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_resource_type_names_and_aliases() {
        assert_eq!(parse_resource_type("script"), Some(ResourceType::Script));
        assert_eq!(parse_resource_type("JS"), Some(ResourceType::Script));
        assert_eq!(parse_resource_type("img"), Some(ResourceType::Image));
        assert_eq!(parse_resource_type("fetch"), Some(ResourceType::Xhr));
        assert_eq!(
            parse_resource_type("MAIN_FRAME"),
            Some(ResourceType::Document)
        );
        assert_eq!(parse_resource_type("nonsense"), None);
    }
}
