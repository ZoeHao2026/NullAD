//! Sample rule printing for the `load` command.

/// Prints up to `limit` sample rules.
///
/// Sample rules come from the already-parsed lists, so this is a faithful view
/// of what the parser produced rather than of the raw text.
pub fn print_sample_rules(rules: &[String], limit: usize) {
    if rules.is_empty() {
        return;
    }
    println!();
    println!("sample parsed rules:");
    for rule in rules.iter().take(limit) {
        println!("  {rule}");
    }
    if rules.len() > limit {
        println!("  ... and {} more", rules.len() - limit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printing_an_empty_set_is_a_no_op() {
        // Must not panic and must not print a header.
        print_sample_rules(&[], 10);
    }

    #[test]
    fn printing_more_than_available_is_safe() {
        let rules = vec!["block ||a.com^".to_string()];
        print_sample_rules(&rules, 100);
    }
}
