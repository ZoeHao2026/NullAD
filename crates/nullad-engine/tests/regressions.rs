use nullad_engine::{FilterEngine, MatchScratch, RegexIndex, Request, ResourceType};

#[test]
fn case_sensitive_rules_keep_original_url_for_every_index() {
    for pattern in ["Banner", "Ban*ner", "||example.com/Banner", "/Banner/"] {
        let mut engine = FilterEngine::new();
        engine.load_list(&format!("{pattern}$match-case")).unwrap();
        let mut scratch = MatchScratch::new();
        assert!(
            engine
                .check_with(
                    &Request::new("https://example.com/Banner", ResourceType::Image),
                    &mut scratch
                )
                .blocked,
            "{pattern}"
        );
        assert!(
            !engine
                .check_with(
                    &Request::new("https://example.com/banner", ResourceType::Image),
                    &mut scratch
                )
                .blocked,
            "{pattern}"
        );
        engine.load_list(pattern).unwrap();
        assert!(
            engine
                .check_with(
                    &Request::new("https://example.com/BANNER", ResourceType::Image),
                    &mut scratch
                )
                .blocked,
            "{pattern}"
        );
    }
}

#[test]
fn length_prefilter_agrees_with_regex_for_nested_and_optional_patterns() {
    let cases = [
        "(ab|cd)",
        "(verylongliteral)?x",
        "(?:ab){0,2}x",
        "\\bfoo\\b",
        "((a|bc)?d)*",
        "[À-Ö]+",
        "(?i:K)",
    ];
    let haystacks = [
        "", "ab", "cd", "x", "abx", "foo", "d", "bcd", "À", "K", "k", "K",
    ];
    for match_case in [false, true] {
        for pattern in cases {
            let oracle = regex::RegexBuilder::new(pattern)
                .case_insensitive(!match_case)
                .build()
                .unwrap();
            let mut index = RegexIndex::new();
            index.add(pattern, 7, match_case).unwrap();
            for text in haystacks {
                let mut actual = Vec::new();
                index.scan(text, &mut actual);
                assert_eq!(
                    actual == [7],
                    oracle.is_match(text),
                    "{pattern:?} {text:?} case={match_case}"
                );
            }
        }
    }
}
