//! NullAD headless command line interface.
//!
//! This binary is the project's primary *measurement and dogfooding surface*.
//! Every performance number quoted for NullAD is reproducible with
//! `nullad-cli bench`, and the interception stack can be exercised end to end
//! with `nullad-cli serve` without involving the desktop GUI at all.
//!
//! The small command surface uses hand-written argument parsing.
//!
//! ## 中文说明
//!
//! 本二进制是项目的**主要度量与自用（dogfooding）入口**。
//! NullAD 对外宣称的每一个性能数字都可以用 `nullad-cli bench` 复现；
//! 整套拦截链路也可以用 `nullad-cli serve` 端到端跑通，
//! 完全不需要拉起桌面 GUI。
//!
//! 命令行入口较小，使用手写参数解析。

use std::path::PathBuf;
use std::process::ExitCode;

mod bench;
mod check;
mod lists;
mod serve;
mod tables;

use lists::{ListSet, LoadReport};
use nullad_intercept::{DetectionPolicy, EngineHandle, HeuristicMode, UpstreamProxy};

/// Parsed command line.
#[derive(Debug)]
enum Command {
    /// Evaluate one URL and report the decision.
    Check {
        url: String,
        page: Option<String>,
        resource_type: String,
        lists: Vec<PathBuf>,
        verbose: bool,
        policy: DetectionPolicy,
        no_lists: bool,
    },
    /// Parse lists and report what was found without running anything.
    Load {
        lists: Vec<PathBuf>,
        show_rules: usize,
    },
    /// Measure matching throughput and latency.
    Bench {
        lists: Vec<PathBuf>,
        iterations: usize,
        synthetic_rules: usize,
        json: bool,
    },
    /// Run the HTTP proxy and/or DNS sinkhole.
    Serve {
        lists: Vec<PathBuf>,
        proxy_port: u16,
        dns_port: Option<u16>,
        dns_upstream: String,
        system_proxy: bool,
        policy: DetectionPolicy,
        no_lists: bool,
        upstream: Option<UpstreamProxy>,
    },
    /// Print version and build information.
    Version,
    /// Print usage.
    Help,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let command = match parse_args(&args) {
        Ok(Some(command)) => command,
        Ok(None) => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("error: {message}");
            eprintln!();
            print_usage();
            return ExitCode::FAILURE;
        }
    };

    let result = match command {
        Command::Help => {
            print_usage();
            Ok(())
        }
        Command::Version => {
            println!("nullad-cli {}", env!("CARGO_PKG_VERSION"));
            println!("host arch   {}", std::env::consts::ARCH);
            println!("host os     {}", std::env::consts::OS);
            println!("interceptors http-proxy, sni, dns");
            Ok(())
        }
        Command::Check {
            url,
            page,
            resource_type,
            lists,
            verbose,
            policy,
            no_lists,
        } => {
            let (engine, report) = load_engine(&lists, no_lists);
            report.print();
            check::run(
                &EngineHandle::new(std::sync::Arc::new(engine)).with_policy(policy),
                &url,
                page.as_deref(),
                &resource_type,
                verbose,
            )
        }
        Command::Load { lists, show_rules } => {
            let (engine, report) = load_engine(&lists, false);
            report.print();
            if show_rules > 0 {
                tables::print_sample_rules(&report.sample_rules, show_rules);
            }
            drop(engine);
            Ok(())
        }
        Command::Bench {
            lists,
            iterations,
            synthetic_rules,
            json,
        } => {
            let (engine, report) = load_engine(&lists, false);
            if !json {
                report.print();
            }
            bench::run(&engine, iterations, synthetic_rules, json)
        }
        Command::Serve {
            lists,
            proxy_port,
            dns_port,
            dns_upstream,
            system_proxy,
            policy,
            no_lists,
            upstream,
        } => {
            let (engine, report) = load_engine(&lists, no_lists);
            report.print();
            serve::run(
                std::sync::Arc::new(engine),
                serve::ServeOptions {
                    proxy_port,
                    dns_port,
                    dns_upstream,
                    system_proxy,
                    policy,
                    upstream,
                },
            )
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Builds an engine from the given lists and reports what was parsed.
///
/// The rule set is built first so that the report can include index-derived
/// figures (trie nodes, automaton fragments) that only exist after indexing.
fn load_engine(lists: &[PathBuf], no_lists: bool) -> (nullad_engine::FilterEngine, LoadReport) {
    let set = if no_lists {
        ListSet::default()
    } else {
        ListSet::load(lists)
    };
    if no_lists {
        return (
            nullad_engine::FilterEngine::new(),
            set.report(nullad_engine::RuleSetStats::default()),
        );
    }
    let started = std::time::Instant::now();
    let builder = set.build_builder();

    match builder.build() {
        Ok(rule_set) => {
            let mut report = set.report(rule_set.stats().clone());
            report.elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
            (nullad_engine::FilterEngine::from_rule_set(rule_set), report)
        }
        Err(err) => {
            eprintln!("warning: {err}; starting with an empty rule set");
            let mut report = set.report(nullad_engine::RuleSetStats::default());
            report.elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
            (nullad_engine::FilterEngine::new(), report)
        }
    }
}

/// Prints usage information.
fn print_usage() {
    println!(
        r#"nullad-cli — NullAD headless engine and interception tool

USAGE:
    nullad-cli <COMMAND> [OPTIONS]

COMMANDS:
    check <URL>       Evaluate one URL and report the blocking decision
    load              Parse filter lists and print structure statistics
    bench             Measure matching latency and throughput
    serve             Run the HTTP proxy and/or DNS sinkhole
    version           Print version and platform information
    help              Print this message

OPTIONS:
    --list <PATH>       Filter list file to load (repeatable). Defaults to
                        every file under ./lists
    --page <URL>        Initiator page URL, for $domain= and third-party checks
    --type <TYPE>       Resource type: script, image, stylesheet, xhr, document,
                        subdocument, font, media, websocket, ping, other
    --verbose           Show every matching rule, not just the decision
    --iterations <N>    Benchmark iterations (default 200000)
    --synthetic <N>     Generate N synthetic rules for benchmarking instead of
                        loading real lists
    --json              Emit benchmark results as JSON
    --show-rules <N>    Print N sample parsed rules (load command)
    --port <PORT>       HTTP proxy port (default 8080)
    --dns-port <PORT>   DNS sinkhole port; omit to disable DNS
    --dns-upstream <IP:PORT>
                        Upstream resolver (default 8.8.8.8:53)
    --system-proxy      Route the OS system proxy through NullAD while serving
    --heuristic <MODE>  Offline detection: off, conservative, balanced (default)
    --allow-host <HOST> Always allow a bare domain and its subdomains (repeatable)
    --no-lists          Do not discover or load any filter lists (check/serve)
    --upstream-proxy <URL>
                        Chain serve through http://host:port or socks5://host:port
                        No credentials; preserves an explicitly chosen proxy route

EXAMPLES:
    nullad-cli load
    nullad-cli check "http://ads.vendor.example/ad-loader.js" --no-lists --type script
    nullad-cli check "http://ads.vendor.example/ad-loader.js" --no-lists --allow-host vendor.example
    nullad-cli bench --iterations 500000
    nullad-cli serve --port 8080 --dns-port 5353
"#
    );
}

/// Parses the command line.
fn parse_args(args: &[String]) -> Result<Option<Command>, String> {
    if args.is_empty() {
        return Ok(None);
    }

    let mut lists: Vec<PathBuf> = Vec::new();
    let mut page: Option<String> = None;
    let mut resource_type = "other".to_owned();
    let mut verbose = false;
    let mut iterations = 200_000usize;
    let mut synthetic_rules = 0usize;
    let mut json = false;
    let mut show_rules = 0usize;
    let mut proxy_port = 8080u16;
    let mut dns_port: Option<u16> = None;
    let mut dns_upstream = "8.8.8.8:53".to_owned();
    let mut system_proxy = false;
    let mut heuristic_mode = HeuristicMode::Balanced;
    let mut allowed_hosts = Vec::new();
    let mut no_lists = false;
    let mut upstream = None;
    let mut policy_option = false;
    let mut positional: Vec<String> = Vec::new();

    let mut index = 0usize;
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            "--list" | "-l" => {
                index += 1;
                lists.push(PathBuf::from(expect_value(args, index, "--list")?));
            }
            "--page" => {
                index += 1;
                page = Some(expect_value(args, index, "--page")?.to_owned());
            }
            "--type" => {
                index += 1;
                resource_type = expect_value(args, index, "--type")?.to_owned();
            }
            "--verbose" | "-v" => verbose = true,
            "--iterations" => {
                index += 1;
                iterations =
                    parse_number(expect_value(args, index, "--iterations")?, "--iterations")?;
            }
            "--synthetic" => {
                index += 1;
                synthetic_rules =
                    parse_number(expect_value(args, index, "--synthetic")?, "--synthetic")?;
            }
            "--json" => json = true,
            "--show-rules" => {
                index += 1;
                show_rules =
                    parse_number(expect_value(args, index, "--show-rules")?, "--show-rules")?;
            }
            "--port" | "-p" => {
                index += 1;
                proxy_port = parse_number(expect_value(args, index, "--port")?, "--port")?;
            }
            "--dns-port" => {
                index += 1;
                dns_port = Some(parse_number(
                    expect_value(args, index, "--dns-port")?,
                    "--dns-port",
                )?);
            }
            "--dns-upstream" => {
                index += 1;
                dns_upstream = expect_value(args, index, "--dns-upstream")?.to_owned();
            }
            "--system-proxy" => system_proxy = true,
            "--heuristic" => {
                index += 1;
                heuristic_mode = match expect_value(args, index, "--heuristic")? {
                    "off" => HeuristicMode::Off,
                    "conservative" => HeuristicMode::Conservative,
                    "balanced" => HeuristicMode::Balanced,
                    _ => return Err("--heuristic must be off, conservative or balanced".into()),
                };
                policy_option = true;
            }
            "--allow-host" => {
                index += 1;
                allowed_hosts.push(expect_value(args, index, "--allow-host")?.to_owned());
                policy_option = true;
            }
            "--no-lists" => {
                no_lists = true;
                policy_option = true;
            }
            "--upstream-proxy" => {
                index += 1;
                upstream =
                    Some(expect_value(args, index, "--upstream-proxy")?.parse::<UpstreamProxy>()?);
            }
            "--help" | "-h" => return Ok(Some(Command::Help)),
            other if other.starts_with('-') => {
                return Err(format!("unknown option `{other}`"));
            }
            other => positional.push(other.to_owned()),
        }
        index += 1;
    }

    let Some(command_name) = positional.first().cloned() else {
        return Ok(None);
    };

    if no_lists && !lists.is_empty() {
        return Err("--no-lists cannot be combined with --list".into());
    }
    if policy_option && !matches!(command_name.as_str(), "check" | "serve") {
        return Err("--heuristic, --allow-host and --no-lists require check or serve".into());
    }
    if upstream.is_some() && command_name != "serve" {
        return Err("--upstream-proxy requires serve".into());
    }
    let policy = DetectionPolicy {
        mode: heuristic_mode,
        allowed_hosts: nullad_core::normalize_allowed_hosts(&allowed_hosts)
            .map_err(|error| error.to_string())?,
    };
    let command = match command_name.as_str() {
        "check" => {
            let url = positional
                .get(1)
                .cloned()
                .ok_or("`check` requires a URL argument")?;
            Command::Check {
                url,
                page,
                resource_type,
                lists,
                verbose,
                policy,
                no_lists,
            }
        }
        "load" => Command::Load { lists, show_rules },
        "bench" => Command::Bench {
            lists,
            iterations,
            synthetic_rules,
            json,
        },
        "serve" => Command::Serve {
            lists,
            proxy_port,
            dns_port,
            dns_upstream,
            system_proxy,
            policy,
            no_lists,
            upstream,
        },
        "version" => Command::Version,
        "help" => Command::Help,
        other => return Err(format!("unknown command `{other}`")),
    };

    Ok(Some(command))
}

/// Returns the value following an option, or an error naming the option.
fn expect_value<'a>(args: &'a [String], index: usize, option: &str) -> Result<&'a str, String> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("`{option}` requires a value"))
}

/// Parses a non-negative integer option.
fn parse_number<T: std::str::FromStr>(value: &str, option: &str) -> Result<T, String> {
    value
        .parse::<T>()
        .map_err(|_| format!("`{option}` expects a number, got `{value}`"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn no_lists_check_uses_offline_policy_and_explicit_allow_hosts() {
        let Some(Command::Check {
            policy,
            no_lists,
            lists,
            ..
        }) = parse_args(&args(&[
            "check",
            "http://ads.vendor.example/ad-loader.js",
            "--no-lists",
            "--heuristic",
            "conservative",
            "--allow-host",
            "VENDOR.example.",
            "--allow-host",
            "vendor.example",
        ]))
        .unwrap()
        else {
            panic!("check")
        };
        assert!(no_lists && lists.is_empty());
        assert_eq!(policy.mode, HeuristicMode::Conservative);
        assert_eq!(policy.allowed_hosts, ["vendor.example"]);
        let (engine, report) = load_engine(&[], true);
        assert_eq!(engine.rule_count(), 0);
        assert!(report.sample_rules.is_empty());
        let handle =
            EngineHandle::new(std::sync::Arc::new(engine)).with_policy(DetectionPolicy::default());
        assert!(
            handle
                .evaluate(
                    "http://ads.vendor.example/ad-loader.js",
                    nullad_engine::ResourceType::Script,
                    None,
                    nullad_intercept::DecisionSource::Proxy
                )
                .blocked
        );
        let handle = handle.with_policy(policy);
        assert!(
            !handle
                .evaluate(
                    "http://ads.vendor.example/ad-loader.js",
                    nullad_engine::ResourceType::Script,
                    None,
                    nullad_intercept::DecisionSource::Proxy
                )
                .blocked
        );
    }

    #[test]
    fn serving_upstream_and_balanced_defaults_are_explicit() {
        let Some(Command::Serve {
            policy,
            upstream,
            no_lists,
            ..
        }) = parse_args(&args(&[
            "serve",
            "--no-lists",
            "--upstream-proxy",
            "socks5://127.0.0.1:7890",
        ]))
        .unwrap()
        else {
            panic!("serve")
        };
        assert_eq!(policy.mode, HeuristicMode::Balanced);
        assert_eq!(upstream.unwrap().endpoint(), ("127.0.0.1", 7890));
        assert!(no_lists);
    }

    #[test]
    fn rejects_ambiguous_or_invalid_detection_options() {
        for values in [
            vec![
                "check",
                "http://example.com",
                "--no-lists",
                "--list",
                "a.txt",
            ],
            vec!["serve", "--heuristic", "aggressive"],
            vec!["serve", "--allow-host", "https://example.com"],
            vec!["serve", "--upstream-proxy", "http://user:pass@127.0.0.1:80"],
            vec!["bench", "--no-lists"],
            vec![
                "check",
                "http://example.com",
                "--upstream-proxy",
                "http://127.0.0.1:80",
            ],
        ] {
            assert!(parse_args(&args(&values)).is_err(), "{values:?}");
        }
    }
}
