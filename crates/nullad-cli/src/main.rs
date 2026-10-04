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
        } => {
            let (engine, report) = load_engine(&lists);
            report.print();
            check::run(&engine, &url, page.as_deref(), &resource_type, verbose)
        }
        Command::Load { lists, show_rules } => {
            let (engine, report) = load_engine(&lists);
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
            let (engine, report) = load_engine(&lists);
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
        } => {
            let (engine, report) = load_engine(&lists);
            report.print();
            serve::run(
                std::sync::Arc::new(engine),
                proxy_port,
                dns_port,
                &dns_upstream,
                system_proxy,
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
fn load_engine(lists: &[PathBuf]) -> (nullad_engine::FilterEngine, LoadReport) {
    let set = ListSet::load(lists);
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

EXAMPLES:
    nullad-cli load
    nullad-cli check "https://ads.example.com/banner.gif"
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
