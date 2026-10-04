# NullAD

**English** · [简体中文](README.zh-CN.md)

NullAD is a Rust ad and tracker blocker with a desktop interface and a headless CLI.
It filters plaintext HTTP requests, TLS connections by hostname, and DNS queries.
Its matching engine contains no network, filesystem, or platform integration code.

## Current validation

| Area | Result and evidence |
|---|---|
| Windows engineering checks | **Pass**: formatting, strict Clippy and 228 workspace tests (3 explicitly ignored); release build recorded in validation |
| Network and lifecycle | **Pass**: 22 local HTTP/DNS checks; ports rebound after 20 cycles and 40 concurrent start/stop operations |
| Settings, rules and recovery | **Pass**: 30 core and 32 host regressions, including failed persistence, obsolete reloads and retained failed restores |
| Windows system proxy | **Pass**: explicit apply/revert and CLI Ctrl+Break restore all four raw registry values; DNS unchanged, pending=0 |
| Native Windows desktop | **Pass**: four pages, IPC, Chinese/English, dark theme, real traffic/logs, explicit save, restart marker and close cleanup without tray |
| Privileged Windows DNS / IPv6 UDP | **Unknown**: no privileged DNS writes; no passing native IPv6 UDP loopback observation |
| Tray menu / actual 125%/150% OS scaling | **Unknown**: browser equivalents pass but do not establish native system scaling or tray menu acceptance |
| Delivery packages / remote CI | Build, clean-directory startup and remote workflow results are recorded separately in [Windows validation](docs/windows-validation.md) |
| macOS and Linux | **Deferred**: known restoration gaps and no native acceptance |

No executed final ordinary check failed; unverified work remains Unknown/Deferred.

A passing build or unit test does not establish successful installation, visible
desktop operation, or restoration on another operating system.
See [Windows validation](docs/windows-validation.md) for the acceptance procedure
and remaining gaps.

## Build on Windows

Use Rust 1.96 or later, the MSVC toolchain, Visual Studio C++ build tools with a
Windows SDK, and WebView2 Runtime for the desktop application. Node.js is needed
for the UI test runner and the Tauri packaging command; Python is needed for the
local traffic acceptance suite.

Run from the repository root:

```powershell
cargo build --release --workspace --locked
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
node --test ui/tests/ui.test.cjs
python tests/e2e.py
```

When the MSVC environment needs initialization, use:

```powershell
scripts\build.bat release
scripts\build.bat test
```

Cargo uses its normal cache and can fetch dependencies. Offline builds are an
explicit option after the necessary dependencies are cached:

```powershell
cargo build --release --workspace --locked --offline
scripts\build.bat release --offline
```

Keep `Cargo.lock` committed. The repository does not require a private or
workspace-local Cargo registry. The UI is HTML, CSS and JavaScript; it has no
separate frontend compilation step.

### Windows delivery formats

The desktop installer is built with NSIS:

```powershell
Push-Location crates/nullad-desktop
npx --yes @tauri-apps/cli@2.12.1 build --bundles nsis -- --locked
Pop-Location
```

The installer output is under `target/release/bundle/nsis/`. It includes the
desktop resources and filter lists. The desktop loads those lists from Tauri's
resource directory, so startup does not depend on the launch directory.

A portable CLI directory contains:

```text
NullAD-cli/
  nullad-cli.exe
  lists/
    nullad-base.txt
    nullad-hosts.txt
```

The CLI finds default lists in `./lists`, then beside the executable. Use
`--list <PATH>` to select a specific list; the option is repeatable. A portable
CLI archive and an NSIS installer are separate artifacts and require separate
startup checks. `scripts/package-windows.ps1` produces desktop/CLI portable ZIPs,
the NSIS installer and SHA256SUMS.txt after both release builds complete.

## Use

```powershell
# Inspect the bundled lists and rules.
.\target\release\nullad-cli.exe load

# Evaluate a URL.
.\target\release\nullad-cli.exe check "https://ads.example.com/banner.gif"

# Include the initiating page and resource type.
.\target\release\nullad-cli.exe check "https://googletagmanager.com/gtm.js" --page "https://example.com/" --type script

# Run local HTTP and DNS listeners. Configure clients to use these endpoints.
.\target\release\nullad-cli.exe serve --port 8080 --dns-port 5353

# Opt in to changing the system proxy while serving.
.\target\release\nullad-cli.exe serve --port 8080 --system-proxy
```

The desktop interface defaults to **Simplified Chinese**, with **English**
available in settings. Listener settings changed during protection take effect
after a restart; status reports the actual bound ports and whether a restart is
needed. DNS is disabled by default. Starting a DNS listener does not itself
configure the operating system resolver.

| Mechanism | Filters | Limit |
|---|---|---|
| HTTP proxy | Plaintext HTTP URLs and paths | Does not inspect encrypted HTTPS paths or response content |
| TLS SNI | TLS connections by hostname | Encrypted Client Hello can hide that hostname |
| DNS sinkhole | Domain queries routed through its listener | Cannot identify a URL path or control applications using another resolver |

NullAD does not install a root certificate or decrypt HTTPS. Manual client
configuration and `--system-proxy` are distinct: system proxy integration only
covers applications that honor that platform's proxy settings. System DNS
changes need administrative privileges. Low-port binding rules vary by OS;
an unavailable port or insufficient privilege is reported by the listener.

CLI `serve` changes the system proxy only with `--system-proxy`, after every
requested listener binds. It journals the previous settings and, on Ctrl+C
(or Ctrl+Break on Windows), stops its listeners and connections before restoring
and verifying those settings. A restore failure exits with an error and retains
the recovery snapshot for the desktop application. An existing pending snapshot
must be restored before a new CLI session can take over the system proxy.

### Isolated settings and QA

By default, settings, data and logs use the operating system's per-user
directories. Set `NULLAD_HOME` to a **non-empty absolute path** to isolate them:

```powershell
$env:NULLAD_HOME = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'NullAD-QA'
.\target\release\nullad-desktop.exe
```

The isolated directory contains `config/`, `data/` and `logs/`. It is an
environment option, not a serialized setting. `NULLAD_WEBVIEW_DATA_DIR` can
also isolate WebView2's user-data directory on Windows. These variables isolate
application files; opting into system proxy changes still changes the real OS
configuration.

## Rules and loading

Supported rule forms include domain anchors (`||domain^`), start/end anchors,
separator markers, wildcards, exceptions (`@@`), regex literals and hosts-file
entries. Resource-type, third-party, domain, match-case and important options
are handled by the engine. Exceptions normally override blocking rules;
an important blocking rule overrides a non-important exception.

Cosmetic rules are recognized and counted but do not hide page elements.
The `$csp`, `$redirect` and `$removeparam` payloads are retained by the parser
but are not applied by the interceptors.

Malformed rules are quarantined. The desktop loader parses accepted content
once with its configured list ID and reuses one HTTP client. Failed reads,
zero-rule updates, HTML responses and excessive remote-list shrinkage do not
replace the last valid rules for the **same list ID and source**. Changing a
source does not reuse a different source's cached rules. Disabling every list
explicitly installs an empty set. A reload started against obsolete settings
cannot publish over a newer configuration.

## Recovery and platform boundaries

System changes are journaled before application. A partially failed apply
attempts rollback and retains its original snapshot. Restoration checks the
result before clearing that kind of entry; failed restoration remains visible
and can be retried. Journal updates are serialized and written atomically.
Corrupt recovery files are preserved and surfaced as an error.

Windows proxy changes use the current user's Internet Settings and broadcast
the update to applications. New snapshots preserve existence, registry type
and raw bytes of the four touched values; restoration sets or deletes exactly
from that snapshot. Legacy proxy snapshots without that metadata remain pending
with an error. Windows DNS snapshots retain an adapter GUID and
the IPv4 DHCP/static mode; current interface indices are resolved again when
restoring. Old DNS snapshots without a mode are retained with an error instead
of guessing whether they used DHCP. IPv6 system resolver configuration is not
modified by this adapter.

macOS and Linux are **not accepted release targets for automatic system
configuration** at present:

- **macOS:** service parsing and network-service identity need native validation;
  the generic proxy snapshot does not preserve separate HTTP/HTTPS settings or
  the complete PAC state. DHCP DNS currently cannot be captured by that backend.
- **Linux:** proxy integration targets GNOME `gsettings`, rather than every
  desktop. Auto mode, independent HTTPS state and bypass-list restoration have
  known gaps. Rewriting a regular `resolv.conf` does not preserve all original
  directives; managed symlinks are refused. NetworkManager/systemd-resolved
  integration is not implemented.

Mobile binaries, HTTPS URL inspection and page element hiding are outside the
current implementation.

## Tests and performance

Normal tests use mock system adapters, isolated files and local traffic
fixtures. Tests that write live proxy settings are ignored unless explicitly
selected. See [Windows validation](docs/windows-validation.md) before running
a live system test.

Five warmed runs per configuration compared the unchanged baseline and optimized
release builds on the same machine. With 100,000 synthetic rules, mixed-load
engine throughput was **1.030x**, while actual `decide` with its 500-entry log
was **11.485x**. Allocation in that decision path fell from about 480 KB to
116 B per request; the reused engine path was essentially unchanged. See
[performance validation](docs/performance.md) for latency, smaller workloads
and all raw data. A quick CLI measurement is:

```powershell
.\target\release\nullad-cli.exe bench --iterations 400000 --synthetic 300000 --json
```

The full comparison is recorded in `docs/performance-comparison.json`. Synthetic
matching results describe that workload; they do not establish real-network
throughput, complete Adblock Plus conformance, or another machine's performance.

## Architecture

| Component | Responsibility |
|---|---|
| `nullad-engine` | Parsing, indexes, matching and atomic rule-set replacement |
| `nullad-api` | Shared status types and interfaces |
| `nullad-intercept` | HTTP proxy, TLS hostname inspection, DNS UDP/TCP |
| `nullad-host` | OS proxy/DNS adapters, filesystem paths and recovery journal |
| `nullad-core` | Settings, runtime status, list loading and restoration reports |
| `nullad-cli` | `check`, `load`, `bench` and `serve` |
| `nullad-desktop` + `ui/` | Tauri shell, IPC commands, tray and interface |

The engine is shared across the CLI and desktop. The desktop owns asynchronous
listener lifecycle and task cancellation; it delegates system changes and
matching to the appropriate layers.

## License

MIT. See [LICENSE](LICENSE).
