# Windows validation / Windows 验收

This document distinguishes verified behavior from remaining acceptance work.
It contains no personal machine paths, account identifiers or adapter GUIDs.

## New local detection follow-up

The 2026-10-05 implementation adds local detection, independent browser cleanup
and explicit HTTP/SOCKS5 chaining. [New acceptance](heuristic-validation.md)
separates actual Edge behavior and site results from unverified optional
permission UI and universal proxy compatibility. [Cost measurements](performance.md)
record the new default path separately from the historical baseline below.
New Windows CI also includes 38 extension tests.
Final local engineering checks: 273 workspace tests passed (0 failed, 3 ignored),
core 34/host 35; 14 UI tests and 38 extension tests. Fmt, strict Clippy and final
release build pass. New native Tauri four-page/settings/real zero-list traffic
and no-tray close pass separately; native DPI/tray and extension permission
grant are still Unknown. The final remote run is linked in the PR checks.

## Historical recorded result (5ac216b / documentation 422eb53)

| Check | Result | Evidence and limit |
|---|---|---|
| Engineering checks | **Pass** | Windows fmt, strict Clippy, release workspace build and all-feature workspace tests: 229 passed, 0 failed, 3 explicitly ignored (includes a doc-test); core 30, host 32 |
| Local HTTP/DNS | **Pass** | 22 real socket fixtures: same/split packet binary/chunked HTTP, CONNECT prefix, DNS concurrency, TCP and truncation fallback |
| Lifecycle | **Pass** | 20 sequential cycles and 40 concurrent start/stop operations, idempotent calls, occupied second listener rollback and port rebind |
| Settings / rule / recovery regressions | **Pass** | Failed persistence does not publish settings, current list identity retains last valid rules, obsolete reload cannot publish; failed/legacy restores retain evidence |
| Live Windows proxy apply/revert | **Pass** | Explicit opt-in tests capture a baseline first and restore four raw registry fields; DNS unchanged, pending=0 |
| CLI shutdown / startup boundary | **Pass** | Default no OS change, failed DNS bind prevents proxy takeover, explicit takeover then Ctrl+Break exits with exact proxy restore |
| Native desktop | **Pass** | Four pages, real IPC, 232 bundled rules outside repo, Chinese/English, dark theme, real HTTP/log updates, save drafts, actual ports, restart marker, custom save/interception and URL checks |
| No-tray native close | **Pass** | Active protection, normal close, process exits and both old/new ports rebind; no pending journal |
| UI failure and layout checks | **Pass** | 11 Node tests and 54 browser assertions; four concept-image comparisons, default/minimum and equivalent 125%/150% viewports, no page errors |
| Privileged system DNS apply/revert | **Unknown** | Process not elevated; no system DNS setting modified. DHCP/static, interface identity and legacy rejection have isolated tests |
| Windows IPv6 UDP upstream | **Unknown** | Native IPv6 UDP loopback probe timed out, including outside NullAD; ignored fixture does not establish application acceptance |
| Native minimum window | **Pass** | Final portable GUI checked on all four pages at 840x560 content size; settings Save remains visible, tables scroll, real records update and timestamps stay on one line |
| Tray / actual OS DPI | **Unknown** | Tray menu operations and real 125%/150% OS scaling remain unverified; browser equivalents are recorded separately |
| NSIS / portable archives | **Pass** | NSIS builds; extracted CLI loads 232 bundled rules and passes 22 traffic checks from unrelated cwd; extracted GUI loads 232, serves local HTTP and blocks an ad/custom domain. Installation/uninstallation remains Unknown |
| Remote Windows CI | **Pass** | [PR run 37204735279](https://github.com/ZoeHao2026/NullAD/actions/runs/37204735279), source 5ac216b: formatting, strict Clippy, workspace/UI tests, release, 22 local traffic fixtures, NSIS, ZIP/checksums and artifact upload all passed |
| Performance | **Pass** | Same-machine alternating five runs per configuration; engine and actual decide latency/throughput/allocation in [performance.md](performance.md), all raw runs in [JSON](performance-comparison.json) |
| macOS/Linux native acceptance | **Deferred** | Known recovery gaps below; not accepted as Windows validation |

Recorded environment: Windows x86_64, Rust 1.96.0, release builds, MSVC, installed WebView2. No failed final ordinary check is being hidden as a pass. Unknown/Deferred rows remain outside the verified result.

The first remote Clippy run failed on a deprecated test helper; the linked
runtime-source run passed after that correction. A subsequent documentation-only
CI run exposed Windows temporary DNS port pairing: a UDP automatic port was not
available to TCP. Automatic pairing now selects TCP first and retries the UDP
companion up to 128 candidates on conflicts; a configured fixed port still fails
without choosing another port. The local upstream fixture follows the same
constraint, and a real occupied-UDP regression verifies rollback releases TCP.
The linked current runtime-source CI run passed after that correction.
Local packages were rebuilt from 5ac216b. Earlier artifacts and checksums remain
historical evidence; packages from separate builds have separate checksums.

One registry round-trip unit test and the live acceptance test are ignored
during normal test execution. A normal test-suite pass therefore does not
include an OS mutation test.

## Reproduce ordinary checks

Prerequisites: Rust 1.96+, MSVC C++ build tools and Windows SDK, WebView2 Runtime,
Node.js and Python. From the repository root:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
node --test ui/tests/ui.test.cjs
cargo build --release --workspace --locked
python tests/e2e.py
```

Use the standard Cargo cache and network. `--offline` is opt-in and requires
previously cached dependencies. `scripts\build.bat release` initializes MSVC
when required; `scripts\build.bat release --offline` is its offline variant.

## Isolate application files

The following variables affect the launched process and its children:

```powershell
$qaRoot = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'NullAD-QA'
$env:NULLAD_HOME = $qaRoot
$env:NULLAD_WEBVIEW_DATA_DIR = Join-Path $qaRoot 'webview'
```

`NULLAD_HOME` must be an absolute, non-empty path. Settings are in
`config/settings.json`, recovery in `data/change-journal.json`, and file logs
in `logs/`. This isolates user files, but does **not** simulate OS proxy or
resolver settings.

## Explicit live proxy acceptance

This test temporarily changes the current user's system proxy. Run it only
when that change is intended, with the normal application and other NullAD
instances stopped. It captures the complete baseline first, installs a
temporary loopback listener address, restores through the journal, then checks
all proxy fields and the untouched DNS configuration. A cleanup guard attempts
restoration if an assertion fails; durable recovery evidence remains available.

```powershell
$qaRoot = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'NullAD-Live-QA'
$env:NULLAD_HOME = $qaRoot
$env:NULLAD_LIVE_SYSTEM_TEST = '1'
New-Item -ItemType Directory -Path $qaRoot -Force | Out-Null
$env:NULLAD_ACCEPTANCE_OUTPUT = Join-Path $qaRoot 'windows-system-baseline.json'
cargo test -p nullad-host --locked --test live_windows live_windows_proxy_apply_restore_preserves_system_baseline -- --ignored --nocapture --test-threads=1
```

The report includes only presence/type/byte-length summaries for raw registry
fields and redacts PAC data. A complete raw recovery copy stays under the
isolated data directory, outside public documentation. New Windows snapshots
restore missing values by deletion and retain nondefault registry types. Legacy
proxy snapshots without raw metadata are retained with an error before any write.
The recorded acceptance result was **Pass**, with exact proxy restoration,
unchanged DNS and zero pending changes.

Remove the opt-in variable after the run:

```powershell
Remove-Item Env:NULLAD_LIVE_SYSTEM_TEST
```

The live proxy test does not perform a privileged DNS write. Such validation
must separately capture each interface and its DHCP/static mode, use already
available administrative rights, restore the exact configuration, and verify
the result. A legacy snapshot without mode must remain unresolved; do not
guess. This acceptance remains **Unknown**.

## Native acceptance checklist and package reproduction

- Open the desktop with an isolated profile. Verify the default Chinese
  interface and English switch, including tray labels and persistence.
- Confirm installed bundled lists load with a nonzero rule count from an
  unrelated working directory.
- Start and stop twice. Verify HTTP and both DNS transports release their
  ports, do not continue serving after stop, and can restart.
- Change a listener setting while running. Verify status continues reporting
  the actual listener, shows restart required, and applies the edit after restart.
- Exercise occupied ports and invalid upstreams. Verify failure status,
  useful errors, cleanup and retained recovery entries when restoration fails.
- Close with a working tray, then reopen through the tray. Test the window-only
  fallback and application exit, including a second exit request during cleanup.
- Verify a pending journal is visible after interruption, failed restoration
  stays pending, and successful restoration clears only the recovered kind.

Build an NSIS installer:

```powershell
Push-Location crates/nullad-desktop
npx --yes @tauri-apps/cli@2.12.1 build --bundles nsis -- --locked
Pop-Location
```

Verify the generated installer from `target/release/bundle/nsis/` and a separate
portable CLI folder containing `nullad-cli.exe` plus `lists/*.txt`. Extract the
CLI into a clean directory and run `load`, `check` and `serve` from another
working directory. The package script creates both portable ZIPs, the exact-version NSIS installer
and SHA256SUMS.txt:

```powershell
./scripts/package-windows.ps1
```

The script requires all release inputs, refuses existing output artifacts,
prepares the whole batch before publishing and cleans only its own staging.
CI runs the same script. Installation and uninstallation need separate native
acceptance; successful packaging is not evidence of installation.

## Other platform boundaries

macOS and Linux native acceptance is **not recorded**. Existing backends do
not imply exact recovery:

- macOS service selection and identity, independent HTTP/HTTPS settings and
  PAC enable state need correction/native validation. DHCP DNS capture is
  currently rejected.
- Linux GNOME auto mode, independent HTTPS and bypass-list restoration have
  gaps. Regular `resolv.conf` rewriting loses other directives; managed
  symlinks are rejected. NetworkManager/systemd-resolved integration is absent.

Windows system DNS currently handles IPv4 configuration only. IPv6 DNS
transport and IPv6 OS resolver configuration are different capabilities;
successful A/AAAA response construction is not evidence that either has been
validated on the native Windows network stack.

## CLI live lifecycle reproduction

Stop other NullAD system-proxy sessions and capture/recover the current user
baseline. The script requires an explicit opt-in and uses isolated application
files; it still temporarily changes the real system proxy.

```powershell
python tests/cli-lifecycle.py --cli ./target/release/nullad-cli.exe --output ./cli-lifecycle.json --allow-system-proxy
```

Sensitive raw backups stay in the isolated work directory; the exported report
contains field presence/type/byte length and equality results. Ordinary CI does
not run this OS mutation script or machine-comparison performance measurements.

## Configuration references

Tauri bridge/resource configuration follows the [Tauri configuration reference](https://v2.tauri.app/reference/config/). Regex length rejection uses [HIR Properties.minimum_len](https://docs.rs/regex-syntax/latest/regex_syntax/hir/struct.Properties.html#method.minimum_len) with the same case settings as compilation; differential and match-case regressions cover that path.
