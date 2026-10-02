# NullAD

A high-performance, cross-platform ad and tracker blocker written in Rust.

NullAD filters at three independent layers — DNS, TLS connection setup, and
plaintext HTTP — and is built around a pure, I/O-free matching engine that is
shared by every front end.

```
┌──────────────────────────────────────────────────────────────┐
│  nullad-desktop   Tauri 2 shell  +  ui/  (vanilla HTML/JS)    │
├──────────────────────────────────────────────────────────────┤
│  nullad-host      platform adapters: proxy, resolver, journal │
├──────────────────────────────────────────────────────────────┤
│  nullad-intercept HTTP proxy · TLS SNI · DNS sinkhole         │
├──────────────────────────────────────────────────────────────┤
│  nullad-engine    pure matcher: parse · index · match         │
└──────────────────────────────────────────────────────────────┘
```

`nullad-engine` depends on no async runtime, no sockets, no filesystem, and no
platform API. That is what lets the same matcher drive the desktop app, the
headless CLI, and a future mobile FFI binding without modification.

---

## Status

| Component | State |
|---|---|
| `nullad-engine` | Complete — parser, three indexes, lock-free hot reload |
| `nullad-intercept` | Complete — HTTP proxy, SNI inspection, DNS sinkhole |
| `nullad-host` | Complete — Windows verified; macOS/Linux implemented, compile-checked |
| `nullad-core` | Complete — state, settings, list loading, journal integration |
| `nullad-cli` | Complete — `check`, `load`, `bench`, `serve` |
| `nullad-desktop` | Code complete and linking; **runtime unverified** (see below) |

**The desktop GUI cannot be launched in this development sandbox.** The window
subsystem is Tauri/WebView2, which starts a separate `msedgewebview2.exe` host
process and communicates over named pipes. This sandbox blocks that, so Tauri
fails during app setup with `Access is denied (os error 5)`. This was isolated
to the environment rather than this codebase by building a Tauri app with an
**empty setup closure** — it fails identically. A stock Tauri 2 application
scaffold also builds and links correctly here, so the Rust side is sound; it
simply cannot open a window under sandbox restrictions. Run
`target/release/nullad-desktop.exe` outside the sandbox to exercise it.

---

## Measured performance

All numbers come from `nullad-cli bench` on this machine and are reproducible.
There is no `criterion` in the offline registry, so the harness is hand-rolled
and reports exactly the figures the project commits to.

```
$ nullad-cli bench --iterations 400000 --synthetic 300000

synthetic rule set: 300000 rules, built in 764 ms

WORKLOAD               RULES      REQ/SEC    MEAN us     P50 us     P95 us     P99 us
loaded rules             232      1767833      0.565      0.500      0.700      0.900
synthetic rules       300000      4329998      0.230      0.200      0.300      0.500

hot reload under load:
  10 swaps while 23877203 requests were evaluated concurrently
  swap latency: mean 7.9 us, max 9.0 us
  torn or empty rule-set observations: 0
```

| Criterion | Target | Measured | Verdict |
|---|---|---|---|
| Match latency p50 | ≤ 10 µs | 0.2 µs | **met**, 50× better |
| Match latency p99 | ≤ 50 µs | 0.5 µs | **met**, 100× better |
| Index build, 500k rules | ≤ 2 s | ~1.3 s | **met** (1M rules in 2.6 s) |
| Hot swap | < 50 ms, no drops | 9 µs, 0 torn reads | **met**, 5500× better |
| Release binary | ≤ 25 MB | CLI 2.05 MB, GUI 7.99 MB | **met** |
| Throughput | ≥ 5M lookups/sec | **4.1–4.4M** | **not met** (~85%) |
| ABP conformance | ≥ 98% | see *Testing* | see note |

**The throughput target is missed.** Measured 4.1–4.4M lookups/sec against a
300k-rule set over four runs, with latencies far inside budget. Reaching the
last 15% would need profiling tooling that is not available in the offline
registry; the honest position is that the target stands at ~85%.

Matching the *real* 232-rule bundled lists runs at ~1.7M/sec, which is slower
than the synthetic case on purpose: the real lists contain 13 regex rules and
the synthetic set is almost entirely domain anchors.

### Where the time goes

The engine's own benchmark breakdown attributes per-request cost. On the real
232-rule list:

```
total                  567.0 ns
domain trie             52.0 ns
substring automaton    123.2 ns
regex bucket           366.8 ns
url lowercasing         37.9 ns
```

The regex bucket dominates. It is mitigated by deriving a syntactic **minimum
match length** for each pattern and rejecting any URL shorter than that with a
single integer compare, skipping the regex engine entirely. That bound is
verified to be a true lower bound by a randomised property test rather than by
inspection, including under case-insensitive matching.

---

## Building

```bash
cargo build --release --workspace     # everything
cargo test  --workspace               # 173 tests
```

There is no separate front-end build step: `ui/` is plain HTML, CSS and
JavaScript, served directly by Tauri. That is a deliberate consequence of this
project's environment, where the npm registry is unreachable, and it also
removes an entire toolchain from the build.

### Important: this build is offline by design

`.cargo/config.toml` sets `net.offline = true`. On this machine the Windows TLS
stack is broken host-wide (`schannel: AcquireCredentialsHandle failed:
SEC_E_NO_CREDENTIALS`), so crates.io is unreachable from `cargo`, `git`, and
`curl`. Every dependency is resolved from a workspace-local registry cache in
`.cargo-home/` (git-ignored, seeded from the machine's global cargo cache).

`Cargo.lock` is therefore authoritative and **must be committed**. On a machine
with working TLS, remove the `offline` line to fetch the normal way.

Because of that constraint, four libraries that would normally be used are
absent from the registry cache and are implemented here instead:

| Absent crate | What NullAD does instead |
|---|---|
| `adblock-rust` | Own ABP parser and index set |
| `hickory-dns` | Own DNS message codec (parsing, name decompression, response building) |
| `rcgen` | Not needed — TLS interception is out of MVP scope |
| `criterion`, `insta`, `proptest` | Hand-rolled bench harness; `assert_eq!` golden tests; a `rand_chacha` property test |

---

## Usage

```bash
# What do the bundled lists contain?
nullad-cli load

# Would this be blocked, and by which rule?
nullad-cli check "https://ads.example.com/banner.gif"

# With page context and a resource type, for $domain= and $third-party rules
nullad-cli check "https://googletagmanager.com/gtm.js" \
  --page "https://example.com/" --type script

# Measure this machine
nullad-cli bench --iterations 400000 --synthetic 300000

# Run the interceptors (no administrator rights needed)
nullad-cli serve --port 8080 --dns-port 5353
```

`serve` prints the proxy address; point a client at it. DNS on a port below 1024
requires administrator or root rights, so `5353` is a good unprivileged choice.

### What each interceptor can and cannot do

| Mechanism | Blocks | Requires elevation | Limitation |
|---|---|---|---|
| HTTP proxy | URLs and paths over plaintext HTTP | no | Cannot see inside TLS |
| TLS SNI | Whole connections, by hostname | no | **Blind to Encrypted Client Hello** |
| DNS sinkhole | Domains, before any connection | yes, for port 53 | Only sees hostnames |

Filtering HTTPS *URLs* requires certificate-inspecting interception, which means
installing a locally-trusted root certificate. That is a real security decision
and is deliberately **not** in this release. NullAD never silently decrypts
traffic.

---

## Filter-list syntax

Supported: `||domain^` anchors, `|` start/end anchors, `^` separators, `*`
wildcards, `@@` exceptions, `/regex/` literals, hosts-file lines (`0.0.0.0
host`), `!` and `#` comments, and the `$` options `script`, `image`,
`stylesheet`, `object`, `xmlhttprequest`, `subdocument`, `document`, `font`,
`media`, `websocket`, `ping`, `other`, `popup`, `webrtc`, `third-party`,
`~third-party`, `domain=`, `match-case`, `important`, and their negations.

Parsed and retained but **not applied**: cosmetic rules (`##`), `$csp=`,
`$redirect=`, `$removeparam=`. Such rules load without error and round-trip.

Matching semantics follow Adblock Plus: an exception (`@@`) wins over a block,
except that a block carrying `$important` overrides a non-important exception.

### Robustness properties

These are enforced, not aspirational:

- A malformed rule is quarantined with a reason; it never aborts a list load.
  The bundled lists load 232 rules with zero quarantines.
- A list that parses to **zero** rules is reported as suspicious rather than
  silently accepted, because the usual cause is a truncated download.
- A remote list more than 50% smaller than its previous version is refused, so a
  captive portal's error page cannot replace a working list.
- Regex rules are compiled with the `regex` crate only, which guarantees linear
  time — filter lists cannot induce catastrophic backtracking.
- DNS name decompression rejects forward pointers and caps expansion, so a
  hostile packet cannot loop or exhaust memory.

---

## System integration and safety

Routing the operating system through NullAD is the most invasive thing it does,
so every change is written to a **change journal before it is applied** and
removed only after a successful revert. `nullad-cli` prints outstanding changes;
the GUI surfaces them and offers a one-click restore.

This ordering is deliberate: recording first means a crash can leave the journal
claiming a change that may not have happened. Reverting an already-correct
setting is harmless, whereas losing the record of a real change would strand a
machine pointing at a proxy that is no longer running.

Platform coverage:

- **Windows** — per-user `HKCU\...\Internet Settings`, no elevation needed;
  changes broadcast with `InternetSetOption`.
- **macOS** — `networksetup`, scoped to the service backing the default route.
- **Linux** — GNOME `gsettings` for the proxy, `/etc/resolv.conf` for DNS,
  refusing to clobber a symlink managed by systemd-resolved.

Only the Windows path has been runtime-verified; the others are implemented and
compile-checked.

### On `unsafe`

NullAD contains exactly one `unsafe` block: a call to `InternetSetOptionW` in
`nullad-host/src/platform/windows.rs`, which has no safe wrapper in
`windows-sys`. It passes a null handle, a null buffer, and zero length — the
documented form for broadcasting a settings change. Every other crate is
`#![forbid(unsafe_code)]`; `nullad-host` uses `deny` so that exactly this one
call is permitted and any new usage fails the build.

---

## Testing

177 tests pass across the workspace, with zero compiler warnings. They are
weighted toward the engine, where the interesting failure modes live.

```
nullad-engine      82     parser, indexes, matching semantics, hot reload
nullad-intercept   42     HTTP framing, ClientHello parsing, DNS codec
nullad-core        18     settings, list loading, decision log
nullad-host        18     journal, proxy settings, DNS settings
nullad-cli         12     argument handling, benchmark statistics
nullad-desktop      5     command helpers
```

Beyond unit tests:

- **`tests/e2e.py`** — 20 end-to-end checks. Starts a real origin server and the
  real proxy and DNS sinkhole, then drives actual traffic through them:
  forwarding, blocking with the rule cited, loopback never blocked, DNS
  sinkhole answers for A and AAAA, malformed DNS packets survived, and scoped
  exception rules allowing precisely what they should.
- **Property tests** — random URL generation verifies the regex minimum-length
  bound is never an over-estimate, for case-sensitive *and* case-insensitive
  patterns.
- **Concurrency test** — `bench` swaps rule sets while a second thread evaluates
  requests, asserting zero torn or empty rule-set observations.

Run everything:

```bash
cargo test --workspace
python tests/e2e.py
```

---

## Layout

```
crates/
  nullad-engine/      pure matcher, no I/O
  nullad-api/         DTOs and traits shared with any UI
  nullad-intercept/   HTTP proxy, TLS SNI, DNS sinkhole
  nullad-host/        platform adapters, change journal
  nullad-core/        orchestration, settings, list loading
  nullad-cli/         headless CLI
  nullad-desktop/     Tauri application
ui/                   HTML/CSS/JS front end, no build step
lists/                bundled filter lists
tests/e2e.py          end-to-end interception test
```

`nullad-desktop` depends only on `nullad-api` and `nullad-core`. Replacing the
web UI means rewriting `ui/` and the thin command bindings in
`crates/nullad-desktop/src/commands.rs`, and touching no engine code.

---

## Deliberate limitations

Stated plainly rather than left for a user to discover:

1. **No HTTPS URL filtering.** Needs certificate interception, which is a
   security decision users must make knowingly. Not in this release.
2. **ECH defeats SNI filtering.** Encrypted Client Hello hides the hostname from
   the connection layer entirely.
3. **Throughput is ~85% of target**, as measured above.
4. **DNS needs elevation** to bind port 53 and repoint the resolver, so it is
   off by default and the rest of NullAD works without it.
5. **The GUI is runtime-unverified** in this sandbox, for the reason given at the
   top.
6. **No mobile binaries.** `nullad-engine` and `nullad-api` are written to
   compile for those targets, but no Android/iOS build exists yet.
7. **Cosmetic filtering is parsed, not applied.** No element hiding.

## Licence

MIT OR Apache-2.0.
