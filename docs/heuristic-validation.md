# 无订阅识别验收 / Local detection validation

Recorded on Windows x86_64, Rust 1.96.0/MSVC, Edge 154.0.4258.53, 2026-10-05.
This is a follow-up to the historical Windows acceptance, not a claim that all
ads or all proxy applications have been tested. Usage: [no-subscription.md](no-subscription.md).

## 实际网站结果

The same isolated Edge profile visited [adblock.turtlecute.org](https://adblock.turtlecute.org/)
in Off → Balanced → Off order. No domain subscription was loaded in this run.
No classifier condition names this test site, its element IDs, or its host list.

| Mode | Site total | Static/dynamic cosmetic | ads.js/pagead.js | Actual browser blocked errors |
|---|---:|---|---|---:|
| Off | 16/132 (12.12%) | Both fail | Both fail | 0 |
| Balanced | 30/132 (22.73%) | Both pass | Both pass | 12 |
| Off again | 16/132 (12.12%) | Both fail | Both fail | 0 |

Two DOM containers were reversibly hidden. The twelve `ERR_BLOCKED_BY_CLIENT`
requests comprise the two scripts and ten advertising service requests. This
on/off comparison establishes actual added interception. The site's total also
counts network errors/timeouts and includes analytics/error telemetry, so 30/132
is not an attribution of thirty successful NullAD decisions or a general accuracy
metric. The remaining 102 tests were not blocked: **full coverage is not achieved**.
Raw reversible runs: [turtlecute-validation.json](turtlecute-validation.json).

A separate combined run used the unchanged 232 bundled native rules, Balanced
native detection and the extension. Browser → NullAD HTTP → the existing local
HTTP proxy software produced **60/132**, with all four cosmetic/script checks
passing. Existing system proxy configuration and proxy selectors were not edited.
That is one route and one site; it does not establish every proxy product/version.
Raw combined run: [turtlecute-combined-validation.json](turtlecute-combined-validation.json).

## 已通过 / Pass

- Windows format, strict workspace Clippy, release build and all-feature
  workspace tests: **273 passed, 0 failed, 3 explicitly ignored** (including
  one doc-test); core 34, host 35, interception unit tests 64. Ignored OS-write
  and IPv6 UDP fixtures are not counted as passed. Final Windows CI is available
  from the [PR checks](https://github.com/ZoeHao2026/NullAD/pull/1/checks).
- Four empty-list local socket fixtures cover effective HTTP, DNS and CONNECT
  detection and exceptions. Eight upstream socket fixtures cover HTTP absolute
  form/binary bodies, CONNECT prefixes, 1xx→2xx, SOCKS5 remote DNS and IPv6 encoding,
  refused-upstream no-direct-fallback, self-listener and resolved alias rejection.
- PSL private suffix regression protects hosted site apex names such as
  `adserver.github.io` and `adservice.pages.dev` from whole-site heuristic blocks.
  The embedded [PSL library](https://docs.rs/psl/latest/psl/) needs no runtime
  download; ABP engine party semantics remain unchanged.
- 38 extension Node tests and 14 desktop UI Node tests. Production manifest loads
  its actual background worker in isolated Edge without mandatory host access.
- Real Edge extension behavior on direct, HTTP and SOCKS5 routes: normal scripts,
  article content and protected forms remain visible; labelled/empty/dynamic,
  iframe and open Shadow DOM ads hide; ads.js/pagead.js fail with browser blocking
  errors; restore, exact-site allow, language and Stop work. HTTP fixture receives
  normal requests; SOCKS5 receives domain ATYP 3 (`proxy-fixture.invalid`).
  Raw protocol/browser evidence: [extension-browser-validation.json](extension-browser-validation.json).
- 54 browser assertions cover four desktop pages, explicit save/failure handling,
  polling after event rejection, Chinese/English, dark mode, default/minimum and
  equivalent 125%/150% viewport sizes. Browser plugin was unavailable; existing
  Playwright and installed Chrome provided this QA. This is separate from native
  Tauri IPC and actual Windows DPI acceptance.
- The final release native Tauri/WebView2 window was launched from outside the
  repository with isolated application files: 232 resources load; four pages,
  Chinese/English, dark mode, explicit save, invalid upstream draft retention,
  unmodified list configuration, live policy update and restart marker pass.
  With both lists disabled, real local HTTP produces 200 normal content and
  403 ad service blocking, with two fresh logs and `heuristic_ad_host` reason.
  Computer Use normal-close while active exits the no-tray process and allows
  the actual listener port to rebind. System proxy/DNS fingerprints match before
  and after; no takeover, selectors or OS resolver settings were modified.
- Cost measurements use five independent warmed processes per mode, alternating
  order, separate latency/allocation builds and actual bounded decision logs.
  See [performance.md](performance.md) and [raw data](heuristic-performance.json).

## 权限测试差异 / Permission boundary

Production is default-off and asks for optional HTTP/HTTPS origin access only
from a user gesture. The headless native permission prompt stayed pending;
it was not approved or bypassed, and no personal browser profile was changed.
Actual grant-dialog interaction is **Unknown**.

Functional browser runs used an isolated QA copy whose **only manifest change**
adds static `host_permissions` for exactly the same optional origins. Its JS/CSS
files match production. This establishes behavior after access is granted;
it does not prove the production browser permission UX. The shipped archive
contains the original optional-only manifest, never the QA manifest. The popup
was exercised as an extension page; toolbar placement/opening remains Unknown.

## 失败后修复 / Corrected checks

One final test attempt selected a TCP port that Windows reserved for UDP and
failed lifecycle startup with error 10013. The fixture now probes both protocols
with at most 128 attempts; the whole workspace rerun passed, including twenty
sequential cycles and forty concurrent lifecycle operations. Fixed production
ports continue reporting failures instead of silently moving.

Native QA scripts initially used a subscribed ad URL to assert detection Off
and then the wrong status DTO field name. Those harness assertions were corrected
by disabling lists and checking `needs_restart`; actual product behavior did
not fail. Earlier reports are retained in local evidence. Browser permission
grant remains unverified, not converted into a passing test.

## 未验收与边界 / Unknown and Deferred

Chrome's actual extension runtime, every third-party proxy program/version, PAC
execution, TUN/VPN routing, authenticated upstreams and proprietary protocols
remain unverified or unsupported. Tested HTTP/SOCKS5 fixtures are protocol
evidence, not product certification. Default-off independent extension does not
change proxy/DNS/certificates/request headers or require the desktop listener.

No 100% ad coverage is claimed. Unlabelled same-origin delivery, first-party
video inserts, closed Shadow DOM, browser-internal pages and service-worker or
CacheStorage-generated responses remain limits. DNR's service-worker boundary
is documented by [Chrome](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest#interactions-with-service-workers).
Bundled semantic conditions can still cause false positives: exact site allow,
DOM restore and Stop are escape paths. Feature scores are not probabilities.

NSIS installation/uninstallation, tray menus, actual OS 125%/150% DPI, privileged
Windows DNS and native IPv6 UDP remain Unknown. macOS/Linux native acceptance
is Deferred; historical restoration limitations remain in windows-validation.md.

Earlier system proxy restoration and native minimum-window evidence is historical
and does not certify new extension permissions or actual OS scaling. New native
settings/traffic evidence above uses the final release implementation; final
package smoke evidence records its runtime source separately.
