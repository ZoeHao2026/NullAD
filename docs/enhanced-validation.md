# 规则与免规则组合增强验收 / Combined protection validation

Windows x86_64 / Rust 1.96.0 MSVC / isolated Edge 154, 2026-10-05.
This records the second enhancement; [heuristic-validation.md](heuristic-validation.md)
and [windows-validation.md](windows-validation.md) retain historical results.

## 数据与组合方式

The seven official EasyList/EasyPrivacy inputs are pinned to
`129e63db3096f78e6dc94ac7ca6a15e27b5d1b79`. Original bytes, SHA256, attribution and
offline reproduction are in [the data documentation](../rules/README.md).
44,442 effective ASCII advertising/tracking domains supplement the original
base list; native GUI/CLI load **44,607 rules, zero quarantined**. The extension
installs those domains in 87 `requestDomains` conditions, separately from its
semantic requests and reversible DOM cleanup. Either layer can be selected or
both can run together. Protection activation remains default-off in the extension;
native defaults still do not take over system proxy or enable DNS.

Only unconditional domain anchors are extracted. Conditional rules are not
widened. Literal-host exceptions exclude matching ancestor/child blocks. This
is a conservative domain subset, **not full EasyList ABP execution**; generic or
regex exceptions cannot all be represented by this subset. Existing independent
base rules remain separately applied by the native engine. Derived domain data
uses CC-BY-SA-3.0; independent application code remains MIT. There are no runtime
downloads in the extension; upstream refresh is an explicit developer command.

## 目标网站实测

One isolated profile visited [the requested site](https://adblock.turtlecute.org/)
in the following order, using the extension alone and the same route:

| Layer | Site result | Static/dynamic containers | ads.js/pagead.js | Browser ERR_BLOCKED_BY_CLIENT |
|---|---:|---|---|---:|
| Off | 16/132 | Both fail | Both fail | 0 |
| Heuristics only | 30/132 | Both pass | Both pass | 12 |
| Domain rules only | 21/132 | Both fail | Both fail | 5 |
| Both | 33/132 | Both pass | Both pass | 15 |
| Off again | 16/132 | Both fail | Both fail | 0 |

The combination adds three observed network blocks beyond heuristics alone.
Two containers are reversibly hidden. Raw [five-phase evidence](enhanced-turtlecute-validation.json)
records errors independently of cosmetic results. The site also counts unrelated
network failures/timeouts and tests general analytics/error telemetry; its total
is neither a general accuracy metric nor attribution of every blocked test to NullAD.
**Full coverage remains unachieved.** No runtime condition names this site's IDs
or rewrites the site's results, and the imported source corpus is not selected
from its test-host list.

A separate route, browser → native NullAD HTTP (44,607 rules, Balanced) → existing
local HTTP proxy software, with both extension layers enabled produced **56/132**
in two runs. All four cosmetic/script checks passed. The recorded
[combined run](enhanced-turtlecute-combined-validation.json) is separate from the
direct-route comparison. The historical 232-rule run's 60/132 used another run
and snapshot; **these results do not establish an improvement over that score**.
Source coverage and real new features are the improvements. System proxy/DNS
[fingerprints match before/after](enhanced-network-validation.json); proxy selectors
and configuration were not edited.

## 已通过 / Pass

- Format, strict all-target/all-feature workspace Clippy, all-feature workspace
  tests: **283 passed, 0 failed, 3 explicitly ignored**, including a doc-test.
  Core 38; interception unit tests 70. Existing twenty sequential restart and
  forty concurrent lifecycle operation tests pass. Ignored OS-writing fixtures
  and IPv6 UDP are not counted as passed.
- **52 extension** and **14 desktop UI** Node tests; six Python generator tests.
  Coverage includes independent/cooperating layers, permission/API/persistence
  failures, allowance preservation, disabled catalog re-enable, multilingual/ARIA
  labels, mixed content protection, recycled content restoration, conditional
  extraction, Unicode rejection, source tampering, partial publication and failed
  rollback with a retained on-disk recovery copy.
- Real native HTTP/DNS/CLI end-to-end **23/23**: binary/coalesced request body,
  actual advertising block and reason, normal origin delivery, DNS sinkhole and
  upstream forwarding. The removed `graph.facebook.com` business API stays allowed
  with heuristic detection off. Zero-list SDK blocking is verified over real HTTP.
- Actual Edge API accepts every final semantic regular expression. The first
  oversized expression was rejected by RE2 memory limits; splitting into small
  conditions fixed the failure. Node regex checks alone are not used as evidence
  of browser support. Domain conditions do not expand 44,442 names into one regex.
- [Direct, HTTP and SOCKS5 local browser fixtures](enhanced-extension-browser-validation.json)
  preserve normal scripts/articles/forms and mixed/login containers; detect
  multilingual labels, child-label recycling, dynamic/iframe/open Shadow DOM ads;
  block scripts, restore DOM, allow exact sites and completely remove DNR conditions
  on Stop. SOCKS5 receives the domain target rather than locally resolved IPs.
- [An additional 738 real Edge assertions](enhanced-sdk-browser-validation.json)
  verify third-party Prebid/GPT/IMA SDK-shaped URLs fail with browser blocking
  errors and do not arrive at the local origin; same-origin SDKs, short `gpt.js`,
  documentation and login samples actually return 200 and reach the origin.
  These are local HTTP sentinel scripts, not execution of downloaded public SDKs.
  Real popup-page checkbox clicks select rules-only/heuristics-only/both, retain
  allowances and clear all conditions/registration on Stop. Chinese/English
  controls are scroll-accessible at 380×600, with no horizontal overflow or page
  errors. Reported runtime hashes match production JS/CSS; native toolbar opening
  and initial permission grant remain separately Unknown.
- Release workspace build and NSIS creation succeeded. The final NSIS-build GUI
  executable was launched with adjacent bundled resources and working directory
  outside the repository: 44,607 rules load; UI disables both lists while retaining
  both toggles, re-enables them, serves real normal **200**, domain-rule **403**,
  and zero-list SDK **403**, and shows three actual records. Four pages, Chinese/
  English and light/dark modes work. [Native evidence](enhanced-native-validation.json)
  records pending changes zero and stopping the test listener frees its port.
- Fresh CLI/desktop/extension ZIP extraction passed: the CLI loads 44,607 rules
  from beside its executable with an empty working directory outside the repository,
  zero-list SDK check blocks without a matched rule, and packaged real traffic
  passes 23/23. Packaged GUI bytes and rule data match the exact native executable
  and resources tested above. The extension archive contains 15 production files,
  version 0.2.0 and the original optional-only manifest, with no QA permissions or
  fixtures. Native portable packages include original rule inputs, source metadata,
  attribution and the offline generator. [Package evidence](enhanced-package-validation.json).
- Five warmed release processes per mode, separate latency/allocation binaries,
  nine cohorts and all bundled lists plus two fixture rules (44,609 total) measure
  the actual `decide`/bounded-log path. See [performance.md](performance.md) and
  [all 30 raw runs](enhanced-performance.json). Increased coverage has measured
  detection costs; no old benchmark speedup is reused.

## 失败后修复与未验收 / Corrected, Unknown and Deferred

The initial E2E fixture expected a normal business API removed from the old
demonstration list to remain blocked. It was replaced with an advertising host
from the new maintained data and a separate business-API allowance regression;
the rerun passed. The performance harness initially collided with existing base
regex rules; v2 uses asserted cohorts selected for the complete dataset and
cannot be directly compared with v1's two-rule absolute numbers.

Functional extension runs use an isolated QA manifest whose **only permission
change** adds static host access for the same optional HTTP/HTTPS origins. Runtime
JS/CSS match production. Production continues optional-only/default-off. Native
permission-dialog approval and actual toolbar-popup opening remain **Unknown**;
QA does not bypass or approve the production permission prompt and does not alter
personal browser profiles.

The user stopped Computer Use with physical Escape during the new native close
check. No further window input followed. Test listener cleanup used the backend
stop IPC; the native window remains available. **Normal window-close cleanup for
this new build is Unknown**, separately from earlier passing historical tests.

Every proxy product/version, PAC/TUN/VPN route, authenticated upstream, proprietary
protocol and native Chrome extension runtime are not comprehensively verified.
The extension leaves proxy/DNS/certificates/headers unchanged; protocol fixtures
support coexistence for those tested routes, not universal certification. No
100% advertisement coverage is claimed. Same-origin encrypted inserts, closed
Shadow DOM, browser internal pages and service-worker-generated responses remain
limits. DOM hidden-ancestor reinspection is bounded to four levels; independent
external `aria-labelledby` mutations have no global reverse index.

NSIS install/uninstall, tray interactions, actual OS 125%/150% DPI, privileged DNS,
native IPv6 UDP and macOS/Linux acceptance remain Unknown or Deferred. Historical
acceptance is not silently upgraded by this round's builds or fixtures.
