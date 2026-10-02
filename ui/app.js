/* NullAD desktop UI controller.
 *
 * Talks to the Rust side through Tauri's `invoke` and listens for the
 * `nullad://status` event that the backend emits once per second. All real work
 * happens in Rust; this file only renders state and forwards user intent.
 */
"use strict";

/* Tauri exposes its IPC bridge as a global when the app is packaged. During
 * development in a plain browser it is absent, so every call is guarded and the
 * UI degrades to a clear "backend unavailable" message rather than throwing. */
const invoke = window.__TAURI__ && window.__TAURI__.core
  ? window.__TAURI__.core.invoke
  : null;
const listen = window.__TAURI__ && window.__TAURI__.event
  ? window.__TAURI__.event.listen
  : null;

const $ = (id) => document.getElementById(id);

/** Latest status pushed by the backend. */
let status = null;
/** Latest decision log entries. */
let decisions = [];
/** Current log filter: all | blocked | allowed. */
let logFilter = "all";
/** Settings currently loaded from the backend. */
let settings = null;

/* ------------------------------------------------------------- formatting */

function fmtCount(n) {
  const value = Number(n) || 0;
  if (value >= 1_000_000) return (value / 1_000_000).toFixed(value >= 10_000_000 ? 0 : 1) + "M";
  if (value >= 10_000) return (value / 1_000).toFixed(value >= 100_000 ? 0 : 1) + "k";
  return String(value);
}

function fmtPercent(ratio) {
  const value = (Number(ratio) || 0) * 100;
  return value.toFixed(1) + "%";
}

function fmtTime(ms) {
  if (!ms) return "--:--:--";
  const d = new Date(Number(ms));
  if (Number.isNaN(d.getTime())) return "--:--:--";
  return d.toLocaleTimeString(undefined, { hour12: false });
}

function escapeHtml(text) {
  return String(text == null ? "" : text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/* ---------------------------------------------------------------- toasts */

function toast(message, kind) {
  const el = document.createElement("div");
  el.className = "toast" + (kind ? " is-" + kind : "");
  el.textContent = message;
  $("toasts").appendChild(el);
  setTimeout(() => el.remove(), kind === "error" ? 9000 : 5000);
}

/** Wraps an invoke call so a backend error becomes a visible toast. */
async function call(command, args) {
  if (!invoke) {
    toast("The NullAD backend is not available in this context.", "error");
    return null;
  }
  try {
    return await invoke(command, args || {});
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    toast(message, "error");
    return null;
  }
}

/* ------------------------------------------------------------ navigation */

function showView(name) {
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.classList.toggle("is-active", btn.dataset.view === name);
  });
  document.querySelectorAll(".view").forEach((view) => {
    view.classList.toggle("is-active", view.id === "view-" + name);
  });
  if (name === "rules") {
    loadLists();
    loadRuleViewer();
    loadCustomRules();
  }
  if (name === "settings") {
    loadSettings();
    loadPlatformInfo();
    loadPendingChanges();
  }
  if (name === "logs") {
    loadDecisions();
  }
}

document.getElementById("nav").addEventListener("click", (event) => {
  const button = event.target.closest(".nav-item");
  if (button) showView(button.dataset.view);
});

/* -------------------------------------------------------------- rendering */

function renderStatus(next) {
  status = next;
  if (!next) return;

  const engine = next.engine || {};
  const rules = next.rule_set || {};
  const ic = next.intercept || {};

  $("stat-queries").textContent = fmtCount(engine.queries);
  $("stat-blocked").textContent = fmtCount(engine.blocked);
  $("stat-allowed").textContent = fmtCount(engine.allowed);
  $("stat-ratio").textContent = fmtPercent(engine.block_ratio) + " of traffic";
  $("stat-exceptions").textContent = fmtCount(engine.exceptions_hit) + " by exception";
  $("stat-rules").textContent = fmtCount(rules.rules);
  $("stat-lists").textContent = (next.lists || []).filter((l) => l.enabled).length + " lists";
  $("rule-count").textContent = fmtCount(rules.rules) + " rules";

  $("ic-proxy").textContent = (ic.proxy_blocked || 0) + " / " + (ic.proxy_requests || 0);
  $("ic-sni").textContent = (ic.sni_blocked || 0) + " / " + (ic.sni_connections || 0);
  $("ic-dns").textContent = (ic.dns_blocked || 0) + " / " + (ic.dns_queries || 0);

  $("rs-domain").textContent = rules.domain_rules || 0;
  $("rs-domainpath").textContent = rules.domain_path_rules || 0;
  $("rs-fragment").textContent = rules.fragment_rules || 0;
  $("rs-regex").textContent = rules.regex_rules || 0;
  $("rs-trie").textContent = rules.trie_nodes || 0;
  $("rs-frag").textContent = rules.distinct_fragments || 0;

  const running = next.protection === "running";
  $("state-dot").className = "dot " + (running ? "is-running" : "");
  $("state-label").textContent = running ? "Running" : "Stopped";
  $("toggle-protection").textContent = running ? "Stop protection" : "Start protection";
  $("toggle-protection").classList.toggle("btn-primary", !running);
  $("toggle-protection").classList.toggle("btn-ghost", running);

  $("clear-log").disabled = false;

  if ($("view-logs").classList.contains("is-active")) {
    renderLogFeed();
  }
}

function renderFeed(entries, target) {
  if (!entries.length) {
    target.innerHTML = '<div class="empty">No requests yet. Start protection to see activity.</div>';
    return;
  }
  target.innerHTML = entries
    .map((entry) => {
      const cls = entry.blocked ? "is-blocked" : "is-allowed";
      const tag = entry.blocked ? "blocked" : "allowed";
      const rule = entry.rule ? " — " + escapeHtml(entry.rule) : "";
      return (
        '<div class="feed-row ' + cls + '" title="' + escapeHtml(entry.url) + rule + '">' +
          '<span class="feed-time">' + fmtTime(entry.timestamp_ms) + "</span>" +
          '<span class="feed-host">' + escapeHtml(entry.host || entry.url) + "</span>" +
          '<span class="feed-tag ' + cls + '">' + tag + "</span>" +
        "</div>"
      );
    })
    .join("");
}

function renderLogFeed() {
  let entries = decisions;
  if (logFilter === "blocked") entries = entries.filter((e) => e.blocked);
  if (logFilter === "allowed") entries = entries.filter((e) => !e.blocked);
  renderFeed(entries.slice(0, 400), $("log-feed"));
}

/* ----------------------------------------------------------------- views */

async function loadDecisions() {
  const result = await call("recent_decisions", { limit: 400 });
  if (Array.isArray(result)) {
    decisions = result;
    renderLogFeed();
    renderFeed(decisions.slice(0, 60), $("feed"));
  }
}

async function loadLists() {
  const lists = await call("list_lists");
  if (!Array.isArray(lists)) return;

  const body = $("lists-body");
  if (!lists.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty">No lists configured.</td></tr>';
    return;
  }

  body.innerHTML = lists
    .map((list) => {
      const checked = list.enabled ? "checked" : "";
      const dim = list.enabled ? "" : ' class="is-off"';
      return (
        "<tr" + dim + ">" +
          '<td><input type="checkbox" data-list-id="' + list.id + '" ' + checked + " /></td>" +
          "<td>" + escapeHtml(list.name) + "</td>" +
          '<td class="muted sm">' + escapeHtml(list.source) + "</td>" +
          '<td class="num">' + list.rules + "</td>" +
          '<td class="num">' + (list.failures ? '<span style="color:var(--warn)">' + list.failures + "</span>" : "0") + "</td>" +
          '<td class="num">' + list.cosmetic + "</td>" +
        "</tr>"
      );
    })
    .join("");

  body.querySelectorAll("input[data-list-id]").forEach((box) => {
    box.addEventListener("change", async () => {
      const result = await call("set_list_enabled", {
        id: Number(box.dataset.listId),
        enabled: box.checked,
      });
      reportReload(result);
      loadLists();
    });
  });
}

function reportReload(result) {
  if (!result) return;
  const parts = [result.rules + " rules loaded in " + result.elapsed_ms.toFixed(0) + " ms"];
  if (result.failures) parts.push(result.failures + " quarantined");
  toast(parts.join(", "), result.warnings && result.warnings.length ? "warn" : "ok");
  if (result.warnings && result.warnings.length) {
    result.warnings.forEach((warning) => toast(warning, "warn"));
    const status = $("custom-status");
    if (status) {
      status.textContent = result.warnings.join("\n");
      status.className = "hint is-warn";
    }
  }
}

async function loadRuleViewer() {
  const rules = await call("list_rules", { limit: 120 });
  if (!Array.isArray(rules)) return;

  $("rule-viewer-note").textContent = rules.length + " shown";
  const target = $("rule-viewer");
  if (!rules.length) {
    target.innerHTML = '<div class="empty">No rules loaded.</div>';
    return;
  }
  target.innerHTML = rules
    .map((rule) => {
      const cls = rule.action === "allow" ? "is-allowed" : "is-blocked";
      return (
        '<div class="feed-row ' + cls + '" title="' + escapeHtml(rule.pattern) + '">' +
          '<span class="feed-time">L' + rule.source_line + "</span>" +
          '<span class="feed-host">' + escapeHtml(rule.raw) + "</span>" +
          '<span class="feed-tag ' + cls + '">' + escapeHtml(rule.action) + "</span>" +
        "</div>"
      );
    })
    .join("");
}

async function loadCustomRules() {
  const text = await call("get_custom_rules");
  if (typeof text === "string") $("custom-rules").value = text;
}

async function loadSettings() {
  const loaded = await call("get_settings");
  if (!loaded) return;
  settings = loaded;

  $("set-proxy-enabled").checked = !!loaded.proxy_enabled;
  $("set-proxy-port").value = loaded.proxy_port;
  $("set-dns-enabled").checked = !!loaded.dns_enabled;
  $("set-dns-port").value = loaded.dns_port;
  $("set-dns-upstream").value = loaded.dns_upstream;
  $("set-dns-nxdomain").checked = !!loaded.dns_nxdomain;
  $("set-system-proxy").checked = !!loaded.intercept_system_proxy;

  $("dns-hint").textContent =
    loaded.dns_port < 1024
      ? "Ports below 1024 need administrator rights. 5353 is a good unprivileged choice."
      : "";
  $("dns-hint").className = loaded.dns_port < 1024 ? "hint is-warn" : "hint";
}

async function loadPlatformInfo() {
  const info = await call("platform_info");
  if (!info) return;
  $("ab-platform").textContent = info.platform;
  $("ab-elevated").textContent = info.elevated ? "yes" : "no";
  $("ab-rules").textContent = fmtCount(info.rule_count);
  $("ab-data").textContent = info.data_dir || "—";
  $("ab-config").textContent = info.config_dir || "—";
}

async function loadPendingChanges() {
  const pending = await call("pending_changes");
  if (!Array.isArray(pending)) return;
  const target = $("pending-changes");
  if (!pending.length) {
    target.textContent = "No outstanding system changes.";
    target.className = "hint is-ok";
    return;
  }
  target.textContent =
    pending.length + " change(s) still applied:\n" +
    pending.map((p) => "• " + p.description).join("\n");
  target.className = "hint is-warn";
}

/* --------------------------------------------------------------- actions */

$("toggle-protection").addEventListener("click", async () => {
  const running = status && status.protection === "running";
  $("toggle-protection").disabled = true;

  const notes = running
    ? await call("stop_protection")
    : await call("start_protection");

  $("toggle-protection").disabled = false;

  if (Array.isArray(notes)) {
    notes.forEach((note) => toast(note, note.toLowerCase().includes("could not") ? "warn" : "ok"));
  }
  refreshStatus();
});

$("clear-log").addEventListener("click", async () => {
  await call("clear_log");
  decisions = [];
  renderFeed([], $("feed"));
  renderLogFeed();
});

$("log-clear").addEventListener("click", async () => {
  await call("clear_log");
  decisions = [];
  renderLogFeed();
});

$("log-filter").addEventListener("change", (event) => {
  logFilter = event.target.value;
  renderLogFeed();
});

$("reload-lists").addEventListener("click", async () => {
  reportReload(await call("reload_lists"));
  loadLists();
  loadRuleViewer();
});

$("save-custom").addEventListener("click", async () => {
  const result = await call("set_custom_rules", { rules: $("custom-rules").value });
  reportReload(result);
  loadLists();
  loadRuleViewer();
});

$("do-check").addEventListener("click", async () => {
  const url = $("check-url").value.trim();
  if (!url) {
    toast("Enter a URL to check.", "warn");
    return;
  }
  const result = await call("check_url", {
    url: url,
    page: $("check-page").value.trim() || null,
    resourceType: $("check-type").value,
  });
  if (!result) return;

  const verdict = result.blocked ? "BLOCKED" : "ALLOWED";
  const cls = result.blocked ? "is-blocked" : "is-allowed";
  $("check-result").innerHTML =
    '<span class="verdict ' + cls + '">' + verdict + "</span>" +
    ' <span class="muted sm">' + result.matched + " rule(s) matched, host " +
    escapeHtml(result.host || "(unparsed)") + "</span>" +
    (result.rule ? '<div class="rule-line">decided by: ' + escapeHtml(result.rule) + "</div>" : "");
});

$("check-url").addEventListener("keydown", (event) => {
  if (event.key === "Enter") $("do-check").click();
});

$("run-bench").addEventListener("click", async () => {
  const target = $("bench-result");
  target.textContent = "Measuring…";
  target.className = "hint";
  const result = await call("benchmark", { iterations: 50000 });
  if (!result) {
    target.textContent = "Benchmark failed.";
    target.className = "hint is-warn";
    return;
  }
  target.textContent =
    result.iterations.toLocaleString() + " lookups over " + fmtCount(result.rules) + " rules\n" +
    "throughput: " + Math.round(result.throughput_per_sec).toLocaleString() + " lookups/sec\n" +
    "mean " + result.mean_us.toFixed(3) + " µs · p50 " + result.p50_us.toFixed(3) +
    " µs · p99 " + result.p99_us.toFixed(3) + " µs";
  target.className = "hint is-ok";
});

$("restore-system").addEventListener("click", async () => {
  const notes = await call("restore_system_changes");
  if (Array.isArray(notes)) notes.forEach((note) => toast(note, "ok"));
  loadPendingChanges();
  loadSettings();
});

/** Pushes the settings form back to the backend. */
async function saveSettings() {
  if (!settings) return;
  const next = Object.assign({}, settings, {
    proxy_enabled: $("set-proxy-enabled").checked,
    proxy_port: Number($("set-proxy-port").value) || 8080,
    dns_enabled: $("set-dns-enabled").checked,
    dns_port: Number($("set-dns-port").value) || 5353,
    dns_upstream: $("set-dns-upstream").value.trim() || "8.8.8.8:53",
    dns_nxdomain: $("set-dns-nxdomain").checked,
    intercept_system_proxy: $("set-system-proxy").checked,
  });

  const warnings = await call("update_settings", { settings: next });
  settings = next;
  if (Array.isArray(warnings) && warnings.length) {
    warnings.forEach((warning) => toast(warning, "warn"));
  } else {
    toast("Settings saved.", "ok");
  }
  loadPendingChanges();
}

[
  "set-proxy-enabled",
  "set-proxy-port",
  "set-dns-enabled",
  "set-dns-port",
  "set-dns-upstream",
  "set-dns-nxdomain",
  "set-system-proxy",
].forEach((id) => {
  $(id).addEventListener("change", saveSettings);
});

/* ---------------------------------------------------------------- startup */

async function refreshStatus() {
  const next = await call("get_status");
  if (next) renderStatus(next);
}

async function init() {
  if (!invoke) {
    toast(
      "Running outside the NullAD shell: no backend is connected, so this page " +
        "cannot read or change protection state.",
      "warn"
    );
    $("state-label").textContent = "Backend unavailable";
    return;
  }

  if (listen) {
    await listen("nullad://status", (event) => renderStatus(event.payload));
    await listen("nullad://request-start", () => $("toggle-protection").click());
    await listen("nullad://request-stop", () => {
      if (status && status.protection === "running") $("toggle-protection").click();
    });
    await listen("nullad://request-reload", async () => {
      reportReload(await call("reload_lists"));
      loadRuleViewer();
    });
  }

  await refreshStatus();
  await loadDecisions();
  await loadPendingChanges();

  // The event stream is authoritative, but a slow poll keeps the UI correct if
  // a push is ever missed.
  setInterval(refreshStatus, 5000);
  setInterval(() => {
    if ($("view-logs").classList.contains("is-active")) loadDecisions();
  }, 3000);
}

init();
