/* Renderers consume backend snapshots and never invent operational state. */
(function (root) {
  "use strict";
  const { state: helpers, i18n } = root.NullAD;
  const t = i18n.t;
  const esc = helpers.escapeHtml;
  const $ = (id) => document.getElementById(id);
  const set = (id, value) => { const el = $(id); if (el) el.textContent = value; };
  const count = (value) => Number(value || 0).toLocaleString(i18n.language);
  function toast(message, kind, translation) {
    const el = document.createElement("div");
    el.className = "toast" + (kind ? " is-" + kind : "");
    el.textContent = message;
    el.translation = translation;
    $("toasts").appendChild(el);
    setTimeout(() => el.remove(), kind === "error" ? 9000 : 5000);
  }
  function translateToasts() {
    $("toasts").querySelectorAll(".toast").forEach((el) => {
      if (el.translation) el.textContent = t(el.translation.key, el.translation.values);
    });
  }
  function notice(id, message) { const el = $(id); el.hidden = !message; el.textContent = message || ""; }
  function hint(id, message, kind) { const el = $(id); el.textContent = message || ""; el.className = "hint" + (kind ? " is-" + kind : ""); }
  function renderStatus(snapshot, pendingAction) {
    if (!snapshot) return;
    const { engine = {}, rule_set: rules = {}, intercept: ic = {} } = snapshot;
    const active = helpers.isActive(snapshot);
    const busy = pendingAction || helpers.isBusy(snapshot);
    const state = snapshot.protection || "stopped";
    set("state-label", t("state_" + state));
    $("state-dot").className = "status-dot is-" + state;
    set("toggle-protection", busy ? t("working") : t(active ? "stopProtection" : "startProtection"));
    $("toggle-protection").disabled = !!busy;
    set("state-description", state === "stopped" ? t("stoppedHint") : t(snapshot.proxy_port ? "proxyListening" : "proxyNotListening") + (i18n.language === "en" ? "; " : "，") + t(snapshot.dns_port ? "dnsListening" : "dnsNotListening", { address: "127.0.0.1:" + snapshot.dns_port }));
    set("proxy-address", snapshot.proxy_port ? "127.0.0.1:" + snapshot.proxy_port : t("notListening"));
    set("system-proxy-state", t(snapshot.intercept_system_proxy ? "proxyManaged" : "proxyUnmanaged"));
    set("dns-state", t(snapshot.dns_port ? "dnsListening" : "dnsNotListening", { address: "127.0.0.1:" + snapshot.dns_port }));
    notice("status-error", snapshot.last_error);
    $("restart-notice").hidden = !snapshot.needs_restart;
    // Traffic totals exclude URL diagnostics and benchmark engine lookups.
    const queries = (ic.proxy_requests || 0) + (ic.sni_connections || 0) + (ic.dns_queries || 0);
    const blocked = (ic.proxy_blocked || 0) + (ic.sni_blocked || 0) + (ic.dns_blocked || 0);
    set("stat-queries", count(queries)); set("stat-blocked", count(blocked));
    set("stat-ratio", queries ? (blocked / queries * 100).toFixed(1) + "%" : "—");
    set("stat-rules", count(rules.rules));
    set("enabled-lists", t("enabledLists", { count: (snapshot.lists || []).filter((list) => list.enabled).length }));
    set("stat-allowed", count(engine.allowed)); set("stat-exceptions", count(engine.exceptions_hit));
    for (const [id, value] of Object.entries({ "ic-proxy": (ic.proxy_blocked || 0) + " / " + (ic.proxy_requests || 0), "ic-sni": (ic.sni_blocked || 0) + " / " + (ic.sni_connections || 0), "ic-dns": (ic.dns_blocked || 0) + " / " + (ic.dns_queries || 0), "ic-dns-failed": ic.dns_failed || 0, "rs-domain": rules.domain_rules || 0, "rs-domainpath": rules.domain_path_rules || 0, "rs-fragment": rules.fragment_rules || 0, "rs-regex": rules.regex_rules || 0, "rs-trie": rules.trie_nodes || 0, "rs-frag": rules.distinct_fragments || 0 })) set(id, value);
  }
  function emptyRow(columns, heading, description) {
    return '<tr><td colspan="' + columns + '" class="empty-cell"><div class="empty-state"><img src="icons/file-earmark-text.svg" alt=""><strong>' + esc(heading) + '</strong><p>' + esc(description) + "</p></div></td></tr>";
  }
  function renderDecisions(entries, filter, snapshot) {
    if (!Array.isArray(entries)) {
      $("feed").innerHTML = emptyRow(4, t("waitingBackend"), "");
      $("log-feed").innerHTML = emptyRow(5, t("waitingBackend"), "");
      set("log-count", "—");
      return;
    }
    const decisionTag = (entry) => '<span class="decision is-' + (entry.blocked ? "blocked" : "allowed") + '">' + esc(t(entry.blocked ? "blocked" : "allowed")) + "</span>";
    const row = (entry, log) => {
      const date = new Date(Number(entry.timestamp_ms));
      const time = Number.isNaN(date.getTime()) ? "—" : date.toLocaleTimeString(i18n.language, { hour12: false });
      return "<tr><td>" + esc(time) + '</td><td title="' + esc(entry.url) + '">' + esc(entry.host || entry.url) + "</td>" + (log ? '<td title="' + esc(entry.url) + '">' + esc(entry.url) + "</td>" : "") + "<td>" + decisionTag(entry) + '</td><td class="rule-line" title="' + esc(entry.rule || t("noMatchedRule")) + '">' + esc(entry.rule || "—") + "</td></tr>";
    };
    $("feed").innerHTML = entries.length ? entries.slice(0, 8).map((entry) => row(entry, false)).join("") : emptyRow(4, t("noRequests"), snapshot && snapshot.proxy_port ? t("noRequestsHint", { address: "127.0.0.1:" + snapshot.proxy_port }) : t("noRequestsStopped"));
    const visible = helpers.filterDecisions(entries, filter);
    $("log-feed").innerHTML = visible.length ? visible.map((entry) => row(entry, true)).join("") : emptyRow(5, t(entries.length ? "noFilterLogs" : "noLogs"), t(entries.length ? "noFilterLogsHint" : "noLogsHint"));
    set("log-count", t("logCount", { count: count(visible.length) }));
  }
  function renderLists(lists, onToggle) {
    $("lists-body").innerHTML = lists.length ? lists.map((list) => '<tr class="' + (list.enabled ? "" : "is-off") + '"><td><input class="switch" type="checkbox" data-list-id="' + list.id + '" aria-label="' + esc(t("enabled") + " " + list.name) + '" ' + (list.enabled ? "checked" : "") + '></td><td>' + esc(list.name) + '</td><td class="muted">' + esc(list.source) + '</td><td class="num">' + count(list.rules) + '</td><td class="num">' + count(list.failures) + '</td><td class="num">' + count(list.cosmetic) + "</td></tr>").join("") : '<tr><td colspan="6" class="empty-cell">' + esc(t("noLists")) + "</td></tr>";
    $("lists-body").querySelectorAll("[data-list-id]").forEach((box) => box.addEventListener("change", () => onToggle(box)));
  }
  function renderRules(rules) {
    set("rule-viewer-note", t("shownRules", { count: rules.length }));
    $("rule-viewer").innerHTML = rules.length ? rules.map((rule) => '<div class="rule-row" title="' + esc(rule.pattern) + '"><span class="muted">L' + rule.source_line + "</span><code>" + esc(rule.raw) + '</code><span class="decision is-' + (rule.action === "allow" ? "allowed" : "blocked") + '">' + esc(t(rule.action === "allow" ? "allowed" : "blocked")) + "</span></div>").join("") : '<p class="hint">' + esc(t("noRules")) + "</p>";
  }
  function fillSettings(settings) {
    for (const field of helpers.fields) {
      const id = { proxy_enabled:"set-proxy-enabled", proxy_port:"set-proxy-port", dns_enabled:"set-dns-enabled", dns_port:"set-dns-port", dns_upstream:"set-dns-upstream", dns_nxdomain:"set-dns-nxdomain", intercept_system_proxy:"set-system-proxy" }[field];
      const el = $(id);
      if (el.type === "checkbox") el.checked = !!settings[field]; else el.value = settings[field];
    }
  }
  function renderPending(pending, busy) {
    const size = helpers.pendingCount(pending);
    set("pending-changes", t(size ? "pendingChanges" : "noPending", { count: size }));
    $("restore-system").disabled = !size || !!busy;
  }
  function renderPlatform(info, snapshot) {
    if (!info) return;
    set("platform-summary", t("platformSummary", { platform: info.platform, privileges:t(info.elevated ? "elevated" : "ordinary"), rules:count(snapshot ? snapshot.rule_set.rules : info.rule_count) }));
    set("ab-elevated", t(info.elevated ? "yes" : "no"));
    $("ab-data").value = info.data_dir || "—"; $("ab-config").value = info.config_dir || "—";
  }
  function renderBenchmark(result) {
    if (!result) return;
    set("bench-result", t("benchSummary", { throughput:count(Math.round(result.throughput_per_sec)), p50:result.p50_us.toFixed(3), p99:result.p99_us.toFixed(3) }));
    $("bench-result").title = t("benchDetail", { iterations:count(result.iterations), rules:count(result.rules), mean:result.mean_us.toFixed(3) });
  }
  function renderCheck(result) {
    if (!result) return;
    const target = $("check-result");
    target.className = "check-result is-result";
    target.innerHTML = '<span class="decision is-' + (result.blocked ? "blocked" : "allowed") + '">' + esc(t(result.blocked ? "blocked" : "allowed")) + '</span><span>' + esc(t("checkSummary", { count:result.matched, host:result.host || "—" })) + '</span><span class="rule-line">' + esc(result.rule || t("noMatchedRule")) + "</span>";
  }
  root.NullAD.views = { $, set, count, toast, translateToasts, notice, hint, renderStatus, renderDecisions, renderLists, renderRules, fillSettings, renderPending, renderPlatform, renderBenchmark, renderCheck };
})(window);
