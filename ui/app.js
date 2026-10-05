/* Controller: navigation, user intent and refresh scheduling. No mock state. */
(function (root) {
  "use strict";
  const { ipc, state: helpers, i18n, views: v } = root.NullAD;
  const { $ } = v;
  const t = i18n.t;
  const fieldIds = { proxy_enabled:"set-proxy-enabled", proxy_port:"set-proxy-port", dns_enabled:"set-dns-enabled", dns_port:"set-dns-port", dns_upstream:"set-dns-upstream", dns_nxdomain:"set-dns-nxdomain", intercept_system_proxy:"set-system-proxy", heuristic_mode:"set-heuristic-mode", allowed_hosts:"set-allowed-hosts", upstream_proxy:"set-upstream-proxy" };
  let status = null, decisions = null, lists = null, parsedRules = null;
  let savedSettings = null, platform = null, benchmark = null, checkResult = null;
  let activeView = "dashboard", filter = "all", customDirty = false, customLoaded = false;
  let protectionPending = false, settingsPending = false, restorationPending = false;
  let statusPending = false, decisionsPending = false, clearPending = false;
  let eventError = null, statusError = null, unlisten = null, restoreReport = null;
  const feedback = {};
  let pendingChanges = 0;
  const errorText = (error) => error.message === "NULLAD_BACKEND_UNAVAILABLE" ? t("backendNotice") : error.message;
  function showError(error) { v.toast(errorText(error), "error"); }
  function toastKey(key, kind, values) { v.toast(t(key, values), kind, { key, values }); }
  function renderFeedback(id) {
    const item = feedback[id];
    if (item) v.hint(id, [item.key ? t(item.key, item.values) : item.raw, ...(item.suffix || [])].filter(Boolean).join("\n"), item.kind);
  }
  function setFeedback(id, key, kind, values, suffix) { feedback[id] = { key, kind, values, suffix }; renderFeedback(id); }
  function setErrorFeedback(id, error) { feedback[id] = { raw:errorText(error), kind:"error" }; renderFeedback(id); }
  function connectionMessage() { return statusError ? t("connectionFailed", { error:errorText(statusError) }) : eventError ? t("eventsFailed", { error:errorText(eventError) }) : ""; }
  function renderRestore() {
    if (!restoreReport) return;
    const remaining = helpers.pendingCount(restoreReport.pending_changes);
    const details = (restoreReport.items || []).map((item) => {
      const key = { systemproxy:"systemProxyKind", dnsresolver:"dnsResolverKind" }[String(item.kind).replace(/[^a-z]/gi, "").toLowerCase()];
      return (key ? t(key) : item.kind) + ": " + t(item.restored ? "restored" : "restoreFailed") + (item.error ? " — " + item.error : "");
    });
    setFeedback("restore-result", remaining ? "restorePartial" : "restoreSuccess", remaining ? "error" : "ok", { count:remaining }, details);
  }
  function currentPatch() {
    return helpers.listenerPatch(Object.fromEntries(helpers.fields.map((field) => {
      const el = $(fieldIds[field]);
      return [field, el.type === "checkbox" ? el.checked : el.value];
    })));
  }
  function syncSettingsControls() {
    const dirty = helpers.changed(savedSettings, currentPatch());
    $("save-settings").disabled = !ipc.available || !savedSettings || !dirty || settingsPending;
    $("cancel-settings").disabled = !dirty || settingsPending;
    $("set-dns-port").disabled = !ipc.available || settingsPending || !$("set-dns-enabled").checked;
    $("set-dns-upstream").disabled = !ipc.available || settingsPending || !$("set-dns-enabled").checked;
    $("set-dns-nxdomain").disabled = !ipc.available || settingsPending || !$("set-dns-enabled").checked;
  }
  function renderDynamic() {
    v.renderStatus(status, protectionPending);
    v.renderDecisions(decisions, filter, status);
    v.renderPending(pendingChanges, restorationPending);
    v.renderPlatform(platform, status);
    v.renderBenchmark(benchmark);
    v.renderCheck(checkResult);
    if (lists) v.renderLists(lists, toggleList);
    if (parsedRules) v.renderRules(parsedRules);
    Object.keys(feedback).forEach(renderFeedback);
    renderRestore();
    if (v.translateToasts) v.translateToasts();
    if (!ipc.available) {
      v.set("state-label", t("backendUnavailable"));
      v.notice("connection-notice", t("backendNotice"));
      $("toggle-protection").disabled = true;
      $("restore-system").disabled = true;
    } else v.notice("connection-notice", connectionMessage());
    syncSettingsControls();
  }
  function setLanguage(language) { i18n.apply(language); renderDynamic(); }
  async function refreshStatus() {
    if (!ipc.available || statusPending) return;
    statusPending = true;
    try {
      status = await ipc.call("get_status");
      pendingChanges = helpers.pendingCount(status.pending_changes);
      statusError = null;
      v.renderStatus(status, protectionPending);
      v.renderPending(pendingChanges, restorationPending);
      v.renderPlatform(platform, status);
      v.notice("connection-notice", connectionMessage());
    } catch (error) {
      statusError = error;
      v.notice("connection-notice", connectionMessage());
    } finally { statusPending = false; }
  }
  async function loadDecisions() {
    if (!ipc.available || decisionsPending || clearPending) return;
    decisionsPending = true;
    try {
      const loaded = await ipc.call("recent_decisions", { limit:500 });
      if (!Array.isArray(loaded)) throw new Error("Invalid decision-log response");
      if (!clearPending) { decisions = loaded; v.renderDecisions(decisions, filter, status); }
    } catch (error) { v.notice("connection-notice", t("connectionFailed", { error:errorText(error) })); }
    finally { decisionsPending = false; }
  }
  async function loadLists() {
    const loaded = await ipc.call("list_lists");
    if (!Array.isArray(loaded)) throw new Error("Invalid filter-list response");
    lists = loaded; v.renderLists(lists, toggleList);
  }
  async function loadRules() {
    parsedRules = await ipc.call("list_rules", { limit:120 });
    v.renderRules(parsedRules);
  }
  async function loadCustom() {
    if (customDirty || customLoaded) return;
    const text = await ipc.call("get_custom_rules");
    if (!customDirty) { $("custom-rules").value = text; customLoaded = true; }
  }
  async function loadSettings() {
    if (savedSettings && helpers.changed(savedSettings, currentPatch())) return;
    const loaded = await ipc.call("get_settings");
    savedSettings = loaded;
    v.fillSettings(loaded); syncSettingsControls();
  }
  async function loadPlatform() {
    platform = await ipc.call("platform_info"); v.renderPlatform(platform, status);
  }
  async function showView(name) {
    activeView = name;
    document.querySelectorAll(".nav-item").forEach((button) => {
      const selected = button.dataset.view === name;
      button.classList.toggle("is-active", selected);
      if (selected) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
    });
    document.querySelectorAll(".view").forEach((section) => {
      section.hidden = section.id !== "view-" + name;
      section.classList.toggle("is-active", !section.hidden);
    });
    $("main").scrollTop = 0;
    if (!ipc.available) return;
    try {
      if (name === "rules") await Promise.all([loadLists(), loadCustom()]);
      if (name === "settings") await Promise.all([loadSettings(), loadPlatform(), refreshStatus()]);
      if (name === "logs" || name === "dashboard") await loadDecisions();
    } catch (error) { showError(error); }
  }
  function reportReload(result) {
    const values = { rules:v.count(result.rules), ms:Number(result.elapsed_ms).toFixed(0), failures:v.count(result.failures) };
    const kind = result.warnings && result.warnings.length ? "warn" : "ok";
    toastKey("reloadResult", kind, values);
    setFeedback("custom-status", "reloadResult", kind, values, result.warnings || []);
  }
  async function toggleList(box) {
    const enabled = box.checked; box.disabled = true;
    try {
      const result = await ipc.call("set_list_enabled", { id:Number(box.dataset.listId), enabled });
      reportReload(result); await Promise.all([loadLists(), refreshStatus()]);
      if ($("parsed-rules").open) await loadRules();
    } catch (error) { box.checked = !enabled; showError(error); }
    finally { box.disabled = false; }
  }
  $("nav").addEventListener("click", (event) => { const button = event.target.closest("[data-view]"); if (button) showView(button.dataset.view); });
  document.querySelectorAll("[data-go]").forEach((button) => button.addEventListener("click", () => showView(button.dataset.go)));
  $("log-filter").addEventListener("click", (event) => {
    const button = event.target.closest("[data-filter]"); if (!button) return;
    filter = button.dataset.filter;
    $("log-filter").querySelectorAll("button").forEach((item) => {
      const selected = item.dataset.filter === filter;
      item.classList.toggle("is-active", selected); item.setAttribute("aria-pressed", String(selected));
    });
    v.renderDecisions(decisions, filter, status);
  });
  $("toggle-protection").addEventListener("click", async () => {
    if (protectionPending || helpers.isBusy(status)) return;
    protectionPending = true; v.renderStatus(status, true);
    try {
      const notes = await ipc.call(helpers.isActive(status) ? "stop_protection" : "start_protection");
      (notes || []).forEach((note) => {
        const key = { "Protection started":"protectionStarted", "Protection stopped":"protectionStopped" }[note];
        if (key) toastKey(key, "ok"); else v.toast(note, "warn");
      });
    } catch (error) { showError(error); }
    finally { protectionPending = false; await refreshStatus(); }
  });
  $("log-clear").addEventListener("click", async () => {
    if (clearPending) return;
    clearPending = true; $("log-clear").disabled = true;
    try {
      await ipc.call("clear_log"); decisions = [];
      v.renderDecisions(decisions, filter, status); toastKey("logsCleared", "ok");
    } catch (error) { showError(error); }
    finally { clearPending = false; $("log-clear").disabled = !ipc.available; }
  });
  $("reload-lists").addEventListener("click", async () => {
    $("reload-lists").disabled = true;
    try {
      reportReload(await ipc.call("reload_lists"));
      await Promise.all([loadLists(), refreshStatus()]);
      if ($("parsed-rules").open) await loadRules();
    } catch (error) { showError(error); }
    finally { $("reload-lists").disabled = !ipc.available; }
  });
  $("custom-rules").addEventListener("input", () => {
    customDirty = true; setFeedback("custom-status", "customUnsaved", "warn");
  });
  $("save-custom").addEventListener("click", async () => {
    $("save-custom").disabled = true; $("custom-rules").disabled = true;
    try {
      const result = await ipc.call("set_custom_rules", { rules:$("custom-rules").value });
      customDirty = false; customLoaded = true; reportReload(result);
      await Promise.all([loadLists(), refreshStatus()]);
      if ($("parsed-rules").open) await loadRules();
    } catch (error) { setErrorFeedback("custom-status", error); showError(error); }
    finally { $("save-custom").disabled = !ipc.available; $("custom-rules").disabled = !ipc.available; }
  });
  $("parsed-rules").addEventListener("toggle", async () => {
    if (!$("parsed-rules").open || !ipc.available) return;
    try { await loadRules(); } catch (error) { showError(error); }
  });
  $("check-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const url = $("check-url").value.trim(), page = $("check-page").value.trim();
    try {
      for (const value of [url, page].filter(Boolean)) if (!["http:", "https:"].includes(new URL(value).protocol)) throw new Error(t("invalidUrl"));
    } catch (_) { toastKey("invalidUrl", "warn"); return; }
    $("do-check").disabled = true;
    try {
      checkResult = await ipc.call("check_url", { url, page:page || null, resourceType:$("check-type").value });
      v.renderCheck(checkResult);
    } catch (error) { showError(error); }
    finally { $("do-check").disabled = !ipc.available; }
  });
  $("settings-form").addEventListener("input", () => {
    setFeedback("settings-status", helpers.changed(savedSettings, currentPatch()) ? "settingsUnsaved" : "", "warn");
    syncSettingsControls();
  });
  $("settings-form").addEventListener("change", syncSettingsControls);
  $("cancel-settings").addEventListener("click", () => {
    if (savedSettings) v.fillSettings(savedSettings);
    setFeedback("settings-status", ""); syncSettingsControls();
  });
  $("settings-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (settingsPending || !savedSettings) return;
    const patch = currentPatch(), invalid = helpers.validate(patch);
    if (invalid) { setFeedback("settings-status", invalid, "error"); toastKey(invalid, "warn"); return; }
    settingsPending = true; $("settings-form").querySelectorAll("input, select, textarea").forEach((el) => el.disabled = true);
    syncSettingsControls(); setFeedback("settings-status", "saving");
    try {
      const saved = await ipc.call("update_settings", { patch:helpers.settingsDelta(savedSettings, patch) });
      // Commit the UI snapshot only when persistence succeeded.
      savedSettings = saved; v.fillSettings(saved);
      setFeedback("settings-status", "settingsSaved", "ok"); toastKey("settingsSaved", "ok");
      await refreshStatus();
    } catch (error) { setErrorFeedback("settings-status", error); showError(error); }
    finally {
      settingsPending = false;
      $("settings-form").querySelectorAll("input, select, textarea").forEach((el) => el.disabled = !ipc.available);
      syncSettingsControls();
    }
  });
  $("language-select").addEventListener("change", async () => {
    const language = $("language-select").value;
    if (!ipc.available) { setLanguage(language); return; }
    $("language-select").disabled = true;
    try {
      const saved = await ipc.call("update_settings", { patch:{ ui_language:language } });
      if (savedSettings) savedSettings.ui_language = saved.ui_language;
      setLanguage(saved.ui_language);
    } catch (error) { $("language-select").value = i18n.language; showError(error); }
    finally { $("language-select").disabled = false; }
  });
  $("restore-system").addEventListener("click", async () => {
    restorationPending = true; v.renderPending(pendingChanges, true);
    try {
      const report = await ipc.call("restore_system_changes");
      restoreReport = report;
      pendingChanges = helpers.pendingCount(report.pending_changes);
      renderRestore();
      toastKey(pendingChanges ? "restorePartial" : "restoreSuccess", pendingChanges ? "error" : "ok", { count:pendingChanges });
      await refreshStatus();
    } catch (error) { restoreReport = null; setErrorFeedback("restore-result", error); showError(error); }
    finally { restorationPending = false; v.renderPending(pendingChanges, false); }
  });
  $("run-bench").addEventListener("click", async () => {
    $("run-bench").disabled = true; v.set("bench-result", t("measuring"));
    try { benchmark = await ipc.call("benchmark", { iterations:50000 }); v.renderBenchmark(benchmark); }
    catch (error) { v.set("bench-result", errorText(error)); showError(error); }
    finally { $("run-bench").disabled = !ipc.available; }
  });
  document.querySelectorAll("[data-copy]").forEach((button) => button.addEventListener("click", async () => {
    const input = $(button.dataset.copy); if (input.value === "—") return;
    try { await navigator.clipboard.writeText(input.value); toastKey("copied", "ok"); }
    catch (_) { input.focus(); input.select(); toastKey("copyFailed", "warn"); }
  }));
  async function init() {
    i18n.apply(i18n.language); renderDynamic();
    if (!ipc.available) return;
    document.querySelectorAll("[data-backend]").forEach((el) => el.disabled = false);
    try {
      unlisten = await ipc.listen("nullad://status", (event) => {
        status = event.payload; pendingChanges = helpers.pendingCount(status.pending_changes);
        v.renderStatus(status, protectionPending); v.renderPending(pendingChanges, restorationPending); v.renderPlatform(platform, status);
      });
    } catch (error) {
      eventError = error;
      v.notice("connection-notice", connectionMessage());
    }
    await refreshStatus();
    await Promise.all([
      loadDecisions(),
      loadSettings().then(() => setLanguage(savedSettings.ui_language)),
      loadPlatform()
    ]).catch(showError);
    setInterval(() => { if (!document.hidden) refreshStatus(); }, 5000);
    setInterval(() => { if (!document.hidden && ["dashboard", "logs"].includes(activeView)) loadDecisions(); }, 2000);
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) { refreshStatus(); if (["dashboard", "logs"].includes(activeView)) loadDecisions(); }
    });
    window.addEventListener("beforeunload", () => { if (unlisten) unlisten(); });
  }
  init().catch(showError);
})(window);
