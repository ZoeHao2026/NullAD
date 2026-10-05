(function () {
  "use strict";
  const { t, apply } = NullADText;
  const $ = (id) => document.getElementById(id);
  let tab = null, state = null, pending = false, feedback = null;
  const send = async (message) => { const result = await chrome.runtime.sendMessage(message); if (!result || !result.ok) throw new Error(result && result.error || "Extension worker did not reply"); return result; };
  function render() {
    if (!state) return;
    apply(state.settings.language);
    $("site").textContent = tab ? NullADPolicy.hostname(tab.url) : t("unsupportedPage");
    const allowed = tab && state.settings.allowSites.includes(NullADPolicy.hostname(tab.url));
    $("status").textContent = t(state.mode === "off" ? "statusOff" : "statusOn", { mode:t(state.mode) });
    $("permission").textContent = t(state.hasAccess ? "pagePermission" : "noPermission");
    $("hidden").textContent = state.hidden == null ? t("hiddenUnknown") : t("hidden", { count:state.hidden });
    $("rules-enabled").checked = state.settings.rulesEnabled;
    $("heuristics-enabled").checked = state.settings.heuristicsEnabled;
    $("rule-data").textContent = t("ruleData", { count:state.ruleData.domain_count, installed:state.installedNetworkRules });
    $("allow-site").textContent = t(allowed ? "resumeSite" : "allowSite");
    $("allow-status").textContent = allowed ? t("allowed") : "";
    if (feedback) { $("feedback").textContent = feedback.key ? t(feedback.key, feedback.values) : feedback.raw; $("feedback").classList.toggle("error", feedback.error); }
    else if (state.lastError) { $("feedback").textContent = t("failed", { error:state.lastError }); $("feedback").classList.add("error"); }
    else if (state.statsWarning) { $("feedback").textContent = state.statsWarning; $("feedback").classList.add("error"); }
  }
  function busy(value) { pending = value; document.querySelectorAll("button,select,input").forEach((element) => element.disabled = value); for (const id of ["enable-page", "enable-all", "allow-site", "restore"]) $(id).disabled = value || !tab; }
  async function refresh() { state = await send({ type:"STATE", tabId:tab && tab.id }); render(); }
  async function operation(action, key) {
    if (pending) return;
    busy(true);
    try { const result = await action(); feedback = result.warnings && result.warnings.length ? { raw:result.warnings.join("\n"), error:true } : { key }; await refresh(); }
    catch (error) { feedback = { key:"failed", values:{ error:error.message }, error:true }; if (state) render(); else { $("feedback").textContent = t("failed", { error:error.message }); $("feedback").classList.add("error"); } }
    finally { busy(false); }
  }
  for (const scope of ["page", "all"]) $("enable-" + scope).addEventListener("click", () => operation(async () => {
    if (!$("rules-enabled").checked && !$("heuristics-enabled").checked) throw new Error(t("chooseLayer"));
    // Request directly in this click gesture, before waiting for worker messages.
    const granted = await chrome.permissions.request({ origins:NullADPolicy.origins });
    if (!granted) throw new Error(t("denied"));
    const mode = $("mode").value === "off" ? state.settings.preferredMode : $("mode").value;
    return send({ type:"ENABLE", scope, mode, tabId:tab.id, rulesEnabled:$("rules-enabled").checked, heuristicsEnabled:$("heuristics-enabled").checked });
  }, "configured"));
  $("stop").addEventListener("click", () => operation(() => send({ type:"STOP" }), "stopped"));
  $("mode").addEventListener("change", () => { if ($("mode").value === "off") operation(() => send({ type:"STOP" }), "stopped"); });
  $("allow-site").addEventListener("click", () => operation(() => send({ type:"ALLOW_SITE", tabId:tab.id, allowed:!state.settings.allowSites.includes(NullADPolicy.hostname(tab.url)) }), "saved"));
  $("restore").addEventListener("click", () => operation(() => send({ type:"RESTORE", tabId:tab.id }), "restored"));
  $("options").addEventListener("click", () => chrome.runtime.openOptionsPage());
  $("language").addEventListener("change", () => operation(() => send({ type:"LANGUAGE", language:$("language").value }), "saved"));
  busy(true);
  chrome.tabs.query({ active:true, currentWindow:true }).then(async (tabs) => {
    const current = tabs[0];
    try { if (current) { $("site").textContent = NullADPolicy.hostname(current.url); tab = current; } } catch (_) { $("site").textContent = t("unsupportedPage"); }
    await refresh(); $("mode").value = state.mode === "off" ? state.settings.preferredMode : state.mode;
  }).catch((error) => { $("feedback").textContent = t("failed", { error:error.message }); $("feedback").classList.add("error"); }).finally(() => busy(false));
})();
