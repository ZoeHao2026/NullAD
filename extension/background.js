/* Event-driven MV3 worker. Persistent policy is local; per-tab mode is session-only. */
if (typeof importScripts === "function") importScripts("policy.js");
(function (root) {
  "use strict";
  const policy = typeof module !== "undefined" && module.exports ? require("./policy.js") : root.NullADPolicy;
  function createService(api) {
    let serial = Promise.resolve();
    const lock = (operation) => { const result = serial.then(operation); serial = result.catch(() => {}); return result; };
    function required() {
      if (!api.declarativeNetRequest || !api.scripting || !api.storage.session) throw new Error("Required MV3 DNR/scripting/session APIs are unavailable");
    }
    async function read() {
      const local = await api.storage.local.get("settings");
      const session = await api.storage.session.get(["pages", "reports", "lastError"]);
      return { settings:policy.normalizeSettings(local.settings), pages:session.pages || {}, reports:session.reports || {}, lastError:session.lastError || null };
    }
    const permitted = () => api.permissions.contains({ origins:policy.origins });
    function isExtensionPage(sender) {
      if (!sender.url || !api.runtime || typeof api.runtime.getURL !== "function") return false;
      try {
        const actual = new URL(sender.url); actual.search = ""; actual.hash = "";
        return ["popup.html", "options.html"].some((page) => actual.href === api.runtime.getURL(page));
      } catch (_) { return false; }
    }
    function summary(value = {}) {
      return { hidden:Math.max(0, Math.min(2000, Number(value.hidden) || 0)), mode:policy.modes.includes(value.mode) ? value.mode : "off", reasons:Array.isArray(value.reasons) ? value.reasons.slice(0, 20).map((entry) => ({ score:Number(entry.score) || 0, reasons:Array.isArray(entry.reasons) ? entry.reasons.slice(0, 5).filter((value) => typeof value === "string").map((value) => value.slice(0, 80)) : [] })) : [] };
    }
    async function snapshot(tabId, restore = false) {
      const frames = await api.scripting.executeScript({ target:{ tabId, allFrames:true }, world:"ISOLATED", args:[restore], func:(restore) => {
        const controller = globalThis.__nulladLocalController;
        if (restore && controller) controller.restoreAll();
        return controller ? controller.stats() : { hidden:0, mode:"off", reasons:[] };
      } });
      if (!Array.isArray(frames) || !frames.length) throw new Error("Current page frames did not return their cleanup status");
      return Object.fromEntries(frames.map((frame) => [frame.frameId, summary(frame.result)]));
    }
    async function apply(data, hasAccess) {
      required();
      const tabs = await api.tabs.query({});
      const dynamic = hasAccess && data.settings.mode !== "off" ? [...policy.blockRules(data.settings.mode), ...policy.allowRules(data.settings.allowSites)] : [];
      const session = hasAccess ? policy.sessionRules(data.settings, data.pages, tabs).rules : [];
      const regexes = [...new Set([...dynamic, ...session].map((rule) => rule.condition.regexFilter).filter(Boolean))];
      for (const regex of regexes) {
        const supported = await api.declarativeNetRequest.isRegexSupported({ regex, isCaseSensitive:false });
        if (!supported.isSupported) throw new Error("Unsupported network heuristic: " + (supported.reason || regex));
      }
      const oldDynamic = await api.declarativeNetRequest.getDynamicRules();
      const oldSession = await api.declarativeNetRequest.getSessionRules();
      try {
        await api.declarativeNetRequest.updateDynamicRules({ removeRuleIds:oldDynamic.map((rule) => rule.id), addRules:dynamic });
        await api.declarativeNetRequest.updateSessionRules({ removeRuleIds:oldSession.map((rule) => rule.id), addRules:session });
      } catch (error) {
        const current = await api.declarativeNetRequest.getDynamicRules();
        await api.declarativeNetRequest.updateDynamicRules({ removeRuleIds:current.map((rule) => rule.id), addRules:oldDynamic });
        throw error;
      }
      try {
        const registered = await api.scripting.getRegisteredContentScripts();
        const active = hasAccess && (data.settings.mode !== "off" || Object.keys(data.pages).length > 0);
        if (active && !registered.some((script) => script.id === "nullad-local")) {
          await api.scripting.registerContentScripts([{ id:"nullad-local", matches:policy.origins, js:["detector.js", "content.js"], runAt:"document_idle", allFrames:true, world:"ISOLATED", persistAcrossSessions:true }]);
        } else if (!active && registered.some((script) => script.id === "nullad-local")) {
          await api.scripting.unregisterContentScripts({ ids:["nullad-local"] });
        }
      } catch (error) {
        const currentDynamic = await api.declarativeNetRequest.getDynamicRules(), currentSession = await api.declarativeNetRequest.getSessionRules();
        await api.declarativeNetRequest.updateDynamicRules({ removeRuleIds:currentDynamic.map((rule) => rule.id), addRules:oldDynamic });
        await api.declarativeNetRequest.updateSessionRules({ removeRuleIds:currentSession.map((rule) => rule.id), addRules:oldSession });
        throw error;
      }
      // Registration removal does not remove effects in existing documents.
      const warnings = [];
      for (const tab of tabs) {
        const mode = hasAccess ? policy.pageMode(data.settings, data.pages, tab) : "off";
        try {
          if (mode !== "off") await api.scripting.executeScript({ target:{ tabId:tab.id, allFrames:true }, files:["detector.js", "content.js"], world:"ISOLATED" });
          await api.tabs.sendMessage(tab.id, { type:"CONFIGURE", mode });
        } catch (error) {
          if (mode !== "off") warnings.push("Page cleanup could not start in tab " + tab.id + ": " + String(error.message || error));
          else if (Object.values(data.reports[tab.id] || {}).some((report) => report.hidden > 0)) warnings.push("Network protection stopped, but page restoration could not be confirmed in tab " + tab.id + ": " + String(error.message || error) + ". Reload this page to remove previous DOM effects.");
        }
      }
      return { networkRules:dynamic.filter((rule) => rule.action.type === "block").length + session.filter((rule) => rule.action.type === "block").length, hasAccess, warnings };
    }
    async function change(transform) {
      return lock(async () => {
        required();
        const previous = await read(), next = structuredClone(previous);
        await transform(next);
        const access = await permitted();
        if ((next.settings.mode !== "off" || Object.keys(next.pages).length) && !access) throw new Error("Access to HTTP/HTTPS page resources has not been granted");
        const result = await apply(next, access);
        try {
          await api.storage.local.set({ settings:next.settings });
          await api.storage.session.set({ pages:next.pages, reports:next.reports, lastError:null });
        } catch (error) {
          await api.storage.local.set({ settings:previous.settings }).catch(() => {});
          await api.storage.session.set({ pages:previous.pages, reports:previous.reports }).catch(() => {});
          await apply(previous, access);
          throw error;
        }
        return { ...next, ...result };
      });
    }
    async function handle(message, sender = {}) {
      required();
      if (message.type === "GET_CONFIG") {
        const data = await read();
        return { mode:await permitted() && sender.tab ? policy.pageMode(data.settings, data.pages, sender.tab) : "off" };
      }
      if (message.type === "REPORT") {
        if (!sender.tab) throw new Error("Page report requires a tab sender");
        return lock(async () => {
          const { reports } = await read();
          const value = message.stats || {};
          reports[sender.tab.id] = reports[sender.tab.id] || {};
          reports[sender.tab.id][sender.frameId || 0] = summary(value);
          await api.storage.session.set({ reports });
          return {};
        });
      }
      // Page scripts can report observations, never mutate extension policy.
      if (sender.tab && !isExtensionPage(sender)) throw new Error("Policy changes must come from an extension popup or options page");
      if (message.type === "STATE") {
        const data = await read(), access = await permitted();
        const tab = Number.isInteger(message.tabId) ? await api.tabs.get(message.tabId) : null;
        let hidden = 0, statsWarning = null;
        if (tab && access && /^https?:/.test(tab.url || "")) {
          try { const frames = await snapshot(tab.id); data.reports[tab.id] = frames; hidden = Object.values(frames).reduce((sum, value) => sum + value.hidden, 0); }
          catch (error) { hidden = null; statsWarning = "Current hidden count could not be confirmed: " + String(error.message || error); }
        } else if (tab && Object.values(data.reports[tab.id] || {}).some((report) => report.hidden > 0)) {
          hidden = null; statsWarning = "Page access is unavailable; previous DOM effects cannot be confirmed. Reload this page.";
        }
        return { ...data, hasAccess:access, mode:tab && access ? policy.pageMode(data.settings, data.pages, tab) : "off", hidden, statsWarning };
      }
      if (message.type === "ENABLE") {
        if (!["conservative", "balanced"].includes(message.mode)) throw new Error("Invalid mode");
        const tab = await api.tabs.get(message.tabId);
        const host = policy.hostname(tab.url);
        return change((next) => {
          next.settings.preferredMode = message.mode;
          next.settings.allowSites = next.settings.allowSites.filter((site) => site !== host);
          if (message.scope === "all") { next.settings.mode = message.mode; next.pages = {}; }
          else if (message.scope === "page") { next.settings.mode = "off"; next.pages = { [tab.id]:{ host, mode:message.mode } }; }
          else throw new Error("Invalid scope");
        });
      }
      if (message.type === "STOP") return change((next) => { next.settings.mode = "off"; next.pages = {}; });
      if (message.type === "ALLOW_SITE") {
        const tab = await api.tabs.get(message.tabId), host = policy.hostname(tab.url);
        return change((next) => {
          if (message.allowed && !next.settings.allowSites.includes(host) && next.settings.allowSites.length >= 200) throw new Error("Site allow list is full (200 sites)");
          next.settings.allowSites = message.allowed ? [...new Set([...next.settings.allowSites, host])].slice(0, 200) : next.settings.allowSites.filter((site) => site !== host);
          for (const [id, entry] of Object.entries(next.pages)) if (entry.host === host) delete next.pages[id];
        });
      }
      if (message.type === "REMOVE_SITE") return change((next) => { next.settings.allowSites = next.settings.allowSites.filter((site) => site !== message.host); });
      if (message.type === "RESTORE") {
        if (!await permitted()) throw new Error("Page access is required to confirm restoration; reload this page if access was revoked");
        const frames = await snapshot(message.tabId, true);
        const hidden = Object.values(frames).reduce((sum, value) => sum + value.hidden, 0);
        if (hidden !== 0) throw new Error("Some page frames could not restore their hidden elements");
        return { hidden, frames };
      }
      if (message.type === "LANGUAGE") {
        if (!["zh-CN", "en"].includes(message.language)) throw new Error("Invalid language");
        return change((next) => { next.settings.language = message.language; });
      }
      throw new Error("Unknown command");
    }
    function reconcile() { return lock(async () => { required(); const data = await read(); const result = await apply(data, await permitted()); await api.storage.session.set({ lastError:null }); return result; }); }
    function removePage(tabId) { return change((next) => { delete next.pages[tabId]; delete next.reports[tabId]; }); }
    function navigated(tabId, url) {
      return change((next) => {
        let host; try { host = policy.hostname(url); } catch (_) {}
        if (next.pages[tabId] && next.pages[tabId].host !== host) delete next.pages[tabId];
        delete next.reports[tabId];
      });
    }
    return { handle, reconcile, removePage, navigated };
  }
  if (typeof module !== "undefined" && module.exports) { module.exports = { createService }; return; }
  const service = createService(chrome);
  chrome.runtime.onMessage.addListener((message, sender, reply) => {
    if (sender.id !== chrome.runtime.id) return;
    service.handle(message, sender).then((result) => reply({ ok:true, ...result }), (error) => reply({ ok:false, error:String(error.message || error) }));
    return true;
  });
  const reconcile = () => service.reconcile().catch((error) => chrome.storage.session.set({ lastError:String(error.message || error) }));
  chrome.runtime.onInstalled.addListener(reconcile);
  chrome.runtime.onStartup.addListener(reconcile);
  chrome.permissions.onRemoved.addListener(reconcile);
  chrome.tabs.onRemoved.addListener((tabId) => service.removePage(tabId).catch(() => {}));
  chrome.tabs.onUpdated.addListener((tabId, change) => { if (change.url) service.navigated(tabId, change.url).catch(() => {}); });
})(globalThis);
