/* Small bundled semantic conditions, not a fetched domain/subscription list. */
(function (root) {
  "use strict";
  const modes = ["off", "conservative", "balanced"];
  const origins = ["http://*/*", "https://*/*"];
  const resources = ["script", "image", "sub_frame", "xmlhttprequest", "media", "ping", "other"];
  const definitions = [
    { id:1, reason:"Dedicated ad-serving hostname label and third-party resource", regex:"^https?://([a-z0-9-]+\\.)*(ads|adserver|adservice|adservices|adserving|ad-delivery|adtracking)\\.[^/:?#]+(:[0-9]+)?/", types:["script", "image", "sub_frame", "xmlhttprequest", "ping"], thirdParty:true },
    { id:2, reason:"Exact advertising script filename", regex:"^https?://[^/?#]+/([^?#]*/)?(ads|pagead|adsbygoogle|adserver)(\\.min)?\\.js([?#]|$)", types:["script"] },
    { id:3, reason:"Ad-serving path and script filename together", regex:"^https?://[^/?#]+/([^?#]*/)?(ads|pagead|adserver)/(js/)?(ads|pagead|adsbygoogle|adserver|show_ads|adserve|adview)(\\.min)?\\.js([?#]|$)", types:["script"] },
    { id:4, reason:"Advertising endpoint path plus delivery action", regex:"^https?://[^/?#]+/([^?#]*/)?(ads|pagead|adserver|adserving)/(serve|show|render|impression|click|delivery)([/?#.]|$)", types:["script", "image", "sub_frame", "xmlhttprequest", "ping"], balanced:true },
    { id:5, reason:"Ad-labelled third-party hostname and advertising resource path", regex:"^https?://(ad|advert|advertisement|advertisements)\\.[^/:?#]+(:[0-9]+)?/([^?#]*/)?(ads|pagead|adserver|adserve|banner)([/?#.]|$)", types:["script", "image", "sub_frame", "xmlhttprequest"], thirdParty:true, balanced:true }
  ];
  const escapeRegex = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  function hostname(value) {
    const parsed = new URL(value);
    if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("HTTP(S) pages only");
    return parsed.hostname.toLowerCase();
  }
  function normalizeSettings(value = {}) {
    const sites = [...new Set((Array.isArray(value.allowSites) ? value.allowSites : []).filter((site) => {
      if (typeof site !== "string" || !site || /[\s/*]/.test(site)) return false;
      try { return new URL("http://" + site + "/").hostname === site.toLowerCase(); } catch (_) { return false; }
    }).map((site) => site.toLowerCase()))].slice(0, 200);
    return { mode:modes.includes(value.mode) ? value.mode : "off", preferredMode:["conservative", "balanced"].includes(value.preferredMode) ? value.preferredMode : "conservative", allowSites:sites, language:value.language === "en" ? "en" : "zh-CN" };
  }
  function blockRules(mode, tabId) {
    if (mode === "off") return [];
    return definitions.filter((item) => mode === "balanced" || !item.balanced).map((item) => ({
      id:tabId == null ? item.id : 100 + item.id,
      priority:10,
      action:{ type:"block" },
      condition:{ regexFilter:item.regex, isUrlFilterCaseSensitive:false, resourceTypes:item.types, ...(item.thirdParty ? { domainType:"thirdParty" } : {}), ...(tabId == null ? {} : { tabIds:[tabId] }) }
    }));
  }
  function allowRules(sites) {
    return sites.map((site, index) => ({ id:1000 + index, priority:1000, action:{ type:"allowAllRequests" }, condition:{ regexFilter:"^https?://" + escapeRegex(site) + "(:[0-9]+)?/", isUrlFilterCaseSensitive:false, resourceTypes:["main_frame"] } }));
  }
  function sessionRules(settings, pageModes, tabs) {
    if (settings.mode === "off" && !Object.keys(pageModes).length) return { rules:[], activeTabs:[] };
    const rules = [], activeTabs = [];
    let id = 10000;
    for (const tab of tabs) {
      if (!Number.isInteger(tab.id) || !tab.url) continue;
      let host;
      try { host = hostname(tab.url); } catch (_) { continue; }
      if (settings.allowSites.includes(host)) {
        // Applies immediately on an already loaded tab; the dynamic main-frame
        // allow above also covers future navigations and all descendant frames.
        rules.push({ id:id++, priority:1000, action:{ type:"allow" }, condition:{ tabIds:[tab.id], resourceTypes:resources } });
        continue;
      }
      const page = pageModes[tab.id];
      if (page && page.host === host && settings.mode === "off") {
        for (const rule of blockRules(page.mode, tab.id)) { rule.id = id++; rules.push(rule); }
        activeTabs.push(tab.id);
      }
    }
    return { rules, activeTabs };
  }
  function pageMode(settings, pages, tab) {
    let host;
    try { host = hostname(tab.url); } catch (_) { return "off"; }
    if (settings.allowSites.includes(host)) return "off";
    return settings.mode !== "off" ? settings.mode : pages[tab.id] && pages[tab.id].host === host ? pages[tab.id].mode : "off";
  }
  const api = { modes, origins, resources, definitions, escapeRegex, hostname, normalizeSettings, blockRules, allowRules, sessionRules, pageMode };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.NullADPolicy = api;
})(globalThis);
