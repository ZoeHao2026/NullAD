/* Pure state and input helpers; shared by production UI and node --test. */
(function (root) {
  "use strict";
  const fields = ["proxy_enabled", "proxy_port", "dns_enabled", "dns_port", "dns_upstream", "dns_nxdomain", "intercept_system_proxy", "heuristic_mode", "allowed_hosts", "upstream_proxy"];
  function isActive(status) { return !!status && ["running", "degraded"].includes(status.protection); }
  function isBusy(status) { return !!status && ["starting", "stopping"].includes(status.protection); }
  function hostValues(values) {
    const entries = Array.isArray(values) ? values : String(values || "").split(/[\n,;]/);
    return [...new Set(entries.map((value) => {
      const host = String(value).trim().toLowerCase().replace(/\.$/, "");
      if (!host || /[/?#@*\s]/.test(host)) return host;
      try {
        const authority = host.includes(":") && !host.startsWith("[") ? "[" + host + "]" : host;
        const parsed = new URL("http://" + authority + "/");
        return parsed.port ? host : parsed.hostname;
      } catch (_) { return host; }
    }).filter(Boolean))];
  }
  function listenerPatch(values) {
    return Object.fromEntries(fields.map((field) => [field,
      field.endsWith("_port") ? Number(values[field]) :
      field === "allowed_hosts" ? hostValues(values[field]) :
      field === "heuristic_mode" ? String(values[field] || "balanced") :
      ["dns_upstream", "upstream_proxy"].includes(field) ? String(values[field] || "").trim() : !!values[field]]));
  }
  function validHost(host) {
    if (/^\[[0-9a-f:]+\]$/i.test(host)) {
      try { return new URL("http://" + host).hostname === host; } catch (_) { return false; }
    }
    return host.length <= 253 && host.split(".").every((label) => label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label));
  }
  function validate(patch) {
    for (const field of ["proxy_port", "dns_port"]) {
      if (!Number.isInteger(patch[field]) || patch[field] < 1 || patch[field] > 65535) return "invalidPort";
    }
    if (!patch.dns_upstream) return "invalidUpstream";
    if (patch.intercept_system_proxy && !patch.proxy_enabled) return "proxyRequired";
    if (patch.proxy_enabled && patch.dns_enabled && patch.proxy_port === patch.dns_port) return "samePorts";
    if (!["off", "conservative", "balanced"].includes(patch.heuristic_mode || "balanced")) return "invalidHeuristic";
    if (hostValues(patch.allowed_hosts).some((host) => !validHost(host))) return "invalidAllowedHosts";
    if (patch.upstream_proxy) {
      try {
        const endpoint = new URL(patch.upstream_proxy);
        const port = patch.upstream_proxy.match(/:(\d+)\/?$/);
        if (!["http:", "socks5:"].includes(endpoint.protocol) || !port || Number(port[1]) < 1 || Number(port[1]) > 65535 || endpoint.username || endpoint.password || endpoint.search || endpoint.hash || (endpoint.pathname && endpoint.pathname !== "/") || !validHost(endpoint.hostname)) return "invalidProxyUpstream";
      } catch (_) { return "invalidProxyUpstream"; }
    }
    return null;
  }
  function equalField(field, a, b) {
    if (field === "allowed_hosts") return JSON.stringify(hostValues(a).sort()) === JSON.stringify(hostValues(b).sort());
    if (field === "upstream_proxy") return String(a || "").trim() === String(b || "").trim();
    if (field === "heuristic_mode") return (a || "balanced") === (b || "balanced");
    return a === b;
  }
  function changed(saved, patch) { return !!saved && fields.some((field) => !equalField(field, saved[field], patch[field])); }
  function settingsDelta(saved, patch) { return Object.fromEntries(fields.filter((field) => !saved || !equalField(field, saved[field], patch[field])).map((field) => [field, patch[field]])); }
  function filterDecisions(entries, filter) { return entries.filter((entry) => filter === "blocked" ? entry.blocked : filter === "allowed" ? !entry.blocked : true); }
  function pendingCount(value) { return Array.isArray(value) ? value.length : Number(value) || 0; }
  function escapeHtml(value) { return String(value == null ? "" : value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char])); }
  const api = { fields, hostValues, isActive, isBusy, listenerPatch, validate, changed, settingsDelta, filterDecisions, pendingCount, escapeHtml };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else { root.NullAD = root.NullAD || {}; root.NullAD.state = api; }
})(typeof window === "undefined" ? globalThis : window);
