/* Pure state and input helpers; shared by production UI and node --test. */
(function (root) {
  "use strict";
  const fields = ["proxy_enabled", "proxy_port", "dns_enabled", "dns_port", "dns_upstream", "dns_nxdomain", "intercept_system_proxy"];
  function isActive(status) { return !!status && ["running", "degraded"].includes(status.protection); }
  function isBusy(status) { return !!status && ["starting", "stopping"].includes(status.protection); }
  function listenerPatch(values) {
    return Object.fromEntries(fields.map((field) => [field, field.endsWith("_port") ? Number(values[field]) : field === "dns_upstream" ? String(values[field]).trim() : !!values[field]]));
  }
  function validate(patch) {
    for (const field of ["proxy_port", "dns_port"]) {
      if (!Number.isInteger(patch[field]) || patch[field] < 1 || patch[field] > 65535) return "invalidPort";
    }
    if (!patch.dns_upstream) return "invalidUpstream";
    if (patch.intercept_system_proxy && !patch.proxy_enabled) return "proxyRequired";
    if (patch.proxy_enabled && patch.dns_enabled && patch.proxy_port === patch.dns_port) return "samePorts";
    return null;
  }
  function changed(saved, patch) { return !!saved && fields.some((field) => saved[field] !== patch[field]); }
  function settingsDelta(saved, patch) { return Object.fromEntries(fields.filter((field) => !saved || saved[field] !== patch[field]).map((field) => [field, patch[field]])); }
  function filterDecisions(entries, filter) { return entries.filter((entry) => filter === "blocked" ? entry.blocked : filter === "allowed" ? !entry.blocked : true); }
  function pendingCount(value) { return Array.isArray(value) ? value.length : Number(value) || 0; }
  function escapeHtml(value) { return String(value == null ? "" : value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char])); }
  const api = { fields, isActive, isBusy, listenerPatch, validate, changed, settingsDelta, filterDecisions, pendingCount, escapeHtml };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else { root.NullAD = root.NullAD || {}; root.NullAD.state = api; }
})(typeof window === "undefined" ? globalThis : window);
