/* The only access to Tauri IPC. A rejected command stays a rejection. */
(function (root) {
  "use strict";
  function message(error) {
    if (error && typeof error.message === "string") return error.message;
    if (typeof error === "string") return error;
    try { return JSON.stringify(error) || "Unknown backend error"; } catch (_) { return String(error); }
  }
  function createClient(bridge) {
    return {
      available: !!(bridge && bridge.core && typeof bridge.core.invoke === "function"),
      async call(command, args) {
        if (!this.available) throw new Error("NULLAD_BACKEND_UNAVAILABLE");
        try { return await bridge.core.invoke(command, args || {}); }
        catch (error) { throw new Error(message(error)); }
      },
      async listen(event, handler) {
        if (!bridge || !bridge.event || typeof bridge.event.listen !== "function") throw new Error("NULLAD_EVENTS_UNAVAILABLE");
        return bridge.event.listen(event, handler);
      }
    };
  }
  if (typeof module !== "undefined" && module.exports) module.exports = { createClient, message };
  else { root.NullAD = root.NullAD || {}; root.NullAD.ipc = createClient(root.__TAURI__); }
})(typeof window === "undefined" ? globalThis : window);
