/* Runs only after user-granted access. It does not fetch, modify requests or proxy settings. */
(function (root) {
  "use strict";
  if (root.__nulladLocalController) return;
  const detector = typeof module !== "undefined" && module.exports ? require("./detector.js") : root.NullADDetector;
  function createController(document, environment = {}) {
    const hidden = new Map(), exempt = new WeakSet(), observers = new Map(), shadowStyles = new Set();
    const dirty = new Set(), work = [], scans = [];
    let mode = "off", scheduled = false, timer = null, scanCount = 0;
    const marker = "data-nullad-local-hidden";
    const raf = environment.raf || root.requestAnimationFrame.bind(root);
    const later = environment.later || root.setTimeout.bind(root);
    const cancel = environment.cancel || root.clearTimeout.bind(root);
    const now = environment.now || (() => root.performance.now());
    const notify = environment.notify || (() => {});
    const Observer = environment.Observer || root.MutationObserver;
    const style = document.createElement("style");
    style.textContent = '[data-nullad-local-hidden="nullad"]{display:none!important}';
    function restore(element, allowAgain = false) {
      const record = hidden.get(element);
      if (!record) return;
      if (element.getAttribute(marker) === "nullad") {
        if (record.previous == null) element.removeAttribute(marker); else element.setAttribute(marker, record.previous);
      }
      hidden.delete(element);
      if (!allowAgain) exempt.add(element);
    }
    function restoreAll(allowAgain = false) {
      for (const element of [...hidden.keys()]) restore(element, allowAgain);
      notify(stats());
    }
    function stats() { return { hidden:hidden.size, scanned:scanCount, mode, reasons:[...hidden.values()].slice(0, 20).map((value) => ({ score:value.score, reasons:value.reasons })) }; }
    function visit(element) {
      if (!element.isConnected || exempt.has(element)) return;
      const previous = hidden.get(element);
      // A hidden recycled SPA node must be measured in its original visibility.
      if (previous) element.removeAttribute(marker);
      const result = detector.inspect(element, mode);
      if (previous) element.setAttribute(marker, "nullad");
      scanCount++;
      if (result.hide) {
        if (!previous) hidden.set(element, { previous:element.getAttribute(marker), score:result.score, reasons:result.reasons });
        element.setAttribute(marker, "nullad");
      } else if (previous) restore(element, true);
    }
    function observe(scope) {
      if (observers.has(scope)) return true;
      if (observers.size >= 32 || mode === "off") return false;
      let sheet = null;
      if (scope.nodeType === 11) {
        sheet = document.createElement("style"); sheet.textContent = style.textContent;
        scope.appendChild(sheet); shadowStyles.add(sheet);
      }
      const observer = new Observer((records) => {
        if (mode === "off") return;
        for (const record of records.slice(0, 300)) {
          if (record.type === "childList") {
            for (const node of [...record.addedNodes].slice(0, 100)) if (node.nodeType === 1) enqueue(node);
            if (record.target.nodeType === 1) enqueue(record.target);
          } else enqueue(record.target.nodeType === 1 ? record.target : record.target.parentElement);
        }
      });
      observer.observe(scope, { childList:true, subtree:true, attributes:true, attributeFilter:["id", "class", "title", "aria-label", "aria-description", "aria-labelledby", "role", "contenteditable", "style", "hidden", "href", "src", "data-ad", "data-ad-slot", "data-ad-unit", "data-ad-client", "data-ad-placement", "data-advertisement", "data-sponsored"], characterData:true });
      observers.set(scope, { observer, sheet });
      return true;
    }
    function flush() {
      scheduled = false;
      if (mode === "off") { dirty.clear(); return; }
      for (const [scope, value] of observers) if (!scope.isConnected) {
        value.observer.disconnect(); observers.delete(scope);
        if (value.sheet) { value.sheet.remove(); shadowStyles.delete(value.sheet); }
      }
      const start = now(); let steps = 0;
      while ((dirty.size || work.length || scans.length) && steps++ < 250 && now() - start < 4) {
        if (work.length) { visit(work.shift()); continue; }
        if (scans.length) {
          const part = scans[0].next();
          if (part.done) scans.shift(); else work.push(...part.candidates);
          continue;
        }
        const scope = dirty.values().next().value;
        dirty.delete(scope);
        if (!scope || !scope.isConnected) continue;
        scans.push(detector.createScan(scope, (node) => {
          if (node.shadowRoot && observe(node.shadowRoot)) enqueue(node.shadowRoot);
        }, (node) => hidden.has(node)));
      }
      for (const element of [...hidden.keys()]) if (!element.isConnected) restore(element, true);
      notify(stats());
      if (dirty.size || work.length || scans.length) schedule();
    }
    function schedule() { if (!scheduled) { scheduled = true; raf(flush); } }
    function enqueue(scope) {
      if (!scope || mode === "off" || scope === style || shadowStyles.has(scope) || dirty.size >= 200) return;
      dirty.add(scope);
      // Recycled labels can stop looking like candidates. Their hidden parent
      // still needs a fresh decision when the child's label/role/text changes.
      for (let depth = 0, parent = scope.parentElement; parent && depth < 4; depth++, parent = parent.parentElement) {
        if (hidden.has(parent) && dirty.size < 200) dirty.add(parent);
      }
      if (timer == null) timer = later(() => { timer = null; schedule(); }, 150);
    }
    function configure(next) {
      const nextMode = ["conservative", "balanced"].includes(next) ? next : "off";
      if (mode !== nextMode) {
        for (const value of observers.values()) value.observer.disconnect();
        observers.clear(); dirty.clear(); work.length = 0; scans.length = 0;
        for (const sheet of shadowStyles) sheet.remove(); shadowStyles.clear();
        if (timer != null) { cancel(timer); timer = null; }
        restoreAll(true);
      }
      mode = nextMode;
      if (mode === "off") { style.remove(); notify(stats()); return; }
      if (!style.isConnected) (document.head || document.documentElement).appendChild(style);
      observe(document.documentElement); enqueue(document.documentElement);
    }
    return { configure, restoreAll, stats, enqueue, visit, restore };
  }
  if (typeof module !== "undefined" && module.exports) { module.exports = { createController }; return; }
  const controller = createController(root.document, { notify:(stats) => chrome.runtime.sendMessage({ type:"REPORT", stats }).catch(() => {}) });
  root.__nulladLocalController = controller;
  let configured = false;
  chrome.runtime.onMessage.addListener((message, sender, reply) => {
    if (sender.id !== chrome.runtime.id) return;
    if (message.type === "CONFIGURE") { configured = true; controller.configure(message.mode); reply(controller.stats()); }
    if (message.type === "RESTORE") { controller.restoreAll(); reply(controller.stats()); }
    if (message.type === "STATS") reply(controller.stats());
  });
  chrome.runtime.sendMessage({ type:"GET_CONFIG" }).then((result) => {
    if (!result || !result.ok) throw new Error(result && result.error || "Cannot load extension settings");
    if (!configured) controller.configure(result.mode);
  }).catch(() => { if (!configured) controller.configure("off"); });
})(globalThis);
