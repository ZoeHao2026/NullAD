/* Deterministic local scores. A score is not a probability or claimed accuracy. */
(function (root) {
  "use strict";
  const label = /^(?:广告|廣告|赞助(?:内容)?|贊助(?:內容)?|advertisement|advertisements|advertising|ads?|sponsored(?: content)?|promoted)$/i;
  const token = /(?:^|[-_\s])(?:ads?|advert(?:isement|ising)?|adslot|adunit|adserver|adbox|adsbox|textads|banner[-_]ads|sponsored)(?:$|[-_\s\d])/i;
  const hardExcluded = new Set(["HTML", "BODY", "MAIN", "NAV", "HEADER", "FOOTER", "FORM", "INPUT", "BUTTON", "TEXTAREA", "SELECT", "VIDEO", "AUDIO"]);
  function leafLabel(element) {
    if (element.childElementCount !== 0 || element.childNodes.length > 3) return false;
    let value = "";
    for (const node of element.childNodes) if (node.nodeType === 3) value += (node.nodeValue || "").slice(0, 41 - value.length);
    return label.test(value.trim());
  }
  function evaluate(features, mode = "conservative") {
    if (mode === "off" || features.protected || !features.visible) return { hide:false, score:0, reasons:[] };
    const reasons = [], groups = new Set();
    let score = 0;
    if (features.label) { score += 4; groups.add("semantics"); reasons.push("advertising-label"); }
    if (features.emptyMarkerCombination) { score += 4; groups.add("semantics"); reasons.push("multiple-explicit-empty-ad-markers"); }
    if (features.marker) { score += 3; groups.add("marker"); reasons.push("advertising-attribute"); }
    if (features.structure) { score += 2; groups.add("structure"); reasons.push("bounded-ad-container"); }
    if (features.geometry) { score += 1; groups.add("geometry"); reasons.push("banner-shape"); }
    const threshold = mode === "balanced" ? 6 : 8;
    return { hide:score >= threshold && groups.size >= 2 && (features.label || features.strongMarker || features.emptyMarkerCombination), score, reasons };
  }
  function features(element) {
    const tag = element.tagName;
    const box = element.getBoundingClientRect();
    if (hardExcluded.has(tag) || box.height > 750 || (box.width > 1100 && box.height > 450)) return { protected:true, visible:box.width > 0 && box.height > 0 };
    const aria = ["aria-label", "title"].some((name) => label.test((element.getAttribute(name) || "").trim()));
    let text = "", shortLabel = false, structure = tag === "IFRAME", interactive = false;
    const isInteractive = (node) => ["INPUT", "TEXTAREA", "SELECT", "FORM", "VIDEO", "AUDIO"].includes(node.tagName) || (node.hasAttribute("contenteditable") && node.getAttribute("contenteditable") !== "false") || ["main", "navigation"].includes(node.getAttribute("role"));
    interactive = isInteractive(element);
    // Bound the traversal before inspecting labels or structure in a large tree.
    const walker = element.ownerDocument.createTreeWalker(element, 5);
    let child = walker.nextNode(), count = 0, visited = 0;
    while (child && visited++ < 101) {
      if (child.nodeType === 3) {
        text += (child.nodeValue || "").slice(0, 401 - text.length);
        if (text.length > 400) break;
      } else {
        count++;
        if (isInteractive(child)) { interactive = true; break; }
        if (["IFRAME", "IMG", "INS", "OBJECT"].includes(child.tagName) || (child.tagName === "A" && child.hasAttribute("href"))) structure = true;
        if (["SPAN", "SMALL", "LABEL", "FIGCAPTION"].includes(child.tagName) && leafLabel(child)) shortLabel = true;
      }
      child = walker.nextNode();
    }
    text = text.replace(/\s+/g, " ").trim();
    shortLabel = shortLabel || label.test(text);
    const strongMarker = ["data-ad-slot", "data-ad-unit", "data-ad-client", "data-ad"] .some((name) => element.hasAttribute(name));
    const advertisingMarkers = new Set();
    for (const value of (element.getAttribute("class") || "").toLowerCase().split(/\s+/)) {
      const matched = value.match(/(?:^|[-_])(adbox|adsbox|textads|banner[-_]ads)(?:$|[-_])/);
      if (matched) advertisingMarkers.add(matched[1].replace(/-/g, "_"));
    }
    const emptyMarkerCombination = !text && element.childElementCount === 0 && advertisingMarkers.size >= 2;
    const marker = strongMarker || token.test(element.id || "") || token.test(element.getAttribute("class") || "");
    const geometry = (box.width >= 250 && box.width <= 1000 && box.height >= 40 && box.height <= 350 && box.width / box.height >= 2) || (box.width >= 100 && box.width <= 400 && box.height >= 200 && box.height <= 650);
    return { label:aria || shortLabel, marker, strongMarker, emptyMarkerCombination, structure:emptyMarkerCombination || structure, geometry, visible:box.width > 0 && box.height > 0, protected:interactive || text.length > 400 || count > 100 || visited > 101 };
  }
  function inspect(element, mode) { return evaluate(features(element), mode); }
  function createScan(scope, onNode = () => {}, include = () => false) {
    const seen = new WeakSet();
    const walker = (scope.ownerDocument || scope).createTreeWalker(scope, 1);
    let first = scope.nodeType === 1 ? scope : null, done = false;
    const add = (element) => {
      const result = [];
      for (let depth = 0; element && depth < 3; depth++, element = element.parentElement) {
        if (hardExcluded.has(element.tagName)) break;
        if (!seen.has(element)) { seen.add(element); result.push(element); }
      }
      return result;
    };
    return { next() {
      if (done) return { done:true, candidates:[] };
      const element = first || walker.nextNode(); first = null;
      if (!element) { done = true; return { done:true, candidates:[] }; }
      onNode(element);
      const likely = include(element) || element.tagName === "IFRAME" || element.tagName === "INS" || token.test(element.id || "") || token.test(element.getAttribute("class") || "") || ["data-ad-slot", "data-ad-unit", "data-ad-client", "data-ad"].some((name) => element.hasAttribute(name)) || label.test((element.getAttribute("aria-label") || "").trim()) || label.test((element.getAttribute("title") || "").trim()) || leafLabel(element);
      return { done:false, candidates:likely ? add(element) : [] };
    } };
  }
  function candidates(scope, limit = 1500, onNode = () => {}) {
    const scan = createScan(scope, onNode), result = [];
    for (let visited = 0; visited < limit; visited++) {
      const part = scan.next(); if (part.done) break;
      result.push(...part.candidates);
    }
    return result;
  }
  const api = { evaluate, features, inspect, candidates, createScan, label, token };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.NullADDetector = api;
})(globalThis);
