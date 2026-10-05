/* Deterministic local scores. A score is not a probability or claimed accuracy. */
(function (root) {
  "use strict";
  const label = /^(?:广告|廣告|赞助(?:内容)?|贊助(?:內容)?|付费(?:广告|推广)|付費(?:廣告|推廣)|advertisement(?:s)?|advertising|ads?|sponsored(?: content)?|promoted(?: content)?|paid (?:advertisement|partnership)|広告(?:コンテンツ)?|スポンサー(?:コンテンツ)?|スポンサード|広告掲載|광고|유료 광고|스폰서 콘텐츠|publicité|contenu sponsorisé|sponsorisé|anzeige|werbung|gesponsert|publicidad|anuncio|contenido patrocinado|patrocinado|publicidade|anúncio|conteúdo patrocinado|pubblicità|annuncio|contenuto sponsorizzato|advertentie|gesponsord|reklama|treść sponsorowana|реклама|спонсорский контент|إعلان(?: ممول)?|محتوى برعاية|פרסומת|תוכן ממומן)$/iu;
  const token = /(?:^|[-_\s])(?:ads?|advert(?:isement(?:s)?|ising|orial)?|adslot|adunit|adserver|adbox|adsbox|textads|adplacement|banner[-_]ads|sponsored)(?:$|[-_\s\d])/i;
  const hardExcluded = new Set(["HTML", "BODY", "MAIN", "NAV", "HEADER", "FOOTER", "ARTICLE", "P", "H1", "H2", "H3", "H4", "H5", "H6", "PRE", "CODE", "FORM", "INPUT", "BUTTON", "TEXTAREA", "SELECT", "VIDEO", "AUDIO"]);
  const markerAttributes = ["data-ad-slot", "data-ad-unit", "data-ad-client", "data-ad-placement", "data-ad", "data-advertisement", "data-sponsored"];
  const protectedRoles = new Set(["main", "navigation", "article", "form", "search", "dialog", "alertdialog", "menu", "menubar", "toolbar"]);
  function matchesLabel(value) {
    if (typeof value !== "string" || value.length > 80) return false;
    const clean = value.normalize("NFKC").replace(/\s+/g, " ").trim().replace(/^[\[({【「『]\s*/u, "").replace(/\s*[\])}】」』]$/u, "").replace(/[：:·•]+$/u, "").trim();
    return label.test(clean);
  }
  function leafText(element) {
    if (element.childElementCount !== 0 || element.childNodes.length > 3) return null;
    let value = "";
    for (const node of element.childNodes) if (node.nodeType === 3) value += (node.nodeValue || "").slice(0, 81 - value.length);
    return value.length <= 80 ? value : null;
  }
  function leafLabel(element) {
    return matchesLabel(leafText(element));
  }
  function referenceLabel(element) {
    if (["aria-label", "title", "aria-description"].some((name) => matchesLabel(element.getAttribute(name) || ""))) return true;
    const ids = element.getAttribute("aria-labelledby") || "";
    if (!ids || ids.length > 120) return false;
    const scope = element.getRootNode ? element.getRootNode() : element.ownerDocument;
    const lookup = scope && typeof scope.getElementById === "function" ? scope : element.ownerDocument;
    if (!lookup || typeof lookup.getElementById !== "function") return false;
    const names = ids.trim().split(/\s+/);
    if (names.length > 3) return false;
    const values = names.map((id) => {
      const reference = lookup.getElementById(id);
      return reference ? leafText(reference) : null;
    });
    return values.every((value) => value !== null) && matchesLabel(values.join(" "));
  }
  function strongMarker(element) {
    return markerAttributes.some((name) => {
      if (!element.hasAttribute(name)) return false;
      return !/^(?:false|off|disabled|none|0)$/i.test((element.getAttribute(name) || "").trim());
    });
  }
  function interactive(element) {
    return ["INPUT", "TEXTAREA", "SELECT", "FORM", "BUTTON", "VIDEO", "AUDIO", "PRE", "CODE", "MAIN", "NAV", "ARTICLE", "HEADER", "FOOTER"].includes(element.tagName) || (element.hasAttribute("contenteditable") && element.getAttribute("contenteditable") !== "false") || protectedRoles.has((element.getAttribute("role") || "").trim().toLowerCase());
  }
  function protectedContext(element) {
    for (let depth = 0, current = element; current && depth < 8; depth++) {
      if (["NAV", "FORM", "VIDEO", "AUDIO", "PRE", "CODE"].includes(current.tagName) || (current.hasAttribute("contenteditable") && current.getAttribute("contenteditable") !== "false") || ["navigation", "form", "search", "dialog", "alertdialog", "menu", "menubar", "toolbar"].includes((current.getAttribute("role") || "").trim().toLowerCase())) return true;
      const scope = current.getRootNode && current.getRootNode();
      current = current.parentElement || (scope && scope.host);
    }
    return false;
  }
  function evaluate(features, mode = "conservative") {
    if (mode === "off" || features.protected || !features.visible) return { hide:false, score:0, reasons:[] };
    const reasons = [], groups = new Set();
    let score = 0;
    if (features.label) { score += 4; groups.add("semantics"); reasons.push("advertising-label"); }
    if (features.emptyMarkerCombination) { score += 4; groups.add("semantics"); reasons.push("multiple-explicit-empty-ad-markers"); }
    if (features.marker) { score += 3; groups.add("marker"); reasons.push(features.descendantMarker ? "contained-advertising-attribute" : "advertising-attribute"); }
    if (features.structure) { score += 2; groups.add("structure"); reasons.push("bounded-ad-container"); }
    if (features.geometry) { score += 1; groups.add("geometry"); reasons.push("banner-shape"); }
    const threshold = mode === "balanced" ? 6 : 8;
    return { hide:score >= threshold && groups.size >= 2 && (features.label || features.strongMarker || features.emptyMarkerCombination), score, reasons };
  }
  function features(element) {
    const tag = element.tagName;
    const box = element.getBoundingClientRect();
    if (hardExcluded.has(tag) || box.height > 750 || (box.width > 1100 && box.height > 450)) return { protected:true, visible:box.width > 0 && box.height > 0 };
    const aria = referenceLabel(element), ownStrongMarker = strongMarker(element);
    const ownMarker = ownStrongMarker || token.test(element.id || "") || token.test(element.getAttribute("class") || "");
    let text = "", shortLabel = false, structure = tag === "IFRAME", creative = structure, controls = interactive(element);
    let childMarker = false;
    const labelBranches = new Set(), markerBranches = new Set(), mediaBranches = new Set(), textSegments = [];
    const branch = (node) => {
      let current = node;
      for (let depth = 0; current && depth < 101; depth++) {
        if (current.parentNode === element) return current;
        current = current.parentNode;
      }
      return null;
    };
    // Bound the traversal before inspecting labels or structure in a large tree.
    const walker = element.ownerDocument.createTreeWalker(element, 5);
    let child = walker.nextNode(), count = 0, visited = 0;
    while (child && visited++ < 101) {
      if (child.nodeType === 3) {
        const value = (child.nodeValue || "").slice(0, 401 - text.length);
        text += value; textSegments.push({ value, branch:branch(child) });
        if (text.length > 400) break;
      } else {
        count++;
        if (interactive(child)) { controls = true; break; }
        const containerBranch = branch(child);
        if (["IFRAME", "IMG", "INS", "OBJECT"].includes(child.tagName)) { structure = true; creative = true; mediaBranches.add(containerBranch); }
        if (child.tagName === "A" && child.hasAttribute("href")) structure = true;
        if (referenceLabel(child) || leafLabel(child)) { shortLabel = true; labelBranches.add(containerBranch); }
        if (strongMarker(child)) { childMarker = true; markerBranches.add(containerBranch); }
      }
      child = walker.nextNode();
    }
    text = text.replace(/\s+/g, " ").trim();
    const ownLabel = aria || matchesLabel(text);
    const evidenceBranches = new Set([...labelBranches, ...markerBranches]);
    // A badge inside an ad must not conceal unrelated siblings or an entire feed.
    const foreignCopy = textSegments.some((segment) => segment.value.trim() && !matchesLabel(segment.value.trim()) && !evidenceBranches.has(segment.branch) && !mediaBranches.has(segment.branch));
    const mixedContainer = !ownLabel && !ownStrongMarker && (foreignCopy || mediaBranches.size > 1 || element.childElementCount > 6);
    const descendantMarker = childMarker && !mixedContainer;
    const advertisingMarkers = new Set();
    for (const value of (element.getAttribute("class") || "").toLowerCase().split(/\s+/)) {
      const matched = value.match(/(?:^|[-_])(adbox|adsbox|textads|banner[-_]ads)(?:$|[-_])/);
      if (matched) advertisingMarkers.add(matched[1].replace(/-/g, "_"));
    }
    const emptyMarkerCombination = !text && element.childElementCount === 0 && advertisingMarkers.size >= 2;
    const marker = ownMarker || descendantMarker;
    const geometry = (box.width >= 250 && box.width <= 1000 && box.height >= 40 && box.height <= 350 && box.width / box.height >= 2) || (box.width >= 100 && box.width <= 400 && box.height >= 200 && box.height <= 650);
    return { label:ownLabel || (shortLabel && (creative || ownMarker || childMarker)), marker, descendantMarker, strongMarker:ownStrongMarker || descendantMarker, emptyMarkerCombination, structure:emptyMarkerCombination || structure, geometry, visible:box.width > 0 && box.height > 0, protected:controls || protectedContext(element) || mixedContainer || text.length > 400 || count > 100 || visited > 101 };
  }
  function inspect(element, mode) { return evaluate(features(element), mode); }
  function createScan(scope, onNode = () => {}, include = () => false) {
    const seen = new WeakSet();
    const walker = (scope.ownerDocument || scope).createTreeWalker(scope, 1);
    let first = scope.nodeType === 1 ? scope : null, done = false;
    const add = (element) => {
      const result = [];
      for (let depth = 0; element && depth < 4; depth++, element = element.parentElement) {
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
      const likely = include(element) || element.tagName === "IFRAME" || element.tagName === "INS" || token.test(element.id || "") || token.test(element.getAttribute("class") || "") || strongMarker(element) || referenceLabel(element) || leafLabel(element);
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
  const api = { evaluate, features, inspect, candidates, createScan, label, token, matchesLabel };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.NullADDetector = api;
})(globalThis);
