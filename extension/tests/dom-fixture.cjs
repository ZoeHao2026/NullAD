"use strict";
// Tiny DOM seam for deterministic controller tests; browser rendering is tested separately.
class Node {
  constructor(document, type) { this.ownerDocument = document; this.nodeType = type; this.parentNode = null; this.childNodes = []; }
  get parentElement() { return this.parentNode && this.parentNode.nodeType === 1 ? this.parentNode : null; }
  get firstChild() { return this.childNodes[0] || null; }
  get nextSibling() { if (!this.parentNode) return null; return this.parentNode.childNodes[this.parentNode.childNodes.indexOf(this) + 1] || null; }
  get isConnected() { return this.nodeType === 9 || (this.host ? this.host.isConnected : !!this.parentNode && this.parentNode.isConnected); }
  get childElementCount() { return this.childNodes.filter(node => node.nodeType === 1).length; }
  get textContent() { return this.nodeType === 3 ? this.nodeValue : this.childNodes.map(node => node.textContent).join(""); }
  set textContent(value) { for (const node of this.childNodes) node.parentNode = null; this.childNodes = []; if (value) { const child = new Node(this.ownerDocument, 3); child.nodeValue = String(value); this.appendChild(child); } }
  appendChild(child) { child.remove(); child.parentNode = this; this.childNodes.push(child); return child; }
  remove() { if (this.parentNode) { this.parentNode.childNodes.splice(this.parentNode.childNodes.indexOf(this), 1); this.parentNode = null; } }
  getRootNode() { return this.parentNode ? this.parentNode.getRootNode() : this; }
}
class Element extends Node {
  constructor(document, tag) { super(document, 1); this.tagName = tag.toUpperCase(); this.attrs = new Map(); this.width = 300; this.height = 80; }
  get id() { return this.getAttribute("id") || ""; }
  getAttribute(name) { return this.attrs.has(name) ? this.attrs.get(name) : null; }
  hasAttribute(name) { return this.attrs.has(name); }
  setAttribute(name, value) { this.attrs.set(name, String(value)); }
  removeAttribute(name) { this.attrs.delete(name); }
  getBoundingClientRect() {
    let current = this;
    while (current) { if (current.nodeType === 1 && current.getAttribute("data-nullad-local-hidden") === "nullad") return { width:0, height:0 }; current = current.parentNode; }
    return { width:this.width, height:this.height };
  }
  attachShadow() { const shadow = new Node(this.ownerDocument, 11); shadow.host = this; this.shadowRoot = shadow; return shadow; }
}
function fixture() {
  const document = new Node(null, 9); document.ownerDocument = document;
  document.createElement = tag => new Element(document, tag);
  document.walked = 0;
  document.createTreeWalker = (scope, mask) => {
    let current = scope;
    return { nextNode() {
      while (current) {
        if (current.firstChild) current = current.firstChild;
        else {
          while (current !== scope && !current.nextSibling) current = current.parentNode;
          if (current === scope) { current = null; return null; }
          current = current.nextSibling;
        }
        document.walked++;
        if ((current.nodeType === 1 && (mask & 1)) || (current.nodeType === 3 && (mask & 4))) return current;
      }
      return null;
    } };
  };
  document.documentElement = document.appendChild(document.createElement("html"));
  document.head = document.documentElement.appendChild(document.createElement("head"));
  document.body = document.documentElement.appendChild(document.createElement("body"));
  const frames = [], timers = new Map(), observers = [], notifications = []; let id = 0;
  class Observer {
    constructor(callback) { this.callback = callback; this.connected = false; observers.push(this); }
    observe(scope, options) { this.scope = scope; this.options = options; this.connected = true; }
    disconnect() { this.connected = false; }
    emit(records) { if (this.connected) this.callback(records); }
  }
  const environment = { Observer, raf:callback => frames.push(callback), later:callback => { timers.set(++id, callback); return id; }, cancel:key => timers.delete(key), now:() => 0, notify:value => notifications.push(value) };
  function drain() {
    let count = 0;
    while (timers.size || frames.length) {
      if (++count > 20000) throw new Error("scan did not settle");
      if (timers.size) { const callbacks = [...timers.values()]; timers.clear(); for (const callback of callbacks) callback(); }
      else frames.shift()();
    }
    return count;
  }
  const element = (tag = "div", attrs = {}, text = "", parent = document.body) => {
    const value = document.createElement(tag); for (const [key, attribute] of Object.entries(attrs)) value.setAttribute(key, attribute); value.textContent = text; if (parent) parent.appendChild(value); return value;
  };
  const ad = (parent = document.body) => { const value = element("div", {class:"ad-box", "aria-label":"Advertisement"}, "", parent); element("img", {}, "", value); return value; };
  return { document, element, ad, environment, observers, notifications, timers, frames, drain };
}
module.exports = { fixture };
