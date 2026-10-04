"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { createClient } = require("../ipc.js");
const helpers = require("../state.js");

test("IPC rejects backend errors instead of returning success-like null", async () => {
  const client = createClient({ core:{ invoke:async () => { throw { message:"disk full" }; } } });
  await assert.rejects(client.call("update_settings"), /disk full/);
  await assert.rejects(createClient(null).call("get_status"), /BACKEND_UNAVAILABLE/);
});
test("listener patches exclude lists, diagnostics preferences and language", () => {
  const patch = helpers.listenerPatch({ proxy_enabled:true, proxy_port:"8080", dns_enabled:false, dns_port:"5353", dns_upstream:" 8.8.8.8:53 ", dns_nxdomain:false, intercept_system_proxy:false, lists:[{ id:42 }], ui_language:"en", log_level:"debug" });
  assert.deepEqual(Object.keys(patch), helpers.fields);
  assert.equal(patch.dns_upstream, "8.8.8.8:53");
  assert.equal(patch.proxy_port, 8080);
  assert.equal(helpers.validate(patch), null);
});
test("ports, upstream and system proxy dependencies are validated without silent defaults", () => {
  const base = { proxy_enabled:true, proxy_port:8080, dns_enabled:true, dns_port:5353, dns_upstream:"8.8.8.8:53" };
  for (const value of [0, -1, 65536, 1.5, NaN]) assert.equal(helpers.validate({ ...base, proxy_port:value }), "invalidPort");
  assert.equal(helpers.validate({ ...base, dns_upstream:"" }), "invalidUpstream");
  assert.equal(helpers.validate({ ...base, proxy_enabled:false, intercept_system_proxy:true }), "proxyRequired");
  assert.equal(helpers.validate({ ...base, dns_port:8080 }), "samePorts");
});
test("degraded state is active, transitions are busy and failed state is stopped", () => {
  assert.equal(helpers.isActive({ protection:"degraded" }), true);
  assert.equal(helpers.isBusy({ protection:"stopping" }), true);
  assert.equal(helpers.isActive({ protection:"failed" }), false);
});
test("log filters preserve order and safely escape rules and URLs", () => {
  const logs = [{ blocked:true, url:"a" }, { blocked:false, url:"b" }];
  assert.deepEqual(helpers.filterDecisions(logs, "blocked"), [logs[0]]);
  assert.deepEqual(helpers.filterDecisions(logs, "allowed"), [logs[1]]);
  assert.equal(helpers.escapeHtml('<img src="x" onerror=\'bad\'> &'), "&lt;img src=&quot;x&quot; onerror=&#39;bad&#39;&gt; &amp;");
});

function fixture(options = {}) {
  class Element {
    constructor(id) { this.id=id; this.value=""; this.checked=false; this.disabled=false; this.hidden=false; this.dataset={}; this.type="text"; this.listeners={}; this.classList={ contains:() => false, toggle:() => {} }; }
    addEventListener(name, handler) { this.listeners[name]=handler; }
    querySelectorAll() { return []; }
    setAttribute() {} removeAttribute() {}
    async fire(name) { if (this.listeners[name]) return this.listeners[name]({ preventDefault(){}, target:this }); }
  }
  const elements = {};
  const get = (id) => elements[id] || (elements[id]=new Element(id));
  const fieldIds = { proxy_enabled:"set-proxy-enabled", proxy_port:"set-proxy-port", dns_enabled:"set-dns-enabled", dns_port:"set-dns-port", dns_upstream:"set-dns-upstream", dns_nxdomain:"set-dns-nxdomain", intercept_system_proxy:"set-system-proxy" };
  ["proxy_enabled","dns_enabled","dns_nxdomain","intercept_system_proxy"].forEach((key) => get(fieldIds[key]).type="checkbox");
  get("settings-form").querySelectorAll = () => Object.values(fieldIds).map(get);
  const saved = { proxy_enabled:true, proxy_port:8080, dns_enabled:false, dns_port:5353, dns_upstream:"8.8.8.8:53", dns_nxdomain:false, intercept_system_proxy:false, ui_language:"zh-CN", lists:[{ id:4, enabled:true }] };
  const calls=[], toasts=[], notices=[], renders=[], intervals=[];
  const fillSettings = (settings) => { for (const key of helpers.fields) { const el=get(fieldIds[key]); if (el.type==="checkbox") el.checked=settings[key]; else el.value=String(settings[key]); } };
  const statuses = { protection:"running", proxy_port:8080, dns_port:null, pending_changes:0, rule_set:{ rules:232 } };
  const noop=()=>{};
  const views = { $:get, set:(id,value) => get(id).textContent=value, count:String, toast:(msg,kind) => toasts.push({msg,kind}), notice:(id,msg) => notices.push({id,msg}), hint:(id,msg,kind) => { get(id).textContent=msg; get(id).kind=kind; }, renderStatus:noop, renderDecisions:(data) => renders.push(data), renderPending:noop, renderPlatform:noop, renderBenchmark:noop, renderCheck:noop, renderLists:noop, renderRules:noop, fillSettings };
  const bridge = {
    available:true,
    listen:async () => { if (options.eventFailure) throw new Error("event blocked"); return noop; },
    call:async (command,args) => {
      calls.push({command,args});
      if (options.failCommand === command) throw new Error("write denied");
      if (command==="get_status") return statuses;
      if (command==="get_settings") return { ...saved };
      if (command==="recent_decisions") return [{ blocked:true, host:"ads.example.com", timestamp_ms:1 }];
      if (command==="platform_info") return { platform:"Test", rule_count:232 };
      if (command==="update_settings") { Object.assign(saved,args.patch); return { ...saved }; }
      return [];
    }
  };
  const document = { hidden:false, getElementById:get, querySelectorAll:() => [], addEventListener:noop };
  let language = "zh-CN";
  const i18n = { get language() { return language; }, t:(key) => options.translated && language === "en" ? "en:" + key : key, apply:(next) => { language = next; } };
  const window = { NullAD:{ ipc:bridge, state:helpers, views, i18n }, addEventListener:noop };
  const context=vm.createContext({window,document,navigator:{},URL,console,setInterval:(fn,ms) => { intervals.push({fn,ms}); },setTimeout});
  vm.runInContext(fs.readFileSync(path.join(__dirname,"../app.js"),"utf8"),context);
  return {get,saved,calls,toasts,notices,renders,intervals,fieldIds};
}
const flush=() => new Promise((resolve) => setImmediate(resolve));
test("event registration failure still loads backend state and enables polling", async () => {
  const f=fixture({eventFailure:true}); await flush(); await flush();
  assert.ok(f.calls.some((call) => call.command==="get_status"));
  assert.ok(f.calls.some((call) => call.command==="get_settings"));
  assert.deepEqual(f.intervals.map((item) => item.ms), [5000,2000]);
  assert.ok(f.notices.some((notice) => notice.msg==="eventsFailed"));
  const before=f.calls.filter((call) => call.command==="recent_decisions").length;
  await f.intervals.find((item) => item.ms===2000).fn(); await flush();
  assert.ok(f.calls.filter((call) => call.command==="recent_decisions").length>before, "dashboard polling loads live logs");
});
test("failed explicit save retains draft, never announces success and cancel restores saved state", async () => {
  const f=fixture({failCommand:"update_settings"}); await flush(); await flush();
  f.get("set-proxy-port").value="9090";
  await f.get("settings-form").fire("input");
  await f.get("settings-form").fire("submit");
  const call=f.calls.find((item) => item.command==="update_settings");
  assert.ok(call);
  assert.equal(call.args.patch.proxy_port,9090);
  assert.deepEqual(Object.keys(call.args.patch), ["proxy_port"]);
  assert.equal(Object.hasOwn(call.args.patch,"lists"),false);
  assert.equal(f.get("set-proxy-port").value,"9090");
  assert.equal(f.get("settings-status").kind,"error");
  assert.equal(f.toasts.some((item) => item.msg==="settingsSaved"),false);
  await f.get("cancel-settings").fire("click");
  assert.equal(f.get("set-proxy-port").value,"8080");
});
test("success save patches only listener fields and preserves newest filter lists", async () => {
  const f=fixture(); await flush(); await flush();
  f.saved.lists=[{id:9,enabled:false}];
  f.get("set-proxy-port").value="9090";
  await f.get("settings-form").fire("submit");
  assert.deepEqual(f.saved.lists,[{id:9,enabled:false}]);
  assert.equal(f.saved.proxy_port,9090);
  assert.ok(f.toasts.some((item) => item.msg==="settingsSaved"));
});
test("failed clear-log preserves last rendered entries", async () => {
  const f=fixture({failCommand:"clear_log"}); await flush(); await flush();
  await f.get("log-clear").fire("click");
  assert.equal(f.renders.at(-1).length,1);
  assert.equal(f.toasts.some((item) => item.msg==="logsCleared"),false);
});
test("language changes retranslate saved feedback, unsaved rules and event fallback notices", async () => {
  const f=fixture({translated:true,eventFailure:true}); await flush(); await flush();
  f.get("set-proxy-port").value="9090";
  await f.get("settings-form").fire("submit");
  await f.get("custom-rules").fire("input");
  f.get("language-select").value="en";
  await f.get("language-select").fire("change");
  assert.equal(f.get("settings-status").textContent,"en:settingsSaved");
  assert.equal(f.get("custom-status").textContent,"en:customUnsaved");
  assert.equal(f.notices.at(-1).msg,"en:eventsFailed");
});
test("all static text keys have both translations", () => {
  const source=fs.readFileSync(path.join(__dirname,"../i18n.js"),"utf8");
  const window={localStorage:{getItem:() => null},document:{}};
  vm.runInNewContext(source,{window});
  const html=fs.readFileSync(path.join(__dirname,"../index.html"),"utf8");
  const keys=[...html.matchAll(/data-i18n(?:-aria|-placeholder)?="([^"]+)"/g)].map((match) => match[1]);
  for (const key of keys) {
    assert.equal(window.NullAD.i18n.text[key].length,2,key);
    assert.ok(window.NullAD.i18n.text[key][0] && window.NullAD.i18n.text[key][1],key);
  }
});
