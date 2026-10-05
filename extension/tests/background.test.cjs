"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const {createService} = require("../background.js");
function fixture() {
  const local = {}, session = {}, messages = [], injection = [];
  let dynamic = [], rules = [], scripts = [], access = false;
  const faults = {}, frameStats = {};
  const area = (data, name) => ({ get:async () => structuredClone(data), set:async (value) => { if(faults[name]){delete faults[name];throw new Error(name+" persistence failed");}Object.assign(data,structuredClone(value)); } });
  const tabs = [{id:1,url:"https://news.example/article"},{id:2,url:"https://other.example/"},{id:3,url:"https://sub.news.example/"}];
  const api = {
    runtime:{getURL:page=>"chrome-extension://fixture-id/"+page},
    storage:{local:area(local,"local"),session:area(session,"session")},
    permissions:{contains:async()=>access},
    tabs:{query:async()=>structuredClone(tabs),get:async(id)=>structuredClone(tabs.find(tab=>tab.id===id)),sendMessage:async(id,message)=>{messages.push({id,message});if(faults.message)throw new Error("document disappeared");return{hidden:0};}},
    scripting:{getRegisteredContentScripts:async()=>structuredClone(scripts),registerContentScripts:async(value)=>{if(faults.register)throw new Error("registration failed");scripts.push(...value);},unregisterContentScripts:async()=>{scripts=[];},executeScript:async(value)=>{if(faults.inject)throw new Error("injection failed");injection.push(value);return value.func?structuredClone((frameStats[value.target.tabId]||[{frameId:0,result:{hidden:0,mode:"off"}}]).map(frame=>value.args[0]?{...frame,result:{hidden:0,mode:frame.result.mode}}:frame)):undefined;}},
    declarativeNetRequest:{isRegexSupported:async()=>({isSupported:!faults.regex,reason:"invalid"}),getDynamicRules:async()=>structuredClone(dynamic),getSessionRules:async()=>structuredClone(rules),updateDynamicRules:async(value)=>{if(faults.dynamic)throw new Error("DNR failed");dynamic=dynamic.filter(rule=>!value.removeRuleIds.includes(rule.id)).concat(structuredClone(value.addRules));},updateSessionRules:async(value)=>{if(faults.ruleSession){delete faults.ruleSession;throw new Error("session DNR failed");}rules=rules.filter(rule=>!value.removeRuleIds.includes(rule.id)).concat(structuredClone(value.addRules));}}
  };
  return {service:createService(api),api,local,session,tabs,messages,injection,faults,frameStats,grant:()=>{access=true;},revoke:()=>{access=false;},dynamic:()=>dynamic,rules:()=>rules,scripts:()=>scripts};
}
test("installation starts off without permission, rules or page injection",async()=>{
  const f=fixture();await f.service.reconcile();
  assert.deepEqual(f.dynamic(),[]);assert.deepEqual(f.rules(),[]);assert.deepEqual(f.scripts(),[]);assert.deepEqual(f.injection,[]);
  assert.equal((await f.service.handle({type:"STATE",tabId:1})).mode,"off");
});
test("permission denial rejects enable without publishing false success",async()=>{
  const f=fixture();await assert.rejects(f.service.handle({type:"ENABLE",scope:"all",mode:"balanced",tabId:1}),/not been granted/);
  assert.equal(f.local.settings,undefined);assert.equal(f.dynamic().length,0);
});
test("all-sites enable persists and stop removes every DNR rule and restores documents",async()=>{
  const f=fixture();f.grant();await f.service.handle({type:"ENABLE",scope:"all",mode:"balanced",tabId:1});
  assert.equal(f.local.settings.mode,"balanced");assert.ok(f.dynamic().filter(rule=>rule.action.type==="block").length>=5);assert.equal(f.scripts().length,1);
  await f.service.handle({type:"ALLOW_SITE",tabId:1,allowed:true});
  assert.ok(f.dynamic().some(rule=>rule.action.type==="allowAllRequests"));
  await f.service.handle({type:"STOP"});
  assert.deepEqual(f.dynamic(),[]);assert.deepEqual(f.rules(),[]);assert.deepEqual(f.scripts(),[]);
  assert.ok(f.messages.slice(-3).every(item=>item.message.mode==="off"));
});
test("this-tab mode survives same-host reload, switches scope and clears on different host",async()=>{
  const f=fixture();f.grant();await f.service.handle({type:"ENABLE",scope:"all",mode:"balanced",tabId:1});
  await f.service.handle({type:"ENABLE",scope:"page",mode:"conservative",tabId:1});
  assert.equal(f.dynamic().length,0);assert.ok(f.rules().every(rule=>rule.condition.tabIds[0]===1));
  f.tabs[0].url="https://news.example/another";await f.service.navigated(1,f.tabs[0].url);assert.ok(f.rules().length);
  f.tabs[0].url="https://different.example/";await f.service.navigated(1,f.tabs[0].url);assert.equal(f.rules().length,0);
});
test("exact-site allow immediately restores that tab while subdomain stays active; removal resumes",async()=>{
  const f=fixture();f.grant();await f.service.handle({type:"ENABLE",scope:"all",mode:"balanced",tabId:1});
  await f.service.handle({type:"ALLOW_SITE",tabId:1,allowed:true});
  assert.equal((await f.service.handle({type:"GET_CONFIG"},{tab:f.tabs[0]})).mode,"off");
  assert.equal((await f.service.handle({type:"GET_CONFIG"},{tab:f.tabs[2]})).mode,"balanced");
  assert.ok(f.rules().some(rule=>rule.action.type==="allow"&&rule.condition.tabIds[0]===1));
  assert.equal(f.messages.filter(item=>item.id===1).at(-1).message.mode,"off");
  await f.service.handle({type:"REMOVE_SITE",host:"news.example"});
  assert.equal((await f.service.handle({type:"GET_CONFIG"},{tab:f.tabs[0]})).mode,"balanced");
  assert.equal(f.dynamic().some(rule=>rule.action.type==="allowAllRequests"),false);
});
test("DNR session failure rolls back the previously installed global rules",async()=>{
  const f=fixture();f.grant();await f.service.handle({type:"ENABLE",scope:"all",mode:"conservative",tabId:1});const previous=structuredClone(f.dynamic());
  f.faults.ruleSession=true;await assert.rejects(f.service.handle({type:"ENABLE",scope:"page",mode:"balanced",tabId:1}),/session DNR failed/);
  assert.deepEqual(f.dynamic(),previous);assert.equal(f.local.settings.mode,"conservative");
});
test("registration and persistence failures reject and restore previous network policy",async()=>{
  const f=fixture();f.grant();f.faults.register=true;
  await assert.rejects(f.service.handle({type:"ENABLE",scope:"all",mode:"balanced",tabId:1}),/registration failed/);assert.equal(f.dynamic().length,0);
  delete f.faults.register;f.faults.local=true;
  await assert.rejects(f.service.handle({type:"ENABLE",scope:"all",mode:"balanced",tabId:1}),/persistence failed/);
  assert.equal(f.dynamic().length,0);assert.equal(f.scripts().length,0);assert.equal(f.local.settings.mode,"off");
});
test("unsupported regex/API is reported instead of a success-shaped empty value",async()=>{
  const f=fixture();f.grant();f.faults.regex=true;
  await assert.rejects(f.service.handle({type:"ENABLE",scope:"all",mode:"balanced",tabId:1}),/Unsupported network heuristic/);
  f.api.declarativeNetRequest=null;await assert.rejects(f.service.handle({type:"STATE",tabId:1}),/unavailable/);
});
test("DOM injection failures are surfaced separately from valid network installation",async()=>{
  const f=fixture();f.grant();f.faults.inject=true;const result=await f.service.handle({type:"ENABLE",scope:"all",mode:"conservative",tabId:1});
  assert.ok(result.networkRules>0);assert.ok(result.warnings.length);assert.match(result.warnings[0],/Page cleanup could not start/);
});
test("page sender cannot mutate policy and reports retain only bounded summary fields",async()=>{
  const f=fixture();await assert.rejects(f.service.handle({type:"STOP"},{tab:f.tabs[0]}),/popup/);
  await Promise.all([0,2].map(frameId=>f.service.handle({type:"REPORT",stats:{hidden:2,mode:"balanced",url:"private",reasons:[]}},{tab:f.tabs[0],frameId})));
  f.grant();f.frameStats[1]=[0,2].map(frameId=>({frameId,result:{hidden:2,mode:"balanced"}}));
  assert.equal((await f.service.handle({type:"STATE",tabId:1})).hidden,4);assert.equal(JSON.stringify(f.session).includes("private"),false);
});
test("own popup and options pages remain authorized when Chrome supplies a tab sender",async()=>{
  const f=fixture();f.grant();
  await f.service.handle({type:"ENABLE",scope:"all",mode:"balanced",tabId:1},{tab:{id:9},url:f.api.runtime.getURL("popup.html")+"?qa=1#view"});
  assert.equal(f.local.settings.mode,"balanced");
  await f.service.handle({type:"STOP"},{tab:{id:9},url:f.api.runtime.getURL("options.html")});
  assert.equal(f.local.settings.mode,"off");assert.equal(f.dynamic().length,0);
});
test("HTTP content senders cannot forge policy authority through message fields or URL lookalikes",async()=>{
  const f=fixture();f.grant();
  const message={type:"ENABLE",scope:"all",mode:"balanced",tabId:1,url:f.api.runtime.getURL("popup.html"),sender:{url:f.api.runtime.getURL("options.html")}};
  for(const url of ["https://news.example/", "https://fixture-id/popup.html", "chrome-extension://other-id/options.html", f.api.runtime.getURL("popup.html")+"/extra", f.api.runtime.getURL("tests/fixtures.html"), "https://news.example/?page="+f.api.runtime.getURL("popup.html")]) await assert.rejects(f.service.handle(message,{tab:f.tabs[0],url}),/extension popup/);
  assert.equal(f.local.settings,undefined);assert.equal(f.dynamic().length,0);
});
test("revoking host access reconciles to zero rules and stops all current documents",async()=>{
  const f=fixture();f.grant();await f.service.handle({type:"ENABLE",scope:"all",mode:"balanced",tabId:1});f.revoke();await f.service.reconcile();
  assert.equal(f.dynamic().length,0);assert.equal(f.rules().length,0);assert.equal(f.scripts().length,0);assert.equal((await f.service.handle({type:"STATE",tabId:1})).mode,"off");
});
test("restore is a DOM command and leaves installed request rules unchanged",async()=>{
  const f=fixture();f.grant();await f.service.handle({type:"ENABLE",scope:"all",mode:"balanced",tabId:1});const previous=structuredClone(f.dynamic());const result=await f.service.handle({type:"RESTORE",tabId:1});
  assert.deepEqual(f.dynamic(),previous);assert.equal(result.hidden,0);assert.equal(f.injection.at(-1).target.allFrames,true);assert.equal(f.injection.at(-1).args[0],true);
});
test("current frame snapshots discard removed iframe and stale document reports",async()=>{
  const f=fixture();f.grant();await f.service.handle({type:"REPORT",stats:{hidden:99,mode:"balanced"}},{tab:f.tabs[0],frameId:8,documentId:"removed"});
  f.frameStats[1]=[{frameId:0,result:{hidden:1,mode:"balanced"}}];const state=await f.service.handle({type:"STATE",tabId:1});
  assert.equal(state.hidden,1);assert.deepEqual(Object.keys(state.reports[1]),["0"]);
  f.frameStats[1]=[{frameId:0,result:{hidden:0,mode:"balanced"}}];assert.equal((await f.service.handle({type:"STATE",tabId:1})).hidden,0);
});
test("failed live frame query reports unknown count and restore fails instead of claiming success",async()=>{
  const f=fixture();f.grant();f.faults.inject=true;const state=await f.service.handle({type:"STATE",tabId:1});
  assert.equal(state.hidden,null);assert.match(state.statsWarning,/could not be confirmed/);await assert.rejects(f.service.handle({type:"RESTORE",tabId:1}),/injection failed/);
});
test("stop reports restoration warning when a previously hidden document cannot be reached",async()=>{
  const f=fixture();f.grant();await f.service.handle({type:"ENABLE",scope:"all",mode:"balanced",tabId:1});await f.service.handle({type:"REPORT",stats:{hidden:1,mode:"balanced"}},{tab:f.tabs[0]});
  f.faults.message=true;const result=await f.service.handle({type:"STOP"});assert.equal(f.dynamic().length,0);assert.match(result.warnings.join(" "),/restoration could not be confirmed/);
});
