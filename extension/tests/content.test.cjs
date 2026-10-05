"use strict";
const test=require("node:test"), assert=require("node:assert/strict"), fs=require("node:fs"), vm=require("node:vm");
const {createController}=require("../content.js"), detector=require("../detector.js"), {fixture}=require("./dom-fixture.cjs");
const marker="data-nullad-local-hidden";
test("hide is reversible, preserves author attributes/styles and restore exempts subsequent scans",()=>{
  const f=fixture(), ad=f.ad();ad.setAttribute(marker,"author");ad.setAttribute("style","color:red");const controller=createController(f.document,f.environment);
  controller.configure("conservative");f.drain();assert.equal(ad.getAttribute(marker),"nullad");assert.equal(controller.stats().hidden,1);
  controller.restoreAll();assert.equal(ad.getAttribute(marker),"author");assert.equal(ad.getAttribute("style"),"color:red");
  controller.enqueue(ad);f.drain();assert.equal(controller.stats().hidden,0);assert.equal(ad.getAttribute(marker),"author");
  controller.configure("off");assert.ok(f.observers.every(value=>!value.connected));assert.equal(f.document.head.childNodes.length,0);
});
test("a hidden SPA node recycled for normal content is measured and restored",()=>{
  const f=fixture(),ad=f.ad(),controller=createController(f.document,f.environment);controller.configure("balanced");f.drain();
  ad.removeAttribute("class");ad.removeAttribute("aria-label");ad.textContent="Normal settings panel";
  f.observers[0].emit([{type:"attributes",target:ad}]);f.drain();
  assert.equal(ad.hasAttribute(marker),false);assert.equal(controller.stats().hidden,0);
});
test("removed nodes shed our marker, then reinserted nodes remain tracked and stop restores them",()=>{
  const f=fixture(),ad=f.ad(),controller=createController(f.document,f.environment);controller.configure("conservative");f.drain();
  ad.remove();controller.enqueue(f.document.body);f.drain();assert.equal(ad.hasAttribute(marker),false);assert.equal(controller.stats().hidden,0);
  f.document.body.appendChild(ad);controller.enqueue(ad);f.drain();assert.equal(controller.stats().hidden,1);
  controller.configure("off");assert.equal(ad.hasAttribute(marker),false);assert.equal(controller.stats().hidden,0);
});
test("initial traversal continues across frame budgets and processes the document tail",()=>{
  const f=fixture();for(let i=0;i<1300;i++)f.element("div",{},"Normal");const ad=f.ad(),controller=createController(f.document,f.environment);
  controller.configure("balanced");assert.ok(f.drain()>3);assert.equal(ad.getAttribute(marker),"nullad");
});
test("mutations are coalesced and observer shutdown prevents subsequent hiding",()=>{
  const f=fixture(),controller=createController(f.document,f.environment);controller.configure("balanced");f.drain();const ad=f.ad();
  const record={type:"childList",target:f.document.body,addedNodes:[ad]};for(let i=0;i<200;i++)f.observers[0].emit([record]);assert.equal(f.timers.size,1);f.drain();assert.equal(controller.stats().hidden,1);
  controller.configure("off");f.observers[0].emit([record]);f.drain();assert.equal(ad.hasAttribute(marker),false);
});
test("open shadow roots have local styles; observer limit does not report unstyled nodes as hidden",()=>{
  const f=fixture(),ads=[];for(let i=0;i<34;i++){const host=f.element("div"),shadow=host.attachShadow();ads.push(f.ad(shadow));}
  const controller=createController(f.document,f.environment);controller.configure("balanced");f.drain();
  assert.equal(f.observers.filter(value=>value.connected).length,32);assert.equal(controller.stats().hidden,31);
  assert.equal(ads[33].hasAttribute(marker),false);assert.equal(ads[0].getRootNode().childNodes.filter(node=>node.tagName==="STYLE").length,1);
  const oldRoot=ads[0].getRootNode();oldRoot.host.remove();controller.enqueue(f.document.body);f.drain();
  assert.equal(oldRoot.childNodes.filter(node=>node.tagName==="STYLE").length,0);assert.equal(ads[31].getAttribute(marker),"nullad");
  controller.configure("off");assert.ok(ads.every(value=>!value.hasAttribute(marker)));
});
test("late initial settings failure cannot overwrite a successful direct configure message",async()=>{
  const f=fixture();let rejectConfig,listener;
  const config=new Promise((resolve,reject)=>rejectConfig=reject);
  const context={document:f.document,NullADDetector:detector,requestAnimationFrame:f.environment.raf,setTimeout:f.environment.later,clearTimeout:f.environment.cancel,performance:{now:()=>0},MutationObserver:f.environment.Observer,chrome:{runtime:{id:"fixture",sendMessage:message=>message.type==="GET_CONFIG"?config:Promise.resolve({ok:true}),onMessage:{addListener:value=>listener=value}}}};
  context.globalThis=context;vm.runInNewContext(fs.readFileSync(require.resolve("../content.js"),"utf8"),context);
  listener({type:"CONFIGURE",mode:"balanced"},{id:"fixture"},()=>{});rejectConfig(new Error("worker asleep"));await new Promise(resolve=>setImmediate(resolve));
  assert.equal(context.__nulladLocalController.stats().mode,"balanced");context.__nulladLocalController.configure("off");
});
