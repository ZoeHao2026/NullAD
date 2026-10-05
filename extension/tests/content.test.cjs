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
test("child label recycling restores its hidden container and later ad reuse is detected again",()=>{
  const f=fixture(),ad=f.element("div",{class:"ad-slot"}),badge=f.element("span",{},"Publicité",ad);f.element("img",{},"",ad);
  const controller=createController(f.document,f.environment);controller.configure("conservative");f.drain();assert.equal(ad.getAttribute(marker),"nullad");
  badge.firstChild.nodeValue="Account settings";f.observers[0].emit([{type:"characterData",target:badge.firstChild}]);f.drain();assert.equal(ad.hasAttribute(marker),false);assert.equal(controller.stats().hidden,0);
  badge.firstChild.nodeValue="広告";f.observers[0].emit([{type:"characterData",target:badge.firstChild}]);f.drain();assert.equal(ad.getAttribute(marker),"nullad");
  controller.restoreAll();badge.firstChild.nodeValue="Sponsored";f.observers[0].emit([{type:"characterData",target:badge.firstChild}]);f.drain();assert.equal(ad.hasAttribute(marker),false);
});
test("child aria label, disabled marker and newly interactive role changes are observed",()=>{
  const f=fixture(),ad=f.element("div",{class:"ad-placement"}),badge=f.element("div",{"aria-label":"광고"},"",ad);f.element("img",{},"",ad);
  const controller=createController(f.document,f.environment);controller.configure("conservative");f.drain();assert.equal(ad.getAttribute(marker),"nullad");
  badge.setAttribute("aria-label","Account settings");f.observers[0].emit([{type:"attributes",target:badge}]);f.drain();assert.equal(ad.hasAttribute(marker),false);
  badge.setAttribute("aria-label","Anzeige");f.observers[0].emit([{type:"attributes",target:badge}]);f.drain();assert.equal(ad.getAttribute(marker),"nullad");
  badge.setAttribute("role","navigation");f.observers[0].emit([{type:"attributes",target:badge}]);f.drain();assert.equal(ad.hasAttribute(marker),false);
  const attributes=f.observers[0].options.attributeFilter;for(const value of ["aria-labelledby","aria-description","role","contenteditable","data-sponsored","data-ad-placement","hidden","style"])assert.ok(attributes.includes(value),value);
});
test("infinite scroll batches preserve normal siblings while detecting new multilingual containers",()=>{
  const f=fixture(),feed=f.element("div"),controller=createController(f.document,f.environment);controller.configure("balanced");f.drain();const ads=[],normal=[];
  for(let i=0;i<60;i++){
    const ad=f.element("div",{},"",feed);f.element("span",{},i%2?"广告":"Publicité",ad);f.element("img",{},"",ad);ads.push(ad);
    normal.push(f.element("div",{},"Normal content card "+i,feed));
  }
  f.observers[0].emit([{type:"childList",target:feed,addedNodes:[...ads,...normal]}]);f.drain();
  assert.ok(ads.every(value=>value.getAttribute(marker)==="nullad"));assert.ok(normal.every(value=>!value.hasAttribute(marker)));assert.equal(feed.hasAttribute(marker),false);
  controller.configure("off");assert.ok(ads.every(value=>!value.hasAttribute(marker)));
});
test("a recycled child within the bounded four-parent notification range restores the slot",()=>{
  const f=fixture(),ad=f.element("div",{class:"ad-slot"});let parent=ad;for(let i=0;i<3;i++)parent=f.element("div",{},"",parent);
  const badge=f.element("span",{},"广告",parent);f.element("img",{},"",ad);const controller=createController(f.document,f.environment);controller.configure("conservative");f.drain();assert.equal(ad.getAttribute(marker),"nullad");
  badge.firstChild.nodeValue="Normal";f.observers[0].emit([{type:"characterData",target:badge.firstChild}]);f.drain();assert.equal(ad.hasAttribute(marker),false);
});
test("false/off advertising markers on a reused slot remove their prior hiding evidence",()=>{
  const f=fixture(),ad=f.element("div",{"data-sponsored":"true"});f.element("img",{},"",ad);
  const controller=createController(f.document,f.environment);controller.configure("balanced");f.drain();assert.equal(ad.getAttribute(marker),"nullad");
  ad.setAttribute("data-sponsored","off");f.observers[0].emit([{type:"attributes",target:ad}]);f.drain();assert.equal(ad.hasAttribute(marker),false);
  ad.setAttribute("data-sponsored","true");f.observers[0].emit([{type:"attributes",target:ad}]);f.drain();assert.equal(ad.getAttribute(marker),"nullad");
  ad.setAttribute("data-sponsored","false");f.observers[0].emit([{type:"attributes",target:ad}]);f.drain();assert.equal(ad.hasAttribute(marker),false);
});
