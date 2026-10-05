"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const detector = require("../detector.js"), {fixture} = require("./dom-fixture.cjs");
test("thresholds require independent evidence and never use shape, ad substring or iframe alone", () => {
  const base = { visible:true, protected:false };
  for (const value of [{geometry:true}, {marker:true,geometry:true}, {structure:true,geometry:true}, {label:true}]) assert.equal(detector.evaluate({...base,...value},"balanced").hide,false);
  assert.equal(detector.evaluate({...base,label:true,structure:true},"balanced").hide,true);
  assert.equal(detector.evaluate({...base,label:true,structure:true},"conservative").hide,false);
  assert.equal(detector.evaluate({...base,label:true,marker:true,structure:true},"conservative").hide,true);
  assert.equal(detector.evaluate({...base,label:true,marker:true,structure:true},"off").hide,false);
});
test("bounded labelled container and unrelated empty multi-marker container are positives", () => {
  const f=fixture(); assert.equal(detector.inspect(f.ad(),"conservative").hide,true);
  const decoy=f.element("div",{id:"unrelated-fixture",class:"adsbox textads banner_ads adbox ADBox"},"\u00a0"); decoy.width=1;decoy.height=1;
  assert.equal(detector.inspect(decoy,"conservative").hide,true);
  assert.ok(detector.inspect(decoy,"conservative").reasons.includes("multiple-explicit-empty-ad-markers"));
});
test("normal negative samples retain single marker, lookalike words, articles and controls", () => {
  const f=fixture();
  for(const value of [f.element("div",{class:"adbox"},"Normal product description"),f.element("div",{class:"adobe admin header-adapter download"}),f.element("iframe"),f.element("div",{},"Advertisement"),f.element("div",{class:"adbox ADBox"}),f.element("div",{class:"textads adsbox"},"Ordinary content")]) assert.equal(detector.inspect(value,"balanced").hide,false);
  const form=f.ad();f.element("input",{},"",form);assert.equal(detector.inspect(form,"balanced").hide,false);
  const editable=f.ad();editable.setAttribute("contenteditable","plaintext-only");assert.equal(detector.inspect(editable,"balanced").hide,false);
  const main=f.ad();main.setAttribute("role","main");assert.equal(detector.inspect(main,"balanced").hide,false);
  const article=f.ad();f.element("p",{},"Normal article about advertising. ".repeat(50),article);assert.equal(detector.inspect(article,"balanced").hide,false);
});
test("large candidate rejection traverses a bounded prefix without whole-tree selectors or textContent", () => {
  const f=fixture(), large=f.ad(); for(let i=0;i<1000;i++) f.element("span",{},"",large);
  Object.defineProperty(large,"textContent",{get(){throw new Error("unbounded text read");}});
  large.querySelector=()=>{throw new Error("unbounded selector");}; f.document.walked=0;
  assert.equal(detector.inspect(large,"balanced").hide,false);assert.ok(f.document.walked<=102);
});
test("empty text nodes and huge leaf labels cannot bypass the traversal budget", () => {
  const f=fixture(),ad=f.ad();
  for(let i=0;i<1000;i++){const text=f.document.createElement("span");text.textContent="x";const node=text.firstChild;node.nodeValue="";ad.appendChild(node);}
  f.document.walked=0;assert.equal(detector.inspect(ad,"balanced").hide,false);assert.ok(f.document.walked<=102);
  const leaf=f.element("span",{},"Advertisement"+" ".repeat(10000));Object.defineProperty(leaf,"textContent",{get(){throw new Error("full leaf text read");}});
  assert.doesNotThrow(()=>detector.candidates(leaf));
});
test("persistent candidate cursor reaches an ad beyond the first thousand elements", () => {
  const f=fixture();for(let i=0;i<1250;i++)f.element("div",{},"Normal");const tail=f.ad();
  const scan=detector.createScan(f.document.documentElement), found=[];let steps=0;
  for(;;){const part=scan.next();if(part.done)break;steps++;found.push(...part.candidates);}
  assert.ok(steps>1250);assert.ok(found.includes(tail));
  assert.equal(found.filter(value=>value===tail).length,1);
});
