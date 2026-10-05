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
test("explicit multilingual labels normalize harmless decoration but never match prose substrings", () => {
  const f=fixture();
  for(const value of ["付费推广", "廣告", "[Advertisement]", "Sponsored content:", "広告", "スポンサーコンテンツ", "광고", "유료 광고", "Publicité", "Contenu sponsorisé", "Anzeige", "Gesponsert", "Publicidad", "Contenido patrocinado", "Anúncio", "Conteúdo patrocinado", "Pubblicità", "Contenuto sponsorizzato", "Advertentie", "Treść sponsorowana", "Реклама", "إعلان ممول", "תוכן ממומן"]){
    assert.equal(detector.matchesLabel(value),true,value);const ad=f.ad();ad.setAttribute("aria-label",value);assert.equal(detector.inspect(ad,"conservative").hide,true,value);
  }
  for(const value of ["How advertising works", "Advertisement settings", "Sponsored by our community volunteers", "Publicité et société", "広告についての記事", "publicidad educativa", "Admin", "Recommended", "PR", "Recommended for you", "adobe", "スポンサーリンクを管理", "Advertisement"+"x".repeat(81)]) assert.equal(detector.matchesLabel(value),false,value);
});
test("aria-labelledby uses the exact accessible label, bounded references and current shadow scope", () => {
  const f=fixture();f.element("span",{id:"ad-label"},"广告");f.element("span",{id:"regular-label"},"Product reviews");
  const ad=f.element("div",{class:"ad-placement", "aria-labelledby":"ad-label"});f.element("img",{},"",ad);
  assert.equal(detector.inspect(ad,"conservative").hide,true);assert.ok(detector.candidates(f.document.documentElement).includes(ad));
  ad.setAttribute("aria-labelledby","regular-label ad-label");assert.equal(detector.features(ad).label,false);
  ad.setAttribute("aria-labelledby","missing ad-label");assert.equal(detector.features(ad).label,false);
  ad.setAttribute("aria-labelledby","ad-label ad-label ad-label ad-label");assert.equal(detector.features(ad).label,false);
  const host=f.element("div"),shadow=host.attachShadow();f.element("span",{id:"ad-label"},"Normal",shadow);
  const shadowAd=f.element("div",{class:"ad-slot", "aria-labelledby":"ad-label"},"",shadow);f.element("img",{},"",shadowAd);
  assert.equal(detector.features(shadowAd).label,false);
  shadow.getElementById("ad-label").textContent="広告";assert.equal(detector.inspect(shadowAd,"conservative").hide,true);
});
test("a child badge or advertising attribute promotes only its bounded creative container", () => {
  const f=fixture(),ad=f.element("div",{class:"ad-slot"}),badge=f.element("div",{"aria-description":"Contenu sponsorisé"},"",ad),media=f.element("a",{href:"https://brand.example/"},"",ad);f.element("img",{},"",media);
  assert.equal(detector.inspect(ad,"conservative").hide,true);assert.equal(detector.inspect(badge,"balanced").hide,false);
  const generic=f.element("div");f.element("span",{},"广告",generic);f.element("img",{},"",generic);
  assert.equal(detector.inspect(generic,"balanced").hide,true);assert.equal(detector.inspect(generic,"conservative").hide,false);
  const marked=f.element("div");f.element("div",{"data-ad-placement":"slot"},"",marked);f.element("iframe",{},"",marked);
  assert.equal(detector.inspect(marked,"balanced").hide,true);assert.ok(detector.inspect(marked,"balanced").reasons.includes("contained-advertising-attribute"));
});
test("a sponsored child never promotes a mixed feed, article or unrelated sibling", () => {
  const f=fixture(),feed=f.element("div"),ad=f.ad(feed);f.element("div",{},"Normal account settings",feed);
  assert.equal(detector.inspect(ad,"conservative").hide,true);assert.equal(detector.inspect(feed,"balanced").hide,false);
  const mixed=f.element("div"),badge=f.element("span",{},"Sponsored",mixed);f.element("a",{href:"#article"},"Ordinary product review",mixed);
  assert.equal(detector.inspect(mixed,"balanced").hide,false);assert.equal(detector.inspect(badge,"balanced").hide,false);
  const article=f.element("article",{class:"ad-slot"});f.element("span",{},"广告",article);f.element("img",{},"",article);assert.equal(detector.inspect(article,"balanced").hide,false);
  const heading=f.element("h2",{class:"ad-title"},"Sponsored");assert.equal(detector.inspect(heading,"balanced").hide,false);
});
test("controls, navigation, login dialog, editor and player ancestry protect normal content", () => {
  const f=fixture();
  for(const [tag,attrs] of [["nav",{}],["form",{}],["div",{role:"dialog"}],["div",{role:"navigation"}],["div",{contenteditable:"plaintext-only"}]]){
    const region=f.element(tag,attrs),ad=f.ad(region);assert.equal(detector.inspect(ad,"balanced").hide,false,tag+JSON.stringify(attrs));
  }
  for(const tag of ["nav","main","article","form","button","video","audio"]){const ad=f.ad();f.element(tag,{},"",ad);assert.equal(detector.inspect(ad,"balanced").hide,false,tag);}
  const host=f.element("div",{role:"dialog"}),shadow=host.attachShadow(),ad=f.ad(shadow);assert.equal(detector.inspect(ad,"balanced").hide,false);
});
test("disabled advertising markers do not add evidence; label and geometry alone are insufficient", () => {
  const f=fixture();
  for(const name of ["data-ad", "data-sponsored", "data-advertisement", "data-ad-slot", "data-ad-unit", "data-ad-placement"]){
    for(const disabled of ["false","OFF","disabled","none","0"]){const node=f.element("div",{[name]:disabled});f.element("img",{},"",node);assert.equal(detector.features(node).strongMarker,false,name+"="+disabled);assert.equal(detector.inspect(node,"balanced").hide,false);}
  }
  const label=f.element("div",{"aria-label":"Advertisement"});assert.equal(detector.inspect(label,"balanced").hide,false);
});
