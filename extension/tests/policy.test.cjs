"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path");
const policy = require("../policy.js");
function matches(rule, url, type, thirdParty = false) { return rule.condition.resourceTypes.includes(type) && (!rule.condition.domainType || thirdParty) && new RegExp(rule.condition.regexFilter, "i").test(url); }
function blocked(url, type = "script", mode = "conservative", thirdParty = false) { return policy.blockRules(mode).some((rule) => matches(rule, url, type, thirdParty)); }
test("bundled network conditions block advertising scripts with filename boundaries", () => {
  for (const url of ["https://example.com/ads.js", "https://example.com/js/widget/ads.js", "https://example.com/js/pagead.js?v=2", "https://cdn.example/ads/adsbygoogle.min.js"]) assert.equal(blocked(url), true, url);
});
test("normal URLs, resource types and query parameter lookalikes are not blocked", () => {
  for (const url of ["https://adobe.example/app.js", "https://example.com/admin.js", "https://example.com/download.js", "https://example.com/header-adapter.js", "https://example.com/myads.js", "https://example.com/ads.js.map", "https://example.com/docs/ads.js.html", "https://example.com/script.js?next=/ads.js", "https://ads.example.com/app.js"]) assert.equal(blocked(url), false, url);
  assert.equal(blocked("https://example.com/ads.js", "main_frame"), false);
  assert.equal(blocked("https://example.com/ads.js", "stylesheet"), false);
});
test("ad hostname labels require an exact label, third party and constrained type", () => {
  assert.equal(blocked("https://ads.example.com/api", "xmlhttprequest", "conservative", true), true);
  assert.equal(blocked("https://badads.example.com/api", "xmlhttprequest", "conservative", true), false);
  assert.equal(blocked("https://ads.example.com/api", "main_frame", "conservative", true), false);
  assert.equal(blocked("https://example.com/path?next=https://ads.other.com/a.js", "script", "conservative", true), false);
});
test("balanced adds path and action combinations rather than an ad substring", () => {
  const url = "https://example.com/adserver/serve?slot=1";
  assert.equal(blocked(url, "xmlhttprequest", "conservative"), false);
  assert.equal(blocked(url, "xmlhttprequest", "balanced"), true);
  assert.equal(blocked("https://example.com/ads/readme.txt", "xmlhttprequest", "balanced"), false);
  assert.equal(blocked(url, "script", "off"), false);
});
test("site allowances are exact-host high-priority main-frame allowAllRequests", () => {
  const rule = policy.allowRules(["example.com"])[0];
  assert.equal(matches(rule, "https://example.com:8443/a", "main_frame"), true);
  assert.equal(matches(rule, "https://sub.example.com/a", "main_frame"), false);
  assert.equal(matches(rule, "https://example.company/a", "main_frame"), false);
  assert.equal(rule.action.type, "allowAllRequests");
  assert.ok(rule.priority > policy.blockRules("balanced")[0].priority);
});
test("tab scope and immediate allowed-tab rules are isolated and higher priority", () => {
  const settings = policy.normalizeSettings({ mode:"off", allowSites:["allowed.example"] });
  const result = policy.sessionRules(settings, { 3:{ host:"news.example", mode:"balanced" } }, [{id:3,url:"https://news.example"},{id:4,url:"https://allowed.example"},{id:5,url:"https://sub.allowed.example"}]);
  assert.ok(result.rules.filter((rule) => rule.action.type === "block").every((rule) => rule.condition.tabIds[0] === 3));
  assert.deepEqual(result.activeTabs,[3]);
  assert.equal(result.rules.find((rule) => rule.action.type === "allow" && rule.priority === 1000).condition.tabIds[0],4);
  assert.equal(policy.sessionRules(settings, {}, []).rules.length,0);
});
test("settings normalize bad modes and store exact valid hostnames without duplicates", () => {
  assert.deepEqual(policy.normalizeSettings({mode:"unsafe",allowSites:["example.com","example.com","*.example.com","example.com:443","a/b","[::1]"],language:"unknown"}), {mode:"off",preferredMode:"conservative",rulesEnabled:true,heuristicsEnabled:true,allowSites:["example.com","[::1]"],language:"zh-CN"});
});
function decision(url, type, settings, thirdParty = false) {
  const host = new URL(url).hostname;
  const matching = policy.networkRules("balanced", settings).filter(rule => rule.condition.resourceTypes.includes(type) && (rule.condition.requestDomains ? rule.condition.requestDomains.some(domain => host === domain || host.endsWith("." + domain)) : matches(rule, url, type, thirdParty)));
  return matching.sort((a,b) => b.priority - a.priority)[0]?.action.type || "allow";
}
test("independent rule and heuristic layers cooperate and protect documentation", () => {
  const rules = policy.normalizeSettings({rulesEnabled:true,heuristicsEnabled:false});
  const heuristic = policy.normalizeSettings({rulesEnabled:false,heuristicsEnabled:true});
  const both = policy.normalizeSettings({});
  for (const settings of [rules, both]) assert.equal(decision("https://doubleclick.com/arbitrary.bin", "image", settings), "block");
  assert.equal(decision("https://doubleclick.com/arbitrary.bin", "image", heuristic), "allow");
  for (const settings of [heuristic, both]) assert.equal(decision("https://clean.example/js/prebid.min.js", "script", settings, true), "block");
  assert.equal(decision("https://clean.example/js/prebid.min.js", "script", rules, true), "allow");
  for (const url of ["https://clean.example/docs/ads.js", "https://clean.example/login/prebid.js", "https://clean.example/oauth/ads/serve"]) assert.equal(decision(url,"script",both,true),"allow");
  assert.equal(decision("https://doubleclick.com/docs/example.js","script",both,true),"block");
  assert.equal(decision("https://clean.example/gpt.js","script",heuristic,true),"allow");
  assert.equal(decision("https://clean.example/tag/js/gpt.js","script",heuristic,true),"block");
  assert.equal(decision("https://clean.example/tag/js/gpt.js","script",heuristic,false),"allow");
  assert.equal(decision("https://clean.example/prebid.js","main_frame",both,true),"allow");
});
test("bundled domains are partitioned without regex expansion or discarded entries", () => {
  const bundled = require("../domain-rules.js"), rules = policy.domainRules(42);
  assert.deepEqual(rules.flatMap(rule=>rule.condition.requestDomains),bundled.domains);
  assert.ok(rules.length < 100 && rules.every(rule=>rule.condition.requestDomains.length <= 512 && rule.condition.tabIds[0] === 42 && !rule.condition.regexFilter));
  assert.equal(new Set(bundled.domains).size,bundled.metadata.domain_count);
  assert.ok(!bundled.domains.includes("graph.facebook.com"));
  assert.ok(!bundled.domains.includes("device-provisioning.googleapis.com"));
});
test("manifest uses optional hosts, local CSP and no proxy/certificate/network-download permission", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname,"../manifest.json"),"utf8"));
  assert.equal(manifest.manifest_version,3);
  assert.deepEqual(manifest.optional_host_permissions,policy.origins);
  assert.equal(manifest.host_permissions,undefined);
  assert.equal(manifest.declarative_net_request,undefined);
  assert.ok(manifest.permissions.includes("declarativeNetRequestWithHostAccess"));
  assert.ok(!manifest.permissions.some((value) => /proxy|nativeMessaging|cookies|webRequest|debugger|unlimitedStorage/.test(value)));
  assert.ok(manifest.content_security_policy.extension_pages.includes("connect-src 'none'"));
  for (const filename of fs.readdirSync(path.join(__dirname,"..")).filter((file) => file.endsWith(".js"))) {
    const text = fs.readFileSync(path.join(__dirname,"..",filename),"utf8");
    assert.doesNotMatch(text,/\bfetch\s*\(|XMLHttpRequest|\beval\s*\(|chrome\.proxy/,filename);
  }
  assert.doesNotMatch(JSON.stringify(policy.definitions),/turtlecute|ct_static|cts_test|doubleclick|adnxs/);
});
