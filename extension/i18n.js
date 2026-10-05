(function (root) {
  "use strict";
  const text = {
    title:["NullAD 本地增强", "NullAD Local"], subtitle:["规则与免规则识别，可独立或一起使用", "Domain rules and heuristics, independently or together"],
    rulesLayer:["内置广告与跟踪域名规则", "Bundled ad and tracker domain rules"], heuristicsLayer:["免规则识别与页面清理", "Rule-free detection and page cleanup"],
    layerHint:["选择后点击启用才会应用；至少选择一层。识别模式只影响免规则层。", "Click Enable to apply the selection; choose at least one layer. Detection mode affects heuristics only."],
    chooseLayer:["请至少选择一层保护。", "Choose at least one protection layer."], ruleData:["内置 {count} 个域名；当前安装 {installed} 条网络条件（不是拦截次数）。", "{count} bundled domains; {installed} network conditions installed (not blocked-request counts)."],
    language:["语言", "Language"], mode:["识别模式", "Detection mode"], off:["关闭", "Off"], conservative:["保守", "Conservative"], balanced:["平衡", "Balanced"],
    statusOff:["当前网页未启用", "Off on this page"], statusOn:["当前网页已启用：{mode}", "Active on this page: {mode}"],
    noPermission:["尚未授权网页资源访问。", "Page-resource access has not been granted."], pagePermission:["已授权 HTTP/HTTPS 资源访问；保护范围仍由下方设置决定。", "HTTP/HTTPS resource access granted. Protection scope is controlled below."],
    enablePage:["仅本页启用", "Enable this tab only"], enableAll:["全部网页启用", "Enable all websites"], stop:["全部关闭并恢复", "Stop all and restore"],
    permissionHint:["启用需要浏览器授权读取网页及第三方资源。本页模式仅保护当前标签；同站刷新保留，换站清除。全部网页模式会持续启用。", "Activation requests access to pages and third-party resources. Tab mode protects this tab, survives same-host reloads and clears on a different host. All-sites mode persists."],
    allowSite:["允许此站点", "Allow this site"], resumeSite:["移除本站允许项", "Remove site allowance"], allowed:["本站已允许（精确主机名）", "This exact hostname is allowed"],
    restore:["恢复本页隐藏内容", "Restore hidden elements"], restoreHint:["恢复后本次页面不会再次隐藏这些元素；不会撤销已阻断的请求。需要重新加载资源时，请允许站点或关闭后刷新。", "Restored elements stay visible in this document. Blocked requests cannot be replayed; allow the site or stop protection, then reload."],
    hidden:["本页隐藏 {count} 个容器", "{count} containers hidden in this tab"], hiddenUnknown:["当前隐藏数量无法确认。", "Current hidden count could not be confirmed."], configured:["识别条件已应用。刷新页面可重新检查之前载入的资源。", "Conditions applied. Reload to recheck resources that had already loaded."],
    stopped:["已停止请求阻断并恢复页面。", "Request blocking stopped and page restored."], restored:["本页已恢复。", "Page restored."], saved:["设置已保存。", "Settings saved."], denied:["未获得网页资源权限，未启用。", "Resource access denied. Protection was not enabled."],
    unsupportedPage:["此页面不支持注入。请打开 HTTP/HTTPS 网页。", "This page cannot be injected. Open an HTTP/HTTPS page."], failed:["操作失败：{error}", "Operation failed: {error}"],
    boundaries:["规则数据与识别均在本地运行，不修改代理、DNS、证书或请求头。取消规则层可仅使用免规则识别。无法保证拦住所有广告；视频插播、无标识内容和浏览器内页存在限制。", "Bundled rules and heuristics run locally without proxy, DNS, certificate or header changes. Disable domain rules to use heuristics alone. Unlabelled ads, in-stream video and browser pages remain limited."],
    manage:["管理站点允许项", "Manage allowed sites"], empty:["没有站点允许项。", "No allowed sites."], remove:["移除", "Remove"], siteHint:["允许项只匹配完整主机名，不自动包含子域。移除允许项后，已启用的全站保护会重新作用于该站点。", "Allowances match exact hostnames, not subdomains. Removing one restores globally enabled protection on that host."],
    back:["在浏览器工具栏打开弹窗以启用保护。", "Use the toolbar popup to enable protection."], loading:["正在读取状态…", "Loading state…"], session:["保护状态在扩展中独立管理，与 NullAD 桌面防护开关分开。", "Extension protection is independent of the NullAD desktop switch."]
  };
  let language = "zh-CN";
  function t(key, values = {}) { const value = text[key] || [key, key]; return value[language === "en" ? 1 : 0].replace(/\{(\w+)\}/g, (_, name) => values[name] == null ? "" : String(values[name])); }
  function apply(next) {
    language = next === "en" ? "en" : "zh-CN";
    document.documentElement.lang = language;
    document.querySelectorAll("[data-i18n]").forEach((element) => element.textContent = t(element.dataset.i18n));
    document.getElementById("language").value = language;
  }
  root.NullADText = { t, apply, text, get language() { return language; } };
})(globalThis);
