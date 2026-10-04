/* Bundled translations: works offline and does not require a frontend build. */
(function (root) {
  "use strict";
  const text = {
    overview:["概览","Overview"], rules:["规则","Rules"], settings:["设置","Settings"], logs:["日志","Logs"],
    navigation:["主导航","Main navigation"], language:["语言","Language"], theme:["主题","Theme"], light:["浅色","Light"], dark:["深色","Dark"],
    overviewSubtitle:["查看防护状态与最近的拦截记录。","View protection status and recent filtering activity."],
    rulesSubtitle:["管理规则列表，并检查规则命中情况。","Manage filter lists and inspect rule matches."],
    settingsSubtitle:["管理监听服务与系统集成。","Manage listeners and system integration."],
    logsSubtitle:["查看最近的请求与规则匹配结果。","View recent requests and matching rules."],
    connecting:["正在连接后端","Connecting to backend"], waitingStatus:["等待防护状态。","Waiting for protection status."],
    waitingBackend:["等待后端连接。","Waiting for the backend."],
    backendUnavailable:["后端未连接","Backend unavailable"],
    backendNotice:["此页面未连接 NullAD 桌面后端，无法读取或改变防护状态。","This page is not connected to the NullAD desktop backend. Protection state cannot be read or changed."],
    connectionFailed:["无法获取最新状态，以下为上次收到的数据。{error}","Could not refresh status. Showing the last received data. {error}"],
    eventsFailed:["状态推送暂不可用，已使用自动刷新。{error}","Status events are unavailable. Automatic refresh is active. {error}"],
    startProtection:["启动防护","Start protection"], stopProtection:["暂停防护","Pause protection"], protectionStarted:["防护已启动。","Protection started."], protectionStopped:["防护已停止。","Protection stopped."], systemProxyKind:["系统代理","System proxy"], dnsResolverKind:["DNS 解析器","DNS resolver"],
    state_stopped:["防护已停止","Protection stopped"], state_starting:["正在启动防护","Starting protection"], state_running:["防护运行中","Protection running"], state_degraded:["防护部分可用","Protection degraded"], state_failed:["防护启动失败","Protection failed"], state_stopping:["正在停止防护","Stopping protection"],
    stoppedHint:["启动防护后，将监听本机请求。","Start protection to listen for local requests."],
    proxyListening:["HTTP 代理正在监听","HTTP proxy is listening"], proxyNotListening:["HTTP 代理未监听","HTTP proxy is not listening"],
    dnsListening:["DNS 正在监听 {address}。","DNS is listening on {address}."], dnsNotListening:["DNS 未监听。","DNS is not listening."],
    httpProxy:["HTTP 代理","HTTP proxy"], systemProxy:["系统代理","System proxy"], proxyManaged:["已接管","Managed"], proxyUnmanaged:["未接管","Not managed"], notListening:["未监听","Not listening"],
    loadedRules:["已载入规则","Rules loaded"], processedRequests:["已处理请求","Requests processed"], blockedRequests:["已拦截请求","Requests blocked"], blockRatio:["拦截比例","Block ratio"],
    recentRequests:["最近请求","Recent requests"], recentLimit:["最近 500 条记录。","Latest 500 records."], viewAll:["查看全部","View all"], manageRules:["管理规则","Manage rules"], enabledLists:["已启用 {count} 个规则列表","{count} filter lists enabled"],
    time:["时间","Time"], domainUrl:["域名 / URL","Domain / URL"], domain:["域名","Domain"], decision:["决策","Decision"], matchedRule:["命中规则","Matched rule"], noMatchedRule:["未命中规则","No matching rule"], blocked:["已拦截","Blocked"], allowed:["已放行","Allowed"],
    noRequests:["当前还没有请求","No requests yet"], noRequestsHint:["将客户端代理设置为 {address} 后，请求将显示在这里。","Set the client proxy to {address} to see requests here."],
    noRequestsStopped:["启动防护并将客户端流量指向本机监听器后，请求将显示在这里。","Start protection and route client traffic to the local listener to see requests here."],
    noLogs:["当前没有日志","No logs yet"], noLogsHint:["启动防护并产生请求后，记录会显示在这里。","Start protection and send requests to see records here."],
    noFilterLogs:["此筛选下没有记录","No records for this filter"], noFilterLogsHint:["选择“全部”查看其他请求。","Choose All to view other requests."],
    filterLists:["规则列表","Filter lists"], reload:["重新载入","Reload"], enabled:["启用","Enable"], name:["名称","Name"], source:["来源","Source"], ruleCount:["规则数","Rules"], quarantined:["隔离","Quarantined"], cosmetic:["装饰规则","Cosmetic"],
    cosmeticHint:["装饰规则只解析，不执行元素隐藏。","Cosmetic rules are parsed; element hiding is not applied."], noLists:["没有配置规则列表。","No filter lists configured."],
    customRules:["自定义规则","Custom rules"], customPlaceholder:["! 在此添加自定义规则\n||ads.example.com^","! Add custom rules here\n||ads.example.com^"], customHint:["支持 ABP 与 hosts 语法。","Supports ABP and hosts syntax."], applyRules:["应用规则","Apply rules"], customUnsaved:["规则已修改，尚未应用。","Rules changed; not applied yet."],
    reloadResult:["已载入 {rules} 条规则，用时 {ms} ms。隔离 {failures} 条。","Loaded {rules} rules in {ms} ms. {failures} quarantined."],
    urlCheck:["URL 检查","Check a URL"], requestUrl:["检查的 URL","Request URL"], pageUrl:["页面地址（可选）","Page URL (optional)"], resourceType:["资源类型","Resource type"], check:["检查","Check"], checkEmpty:["输入 URL 查看拦截结果与命中规则。","Enter a URL to view the decision and matching rule."],
    checkSummary:["匹配 {count} 条规则，域名 {host}。","{count} rules matched; host {host}."], invalidUrl:["请输入有效的 HTTP 或 HTTPS 地址。","Enter a valid HTTP or HTTPS URL."],
    parsedRules:["已解析规则","Parsed rules"], parsedHint:["查看当前生效的规则，最多显示 120 条。","View active rules. Up to 120 are shown."], shownRules:["显示 {count} 条","{count} shown"], noRules:["尚未载入规则。","No rules loaded."],
    listeners:["监听服务","Listeners"], listenersSubtitle:["配置本机的监听服务。","Configure local listeners."], proxyHint:["用于拦截 HTTP 请求。","Filters HTTP requests."], dnsHint:["用于拦截 DNS 请求。","Filters DNS requests."], listenPort:["监听端口","Listen port"], loopbackOnly:["仅监听本机地址。","Listens on loopback only."], upstreamDns:["上游 DNS 服务器","Upstream DNS server"], nxdomain:["被拦截域名返回 NXDOMAIN","Return NXDOMAIN for blocked domains"],
    settingsRestartHint:["修改监听设置后，需要重新启动防护才能生效。","Listener changes take effect after restarting protection."], restartRequired:["设置已保存，重新启动防护后生效。","Settings saved. Restart protection to apply them."],
    cancelChanges:["取消修改","Cancel changes"], saveSettings:["保存设置","Save settings"], settingsSaved:["设置已保存。","Settings saved."], settingsUnsaved:["设置已修改，尚未保存。","Settings changed; not saved yet."],
    invalidPort:["监听端口必须是 1–65535 之间的整数。","Listen ports must be integers from 1 to 65535."], invalidUpstream:["请输入上游 DNS 服务器。","Enter an upstream DNS server."], proxyRequired:["接管系统代理前，请先启用 HTTP 代理。","Enable the HTTP proxy before managing the system proxy."], samePorts:["HTTP 与 DNS 必须使用不同端口。","HTTP and DNS must use different ports."],
    systemIntegration:["系统集成","System integration"], systemIntegrationSubtitle:["管理与操作系统的集成。","Manage integration with the operating system."], takeOverProxy:["接管系统代理","Manage system proxy"], takeOverHint:["将系统代理设置为指向 NullAD。","Route the system proxy through NullAD."], integrationHint:["启动防护后，将系统代理指向 NullAD；停止时恢复原设置。","When protection starts, route the system proxy through NullAD. Restore the previous settings when it stops."],
    noPending:["当前没有待恢复的系统变更。","No system changes await restoration."], pendingChanges:["有 {count} 项系统变更待恢复。","{count} system changes await restoration."], restoreSettings:["恢复系统设置","Restore system settings"], restoreSuccess:["已恢复系统设置。","System settings restored."], restorePartial:["仍有 {count} 项变更未恢复，请查看详情并重试。","{count} changes remain unrestored. Review the details and retry."], restored:["已恢复","Restored"], restoreFailed:["恢复失败","Restoration failed"],
    diagnostics:["诊断","Diagnostics"], diagnosticsSubtitle:["运行性能测试以检查当前配置的效果。","Measure performance with the currently loaded rules."], runBenchmark:["运行性能测试","Run benchmark"], benchNotRun:["未运行性能测试","No benchmark yet"], measuring:["正在测量…","Measuring…"],
    benchSummary:["{throughput} 次/秒 · p50 {p50} µs · p99 {p99} µs","{throughput} lookups/sec · p50 {p50} µs · p99 {p99} µs"], benchDetail:["{iterations} 次查找 · {rules} 条规则 · 平均 {mean} µs","{iterations} lookups · {rules} rules · mean {mean} µs"],
    dataDirectory:["数据目录","Data directory"], configDirectory:["配置目录","Config directory"], copyData:["复制数据目录","Copy data directory"], copyConfig:["复制配置目录","Copy config directory"], copied:["目录已复制。","Directory copied."], copyFailed:["无法自动复制，已选中路径，请手动复制。","Could not copy automatically. Path selected; copy it manually."],
    platformSummary:["{platform} · {privileges} · 已载入 {rules} 条规则","{platform} · {privileges} · {rules} rules loaded"], elevated:["管理员权限","Administrator"], ordinary:["普通权限","Standard privileges"],
    advancedDiagnostics:["详细诊断","Advanced diagnostics"], interceptors:["拦截器","Interceptors"], blockedSeen:["拦截 / 处理","Blocked / seen"], dnsFailures:["DNS 失败","DNS failures"], ruleSet:["规则集","Rule set"], domainAnchors:["域名锚点","Domain anchors"], domainPath:["域名与路径","Domain and path"], fragments:["子串与通配","Substrings / wildcards"], regexRules:["正则","Regex"], trieNodes:["前缀树节点","Trie nodes"], automatonFragments:["自动机片段","Automaton fragments"], engine:["引擎","Engine"], exceptions:["命中例外","Exception matches"], administrator:["管理员权限","Administrator"], yes:["是","Yes"], no:["否","No"],
    filterLimitations:["HTTPS 按主机名过滤；不解密 TLS，也不执行元素隐藏。加密 ClientHello 可能使 SNI 过滤失效。","HTTPS is filtered by hostname. TLS is not decrypted and element hiding is not applied. Encrypted ClientHello can prevent SNI filtering."],
    show:["显示","Show"], all:["全部","All"], logFilter:["日志筛选","Log filter"], clearLogs:["清空日志","Clear logs"], autoRefresh:["列表自动刷新。","Refreshes automatically."], logCount:["{count} 条记录","{count} records"], logRetention:["日志仅保留在本次运行内，较早的记录会自动移除。","Logs are kept for this session. Older records are removed automatically."], logsCleared:["日志已清空。","Logs cleared."],
    saving:["正在保存…","Saving…"], working:["正在处理…","Working…"]
  };
  let language = "zh-CN";
  try { if (root.localStorage.getItem("nullad.language") === "en") language = "en"; } catch (_) {}
  function t(key, values) {
    const entry = text[key];
    const template = entry ? entry[language === "en" ? 1 : 0] : key;
    return template.replace(/\{(\w+)\}/g, (_, name) => String(values && values[name] != null ? values[name] : ""));
  }
  function apply(next) {
    language = next === "en" ? "en" : "zh-CN";
    root.document.documentElement.lang = language;
    try { root.localStorage.setItem("nullad.language", language); } catch (_) {}
    root.document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
    root.document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => { el.placeholder = t(el.dataset.i18nPlaceholder); });
    root.document.querySelectorAll("[data-i18n-aria]").forEach((el) => { el.setAttribute("aria-label", t(el.dataset.i18nAria)); });
    root.document.querySelectorAll("[data-i18n-title]").forEach((el) => { el.title = t(el.dataset.i18nTitle); });
    root.document.querySelectorAll(".nav-item").forEach((el) => { el.setAttribute("aria-label", t(el.dataset.view === "dashboard" ? "overview" : el.dataset.view)); });
    root.document.getElementById("language-select").value = language;
  }
  root.NullAD = root.NullAD || {};
  root.NullAD.i18n = { t, apply, get language() { return language; }, text };
})(window);
