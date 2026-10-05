# NullAD Local / 本地浏览器增强

Chrome / Edge Manifest V3 扩展，独立于 NullAD 桌面应用运行。提供两层无需订阅维护的补充：浏览器 DNR 阻断明确广告资源特征；本地 DOM 多信号识别并可逆隐藏广告容器。算法仍有内部识别条件，不是没有规则的万能识别。所有条件随代码打包，不下载规则、模型，不训练或上传网页内容。

## 安装与启用

1. 在 Chrome 的 `chrome://extensions` 或 Edge 的 `edge://extensions` 打开开发者模式，选择“加载已解压的扩展”，选择包含本文件和 `manifest.json` 的目录。需要 Chromium 119+。仅在你选择的浏览器/profile 中加载，不自动安装到其他个人浏览器。
2. 打开普通 HTTP/HTTPS 网页，点击工具栏的 NullAD Local。默认关闭且没有网页访问授权。
3. 选择“保守”或“平衡”，点击“仅本页启用”或“全部网页启用”。浏览器会请求可选 HTTP/HTTPS 访问权限；第三方广告资源也需要权限，因此两种启用方式均请求这些资源权限。本页按钮将范围切换为仅当前标签；同主机刷新保留，导航到不同主机时清除。全站模式跨浏览器重启保留。
4. 启用后刷新页面，重新检查此前已下载的脚本/资源。已加载的脚本不会被倒退撤销。

弹窗支持中文/英文、关闭、精确主机名站点允许、恢复本页隐藏内容；管理页可移除允许项。站点允许会停止本扩展对此站的 DOM 隐藏及请求阻断，并即时恢复已隐藏的内容；已经失败的资源需刷新才能重新请求。允许项不包含子域。例如允许 `example.com` 不会自动允许 `shop.example.com`。

“恢复本页隐藏内容”只撤销 DOM 隐藏：当前文档中恢复的元素不会立即再次被藏，网络阻断继续生效。“全部关闭并恢复”清空本扩展的动态/会话 DNR 规则，注销自动注入并向已注入的文档发送停止/恢复指令。不能恢复其他扩展或网络代理阻断的资源。

## 识别范围

请求层只有 `block` 和 `allow` / `allowAllRequests`，不重定向、不改头：

- 完整广告服务主机标签，配合第三方关系与资源类型限制。
- `ads.js`、`pagead.js`、`adsbygoogle.js` 等精确脚本文件名，配合 script 类型；不会以 `ad` 子串匹配 `adobe`、`admin`、`download`。
- 平衡模式增加广告路径与投放动作组合。主文档导航不会被这些阻断条件拦截。

DOM 使用短广告标识/ARIA、广告属性、独立容器结构、形状组合，保守阈值 8、平衡阈值 6；每类信号封顶，至少两类。空的非交互容器同时含多个明确完整广告 marker 也可以命中。评分是解释性启发式值，不是概率/准确率。导航、表单、主内容、长正文、播放器、超大容器有保护条件。单个 `ad` 类名、一个横幅尺寸、第三方 iframe 均不单独触发。

隐藏只添加本扩展标记，不删除节点或覆盖原样式；允许/关闭可恢复。MutationObserver 增量处理新增节点与有限属性，去抖、队列/每帧工作预算均有限；初始扫描以持续游标分帧完成，不永久丢弃树尾。单个候选最多检查 101 个元素与 401 字符，开放 Shadow DOM 最多同时观察 31 个（另外一个观察器用于主文档），断开的 root 释放观察器；闭合 Shadow DOM 不可读取。超大或高频变化页面、无标识广告、流内视频广告、浏览器内部页以及其他扩展干预都可能影响结果。DOM 隐藏不等于资源没有下载。

`https://adblock.turtlecute.org/` 是用户指定的外部验收站。运行代码不含该站专用条件、站点 ID、测试结果改写或 128 域名名单。其脚本诱饵可被通用路径条件自然识别；其结果必须由真实浏览器记录，不能用 Node 正则测试替代网络请求验收，更不能把页面隐藏计为请求阻断。

## 与代理软件共存

扩展不使用 `chrome.proxy`、原生消息或桌面 IPC，不写代理/DNS/证书配置，不需要占用本地端口。HTTP、SOCKS、PAC、VPN/TUN 的路由配置继续由原软件管理；浏览器在现有网络栈请求前应用 DNR。这个结构减少配置冲突，但不代表所有软件版本已经实测，也不保证代理或其他扩展对请求的改写不会改变识别结果。HTTP/SOCKS 共存、系统代理基线和外部站结果应分别报告。

## 数据与权限

必需权限：`storage`、`scripting`、`activeTab`、`declarativeNetRequestWithHostAccess`。HTTP/HTTPS host 权限可选，只在启用按钮的用户操作中请求。没有网络订阅、分析上传、`fetch`/XHR、远程代码、证书或代理 API。配置存在 `storage.local`，当前标签范围/数量/有限理由存在 `storage.session`，不保存浏览历史、完整页面文本或请求日志。后台 worker 可休眠，observer 留在页面 content script。

DOM 隐藏数量在打开弹窗时读取当前 allFrames 控制器快照，不使用已移除 iframe 或过期文档的缓存来显示数量，不伪造请求拦截次数；读取失败时显示“无法确认”。启动、保存、权限或 API 失败会返回错误；页面不能注入或停止后无法确认恢复时显示警告，不能把网络规则成功当作 DOM 已成功运行。

## 开发与验收

仓库根目录：`node --test extension/tests/*.test.cjs`，无生产 npm 依赖。Node 覆盖条件正负样例、作用域、允许优先、权限拒绝、API/保存失败、规则清理、撤销、SPA 复用和 observer 停止。`tests/fixtures.html` 为仅用于验收的离线 DOM 正负样例页面。真实 Edge/Chrome 需要另外加载扩展、检查 DNR 实际请求是否到达本地测试源站，并在允许/关闭后确认恢复。

消息契约（扩展页发送 `chrome.runtime.sendMessage`，响应 `{ok:true,...}` / `{ok:false,error}`）：

| type | 参数 | 行为 |
| --- | --- | --- |
| STATE | tabId（可选） | 当前配置、授权、页模式、实际隐藏数、启动错误 |
| ENABLE | scope:page/all, mode:conservative/balanced, tabId | 在用户权限授权后启用 |
| STOP | 无 | 全部停止并恢复 |
| ALLOW_SITE | tabId, allowed:boolean | 精确当前主机允许/移除 |
| REMOVE_SITE | host | 管理页移除允许项 |
| RESTORE | tabId | 当前文档 DOM 恢复、网络保持 |
| LANGUAGE | language:zh-CN/en | 持久化语言 |

Content sender 仅能 `GET_CONFIG` 和 `REPORT`，不能改变策略。API 依据：[Content scripts](https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts)、[DNR](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest)、[scripting](https://developer.chrome.com/docs/extensions/reference/api/scripting)、[permissions](https://developer.chrome.com/docs/extensions/reference/api/permissions)、[worker lifecycle](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle)、[Edge API support](https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/api-support)。

---

English: This independent MV3 extension uses bundled URL/resource semantics and reversible multi-signal DOM cleanup. No subscription, remote model, training, upload, certificate, DNS or proxy configuration changes. It starts off without host access. The toolbar popup explicitly requests HTTP/HTTPS resource permissions and selects this-tab or all-sites protection. Allowances match exact hostnames; restored elements remain exempt in the current document. Stop removes all extension DNR rules and restores page effects. Existing failed requests require a reload. Node tests verify local logic only; real requests, external-site results and proxy coexistence require separate browser acceptance. Coverage is limited and no universal ad-blocking or every-proxy-version guarantee is made.
