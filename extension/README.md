# NullAD Local 0.2.0 / 本地浏览器增强

Chrome / Edge Manifest V3 扩展，独立于 NullAD 桌面应用运行。提供两个可单独或
共同启用的层级：内置广告/跟踪域名规则，以及免规则请求识别和可恢复 DOM 清理。
运行时不下载规则、模型或远程代码，不训练或上传网页内容，不接管已有代理。

## 安装与选择组合

1. 解压 `nullad-browser-extension.zip`。在 Chrome 的 `chrome://extensions` 或
   Edge 的 `edge://extensions` 打开开发者模式，选择“加载已解压的扩展”，指向
   含 `manifest.json` 的目录。需要 Chromium 119+；仅加载到所选浏览器/profile。
2. 打开 HTTP/HTTPS 网页，点击工具栏 NullAD Local。首次安装两个层级偏好均
   勾选，但防护为 **Off**，尚未授权访问网页。
3. 选择“内置规则”和/或“免规则识别”，再点击“仅本页启用”或“全部网页启用”。
   点击按钮才会应用复选框选择，并请求可选 HTTP/HTTPS 资源权限；广告资源也
   需要这些权限。本页按钮将范围切到当前标签，同主机刷新保留，导航到不同
   主机或浏览器关闭后清除；全站模式跨浏览器重启保留。
4. 启用后刷新页面，让此前已经请求的资源重新经过过滤。已加载脚本不能倒退撤销。

| 内置规则 | 免规则识别 | 启用后的行为 |
|---|---|---|
| 勾选 | 不勾选 | 仅域名 DNR 过滤，不运行 DOM 清理 |
| 不勾选 | 勾选 | 仅通用请求条件与可恢复 DOM 识别 |
| 勾选 | 勾选 | 两层共同使用 |

启用至少选择一层；单独改复选框不会即时发布。保守/平衡只影响识别层的请求
条件和 DOM 阈值，不改变域名数据。选择 Off 停止两层。

## 允许与恢复

弹窗支持中文/英文、精确主机名允许和本页恢复；管理页可移除允许项。
允许站点停止本扩展对此站的请求阻断与 DOM 隐藏，并即时恢复已隐藏内容。
允许项不包括子域，例如允许 `example.com` 不会自动允许 `shop.example.com`。
全站启用或换层保留所有允许项；显式“仅本页启用”会移除当前主机允许项并恢复
该页防护。也可以点击“移除本站允许项”或在管理页移除允许项。

“恢复本页隐藏内容”只撤销 DOM 隐藏；恢复的元素在当前文档中保持豁免，网络
过滤继续生效。已失败的请求需要刷新。“全部关闭并恢复”清空本扩展的动态/
会话 DNR 规则，注销自动注入并向当前文档发送停止/恢复指令；恢复无法确认时
会显示警告，重新加载页面可移除旧文档的效果。不能恢复其他拦截软件的阻断。

## 内置规则来源

规则层包含 **44,442 个域名**，由官方 EasyList/EasyPrivacy 固定提交
`129e63db3096f78e6dc94ac7ca6a15e27b5d1b79`（2026-10-05）生成，和原生
`nullad-hosts.txt` 使用相同快照。EasyList 侧重广告；EasyPrivacy 还覆盖跟踪、
分析和遥测，遥测不等同于广告。该层分成 **87 个 DNR `requestDomains` 组**，
每组至多 512 个域名，使用标签边界匹配并包含子域，不拼成巨大域名正则。

只抽取无选项的完整 ASCII 域名锚点；不将 `$third-party`、资源类型或页面条件
丢弃后扩大为整站阻断。受字面主机例外影响的阻断域名及其相关父/子域被排除，
泛化/正则例外不能全部表示；这是域名子集，不是完整 ABP 列表执行。
独立原有本地域名也纳入生成输入，正常业务端点的排除不以测试站成绩为依据。

派生 `domain-rules.js` 数据单独采用 **CC BY-SA 3.0**，应用代码保持 **MIT**。
重新分发本扩展时保留 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)、数据许可
和修改归因。官方许可见 [EasyList](https://easylist.to/pages/licence.html)；
可复现来源、哈希与更新流程见
[源仓库规则数据说明](https://github.com/ZoeHao2026/NullAD/blob/codex/nullad-windows-optimization/rules/README.md)。

## 免规则请求识别

DNR 使用 `block`、`allow`、`allowAllRequests`，不重定向、不改请求头：

- 完整广告服务主机标签配合第三方关系和资源类型。
- 精确广告脚本名，如 `ads.js`、`pagead.js`、`adsbygoogle.js`；不会按 `ad`
  子串匹配 `adobe`、`admin`、`download`。
- 第三方 SDK 文件 `prebid.js`、`adsbygoogle.js` 及
  `/tag/js/gpt.js`、`/js/sdkloader/ima3.js` 加载路径。
- 平衡模式增加广告命名空间与投放/竞价动作组合。这组条件已拆成 18 个小正则，
  以满足真实 Chromium RE2 API 的内存预算。

主文档导航不会被这些阻断条件拦截。文档、教程、登录、支付等路径的语义保护
优先于启发式猜测；显式域名规则更高，站点允许优先于两层。本扩展的允许不能
否决其他扩展或网络代理的阻断。

## DOM 识别与边界

DOM 使用短广告/赞助标识、ARIA、广告属性、独立容器结构和形状组合。
标签涵盖简繁中文、英文、日文、韩文及部分欧洲、中东语言；这不是通用翻译或
所有语言识别。支持 `aria-label`、`aria-description`、`title`，以及至多三个
`aria-labelledby` 短叶文本引用。保守阈值 8、平衡阈值 6，至少两类信号；
评分表示特征强度，不是广告概率或准确率。

广告容器会连同短标签识别，并保护导航、表单、主内容、长正文、播放器和含
无关内容的混合容器。单独 `ad` 类名、一个横幅尺寸或第三方 iframe 不足以隐藏。
空的非交互容器同时含多个明确广告标记也可命中。

隐藏只增加本扩展标记，不删除节点或覆盖原始样式。已隐藏的 SPA 节点被复用成
正常内容时，会在原可见状态下重新测量并恢复。局部文本/属性变更会复检附近
至多 **4 层已隐藏祖先**；候选初扫沿父链检查至多 4 个层级。没有外部 ARIA
引用的反向索引：外部标签内容变动后，不能保证立即找到所有引用容器，必要时
刷新重新识别。

MutationObserver 增量扫描有去抖、队列与每帧预算，初扫用持续游标处理树尾。
单候选读取正文至 401 字符并限制节点遍历；开放 Shadow DOM 最多同时观察 31
个 root（另一个观察器用于主文档），断开的 root 会释放观察器。封闭 Shadow
DOM、无标识广告、流内视频、超大或高频变更页面、浏览器内部页仍有覆盖边界。
DOM 隐藏不能证明资源没有下载。

## 与代理软件共存及权限

扩展不使用 `chrome.proxy`、原生消息或桌面 IPC，不写代理/DNS/证书，不占用
本地端口。已有 HTTP/SOCKS/PAC/VPN/TUN 软件负责路由，浏览器 DNR 在其网络栈
请求前应用过滤；不能据此推断所有软件版本均已兼容或验收。

必需权限为 `storage`、`scripting`、`activeTab`、
`declarativeNetRequestWithHostAccess`；HTTP/HTTPS host 权限可选，只在启用点击
中请求。没有分析上传、`fetch`/XHR 或远程代码。配置存于 `storage.local`，
当前标签范围、数量和有限理由存于 `storage.session`；不保存浏览历史、完整
页面文本或请求日志。后台 worker 可休眠，observer 留在页面 content script。

弹窗隐藏数量来自当前 allFrames 控制器快照，不拿已移除 iframe 或过期文档
缓存显示计数；读取失败时显示无法确认。请求规则安装和页面清理分别报告，
不能把网络安装成功当作 DOM 已成功运行。

## 开发与本轮验收

仓库根目录执行 `node --test extension/tests/*.test.cjs`。测试覆盖正负样例、
两层组合、允许优先、权限/API/保存失败、撤销、SPA 复用与 observer 停止。
`tests/fixtures.html` 是离线 DOM 验收页面；真实请求还需浏览器记录源站到达
或 client-blocked 错误，Node 正则测试不能替代浏览器验收。

本轮 Edge 目标站：**Off 16/132 → 仅识别 30 → 仅规则 21 → 共同使用 33
→ Off 16**。组合运行记录 15 个 client-blocked 请求，两个脚本/两个元素检查
通过。总分含独立故障与遥测项，不能视为本扩展独立贡献或完整广告覆盖。
无测试站专用条件、站点 ID 或抄取的 128 域名名单。详见
[增强验收](https://github.com/ZoeHao2026/NullAD/blob/codex/nullad-windows-optimization/docs/enhanced-validation.md)；
旧 232 规则/60 分及早期零列表结果保留在
[上一轮记录](https://github.com/ZoeHao2026/NullAD/blob/codex/nullad-windows-optimization/docs/heuristic-validation.md)，
不替代本轮验证。跨目录源文档使用仓库链接，独立 ZIP 保留本地许可通知。

消息响应为 `{ok:true,...}` / `{ok:false,error}`：

| type | 参数 | 行为 |
|---|---|---|
| STATE | tabId（可选） | 配置、授权、页模式、当前隐藏数、错误 |
| ENABLE | scope:page/all, mode:conservative/balanced, tabId, rulesEnabled, heuristicsEnabled | 应用两层选择；全站保留允许，本页恢复当前站防护 |
| STOP | 无 | 全部停止并恢复 |
| ALLOW_SITE | tabId, allowed:boolean | 精确当前主机允许/移除 |
| REMOVE_SITE | host | 管理页移除允许项 |
| RESTORE | tabId | 恢复当前 DOM，网络继续 |
| LANGUAGE | language:zh-CN/en | 持久化语言 |

Content sender 仅能 `GET_CONFIG`、`REPORT`，不能修改策略。官方 API：
[Content scripts](https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts)、
[DNR](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest)、
[scripting](https://developer.chrome.com/docs/extensions/reference/api/scripting)、
[permissions](https://developer.chrome.com/docs/extensions/reference/api/permissions)、
[worker lifecycle](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle)。

English: Extension 0.2.0 combines an independently licensed 44,442-domain
EasyList/EasyPrivacy snapshot with offline network and reversible DOM heuristics.
Both checkbox preferences start selected; activation starts Off. Click Enable to
apply rules only, heuristics only, or both. All-sites changes preserve allowances;
explicit this-page activation resumes its exact host. Modes affect heuristics,
not the 87 domain groups. No runtime downloads or proxy/DNS/certificate changes.
Short multilingual/ARIA labels and specific third-party SDK loaders improve
coverage; limited ancestor revisits and missing external-ARIA reverse lookup
remain documented boundaries. Stop/Allow undo this extension's own effects;
failed requests need reload. Independent code remains MIT and data CC BY-SA 3.0.
Browser totals are 16→30→21→33→16 /132; no universal blocking or proxy guarantee.
