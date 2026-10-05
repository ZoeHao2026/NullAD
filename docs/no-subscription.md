# 内置规则与免规则识别 / Bundled rules and local detection

NullAD 可使用内置域名规则、离线启发式识别，或两者共同使用。运行时均不需要
下载广告订阅；“仅识别”仍有随软件打包的语义条件，不代表无条件的万能识别。
原生网络层与浏览器扩展看见的信息不同，浏览器页面隐藏也不等于资源没有下载。

## 选择两层组合

桌面/CLI 默认启用两份内置列表与平衡识别。当前默认列表实际加载 **44,607 条**：
165 条 `nullad-base.txt` 规则，加 44,442 个 `nullad-hosts.txt` 域名条目。
后一份来自官方 EasyList/EasyPrivacy 固定提交
`129e63db3096f78e6dc94ac7ca6a15e27b5d1b79`（2026-10-05）。
它包含广告、跟踪和部分遥测，遥测不等同于广告；误判时可禁用列表或允许域名。
数据独立采用 CC BY-SA 3.0，应用代码保持 MIT，详见
[规则来源与许可](../rules/README.md)。

| 组合 | 桌面 | CLI `check` / `serve` |
|---|---|---|
| 仅规则 | 保持所选列表启用；启发式模式选关闭并保存 | `--heuristic off` |
| 仅识别 | 禁用全部列表；保存保守或平衡模式 | `--no-lists --heuristic balanced` |
| 共同使用 | 列表与识别模式均启用 | 默认配置，或 `--heuristic balanced` |
| 两层关闭 | 禁用全部列表且保存关闭模式 | `--no-lists --heuristic off` |

桌面列表关闭后仍会显示，可再次启用；缓存规则数只对应相同 ID 与来源，
禁用列表不参与匹配。识别模式/允许域名须显式保存，持久化成功后才发布到正在
使用的策略；不需要重启监听器。保存上游或监听配置后需要重启防护。
CLI 默认从 `./lists`、随后从可执行文件旁查找列表；重复 `--list <PATH>` 可选择
具体列表，不能与 `--no-lists` 混用。CLI 参数不替代桌面持久化配置。

```powershell
# 仅规则：使用默认内置列表，关闭启发式。
nullad-cli.exe check https://doubleclick.com/resource.js --heuristic off --type script

# 仅识别：不加载任何列表；明确提供脚本类型与发起页面。
nullad-cli.exe check https://clean.example/prebid.js --no-lists --heuristic balanced --type script --page https://publisher.example/

# 共同使用：默认内置列表与平衡识别。
nullad-cli.exe serve --heuristic balanced --port 8080

# 允许一个域名及其子域，使用严格标签边界。
nullad-cli.exe serve --allow-host vendor.example --port 8080
```

`check` 使用同一策略作诊断，不增加实际流量的日志或拦截计数。
理由与特征分显示在原生诊断/日志中；分数是特征强度，不是准确率或广告概率。
显式允许域名优先，命中的 ABP 例外也会阻止启发式随后覆盖该决定。

## 不接管已有代理的浏览器方案

独立扩展 **0.2.0** 支持 Chrome / Edge（Chromium 119+）。解压
`nullad-browser-extension.zip`，在扩展管理页选择“加载解压缩的扩展”，指向包含
`manifest.json` 的目录。它不需要桌面服务或本地端口。

弹窗有“内置规则”和“免规则识别”两个复选框，默认偏好均选中，但防护初始为
**Off**。选择其中一层或两层，点击“仅本页启用”或“全部网页启用”，才会应用
选择并请求可选 HTTP/HTTPS 资源权限。单独改复选框不会立即改变正在运行的策略。
保守/平衡只改变启发式请求识别与 DOM 阈值，不改变域名快照。Off 停止全部层。

规则层将同一 44,442 域名快照分成 **87 组** `requestDomains` 条件，每组至多
512 个域名；识别层使用通用 URL/资源类型条件与本地 DOM 识别。复杂投放路径条件
拆成 18 个小正则表达式，以满足 Chromium RE2 内存预算。运行时不下载列表、
模型或远程代码，不上传浏览记录。

全站启用/换层保留允许项；“仅本页启用”显式移除当前主机的允许项并恢复该页
防护。本页范围跟随当前标签页的主机，同主机刷新保留，导航到其他主机或关闭
浏览器后失效。全站模式和层级偏好保存在本地，跨浏览器重启保留。

“允许此站点”按精确主机名放行本扩展的网络过滤，并停止、恢复该站 DOM 隐藏；
不包含子域。例如允许 `example.com` 不会自动允许 `shop.example.com`。
“恢复本页隐藏内容”只撤销 DOM 隐藏，恢复的元素在当前文档中保持豁免，网络过滤
继续运行。已失败的资源仍需刷新重新请求。“全部关闭并恢复”移除本扩展的
动态/会话 DNR 规则，注销自动注入并停止/恢复已注入页面；无法确认恢复时会显示
警告，重新加载页面可移除原文档中的效果。

扩展不修改系统/浏览器代理、DNS、证书或请求头，不连接桌面 IPC。
已有 HTTP/SOCKS 代理、PAC、TUN 或 VPN 继续负责路由；扩展在浏览器请求层应用
DNR。这个结构不代表每种软件或版本都经过实测，其他拦截软件仍可阻断请求。

## 新识别范围与恢复边界

原生与扩展请求识别增加明确第三方广告 SDK 文件和加载路径，例如
`adsbygoogle.js`、`prebid.js`、`/tag/js/gpt.js`、`/js/sdkloader/ima3.js`，以及
广告命名空间与投放/竞价动作的组合。SDK 判断受资源类型和第三方上下文约束；
单独 `gpt.js`、`bid`、`click`、`analytics` 或普通 `ad` 子串不能证明是广告。
主文档导航和文档、登录、支付等路径有保护条件；域名规则独立于这些语义猜测。

DOM 结合多语言短广告/赞助标签、ARIA、广告属性、独立容器结构与尺寸。
支持 `aria-label`、`aria-description`、`title` 及 `aria-labelledby` 的短叶文本
引用（至多三个引用 ID）。保守阈值 8，平衡阈值 6，至少两类信号；导航、表单、
主内容、长正文、播放器和混合内容容器有保护条件。

隐藏添加本扩展标记，不删除节点或覆盖原始样式。SPA 容器被复用成正常内容时，
检测会重新测量原可见状态并恢复；局部文本/属性变化会复检附近至多 **4 层**已
隐藏祖先。候选初扫沿父链检查至多 4 个层级，不保证任意深度的容器能被识别。

外部 `aria-labelledby` 标签的初始引用可以读取，但尚无跨分支反向索引：
外部标签文本改变后，不能保证立即找到所有引用容器，必要时刷新页面重新识别。
单候选读取正文至 401 字符，节点检查有上限；每帧与变更队列也有预算。
开放 Shadow DOM 至多同时观察 31 个 root（另一个观察器用于主文档），关闭的
Shadow DOM 不可读取。无标识广告、流内视频、超大页面、高频变更和浏览器内部页
仍有覆盖边界。

## 与 HTTP / SOCKS5 代理串联

原生代理可显式使用现有软件提供的 HTTP/SOCKS5 下一跳。下面的端口仅为示例，
请使用实际监听地址；客户端需要使用 NullAD 的监听端口。

```powershell
# 仅识别，保留已有 HTTP 代理作为下一跳。
nullad-cli.exe serve --no-lists --heuristic balanced --port 8080 --upstream-proxy http://127.0.0.1:7890

# 默认规则与识别共同使用，SOCKS5 在上游解析目标域名。
nullad-cli.exe serve --port 8080 --upstream-proxy socks5://127.0.0.1:1080
```

桌面设置提供同样的上游地址。支持无认证 HTTP/SOCKS5；含用户名/密码的 URL、
HTTPS-to-proxy、SOCKS4、私有代理协议或订阅链接不能直接作为上游。
上游超时、不可用或拒绝连接时返回错误，**不回退直连**。
已有系统代理启用但未填写上游时，显式系统代理接管会拒绝；非空 PAC 始终拒绝
接管，因为静态下一跳不能复制其动态路由。独立扩展可保留 PAC。
默认不接管系统代理、不修改系统 DNS，也不安装根证书。
不要将上游指向 NullAD 自身或建立互相转发的循环。

## 验收记录

本轮 Edge 目标站记录：**Off 16/132 → 仅识别 30 → 仅规则 21 → 共同使用 33
→ Off 16**。组合运行有 15 个 `ERR_BLOCKED_BY_CLIENT` 请求，两项脚本与两项
元素检查通过。该站还测试分析、错误报告和设备遥测，独立网络故障/超时也能计
入 blocked，因此总分不是 NullAD 独立贡献，更不能据此承诺全部广告被拦截。
运行代码没有测试站专用域名、元素 ID 或从该站抄取的 128 主机名单。

新原生包检查已确认 44,607 规则资源加载、关闭列表后 UI 重新启用、零列表 SDK
返回 403，以及正常请求 200/规则命中 403；原生四页中英与明暗主题已检查。
原生规则 + 扩展 + 已有本地 HTTP 上游的两次目标站结果均为 **56/132**，没有同
环境旧 232 规则对照，不能与旧 60 分直接比较。本轮可见 QA 被停止，原生正常
关闭验收保持 **Unknown**，不能沿用历史关闭通过。完整新证据见
[增强验收](enhanced-validation.md)。旧 232 条规则、60/132 及旧零列表
16→30→16 记录属于上一轮环境，保留在 [历史验收](heuristic-validation.md)，
不能替代本轮包、原生、性能或不同代理版本的验收。

## English usage

Desktop/CLI default to 44,607 bundled rules and Balanced local detection.
Use `--heuristic off` for rules only, `--no-lists --heuristic balanced` for local
recognition only, or leave both enabled. Desktop policy edits require Save;
disabled lists remain selectable. The 44,442-domain EasyList/EasyPrivacy
snapshot is separately CC BY-SA 3.0; independent application code remains MIT.

Extension 0.2.0 has separate rules/heuristics checkboxes. Both preferences start
selected, but activation starts Off; an enable button applies the selection.
All-sites changes preserve site allowances; explicitly enabling this page
resumes its exact host. Mode changes affect heuristics only. It uses 87 domain
DNR groups and local reversible DOM detection without downloads or proxy changes.
Short multilingual/ARIA labels and third-party ad SDK loaders improve coverage.
DOM ancestor revisits are limited; external ARIA-label changes have no reverse
reference index and may need a reload. No universal blocking claim is made.

The native listener can chain through an unauthenticated HTTP/SOCKS5 endpoint.
An unavailable upstream never falls back to direct routing; PAC takeover is
refused. The independent browser extension preserves the existing route.
Current browser totals are 16→30→21→33→16 /132. New native checks cover packaged
rules, list re-enabling and rule-free SDK blocking. Native + extension + the
existing HTTP upstream scored 56/132 twice without a matched historical control;
this round's native normal-close acceptance remains Unknown. See
[enhanced validation](enhanced-validation.md).
