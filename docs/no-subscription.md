# 无订阅识别与代理共存 / Local detection and proxy coexistence

NullAD can use local detection without loading a domain subscription. This does
not mean an algorithm has no conditions, and it does not guarantee every ad is
recognizable. Lists, local network detection and the browser extension are
independent layers with different visibility.

## 不接管已有代理的浏览器方案

Chrome / Edge 使用 `nullad-browser-extension.zip`：解压，在扩展管理页选择
“加载解压缩的扩展”，指向含 `manifest.json` 的目录。扩展初始关闭，点击图标，
选择“保守”或“平衡”，再选择“仅本页启用”或“全部网页启用”。浏览器会请求
HTTP/HTTPS 资源权限；未授权时不会假报启用。

扩展不修改系统代理、浏览器代理、DNS、证书、请求头，也不连接桌面服务。
因此已有代理扩展、系统 HTTP/SOCKS 代理、PAC、TUN 或 VPN 可继续负责路由。
它不需要 NullAD 桌面监听器才能使用。网络请求在浏览器的 DNR 层阻断，
页面元素在本地 DOM 中识别、隐藏；隐藏本身不表示资源没有下载。

没有广告域名订阅、云端模型、远程代码或浏览记录上传。扩展包中的通用条件
识别独立广告脚本名、广告服务主机标签与路径组合；页面检测结合广告标签、
属性、容器结构和尺寸。普通 `ad` 子串、横幅尺寸或跨站 iframe 均不足以隐藏。
当前规则没有针对测试网站的域名、元素 ID 或完整测试主机列表。

误判时选择“允许此站点”（精确主机名）、“恢复本页隐藏内容”或“全部关闭并恢复”。
允许站点会同时撤销该站 DOM 隐藏并放行该扩展的网络过滤；其他拦截软件仍可拦截。
恢复页面内容只撤销 DOM 隐藏，不会恢复已经失败的网络请求，需要重新加载页面。
仅本页模式跟随当前标签页的主机，关闭浏览器或导航到其他主机后失效。

## 与 HTTP / SOCKS5 代理串联

如果希望浏览器以外的流量经过 NullAD，显式填写现有代理软件提供的 HTTP 或
SOCKS5 端口。以下 `7890` / `1080` 只是示例，使用实际软件显示的监听地址。

```powershell
# 零订阅，保留现有 HTTP 代理作为下一跳；客户端使用 127.0.0.1:8080。
nullad-cli.exe serve --no-lists --heuristic balanced --port 8080 --upstream-proxy http://127.0.0.1:7890

# SOCKS5 域名交给上游解析，不在本机提前解析目标域名。
nullad-cli.exe serve --no-lists --heuristic balanced --port 8080 --upstream-proxy socks5://127.0.0.1:1080

# 脱离真实流量的同策略诊断；不会增加拦截日志/计数。
nullad-cli.exe check http://ads.vendor.example/ad-loader.js --no-lists --heuristic balanced --type script --page https://publisher.example/

# 恢复误判的域名（同时包括它的子域，严格标签边界）。
nullad-cli.exe serve --no-lists --allow-host vendor.example --upstream-proxy http://127.0.0.1:7890
```

桌面设置也提供模式、允许域名和上游地址。模式/允许域名只在保存成功后实时生效；
更改上游需要重启防护。首次启动仍不接管系统代理，不启用系统 DNS。

已有系统代理启用但未配置上游时，`--system-proxy` / 桌面系统代理接管会拒绝启动，
保留当前配置。非空 PAC 配置也会拒绝接管，因为单个静态上游不能复制 PAC 的动态路由；
使用独立扩展可保留 PAC。上游不可用或拒绝连接时返回错误，不回退为直连。
HTTP CONNECT 的预读字节、二进制内容及 SOCKS5 域名/IPv4/IPv6 目标均保持原顺序。

支持不带认证的 HTTP 和 SOCKS5 上游；用户名/密码 URL 会被拒绝，不存入日志。
HTTPS-to-proxy、SOCKS4、专用私有协议或仅提供订阅链接的代理不能直接填写为上游。
如果软件只有 TUN/VPN，保留它的路由并使用浏览器扩展，或让 NullAD 直连套接字走系统路由。
不要把 NullAD 的上游指回自己的监听端口，也不要建立相互转发的循环。

## 能力与验证边界

| 层 | 可见信息 | 无订阅方案 | 边界 |
|---|---|---|---|
| HTTP | 完整明文 URL、资源类型、Referer/Origin | 多信号启发式 | 请求可伪造或缺少上下文；保护导航/登录/支付/文档路径 |
| CONNECT / DNS / SNI | 主机名 | 更保守的广告服务子域判断 | 不读 HTTPS 路径；不会凭 `metrics` 等单词阻断整个正常站点 |
| 浏览器 DNR | HTTP/HTTPS URL 与资源类型 | 打包的通用语义条件 | 模糊主机、无标识同源接口可能无法判断；不等于订阅广度 |
| 浏览器 DOM | 可访问文档与开放 Shadow DOM | 多信号识别与可逆隐藏 | 流内视频广告、封闭 Shadow DOM、伪装正文与浏览器内部页不能保证 |

离线启发式理由单独显示，不伪造“命中了某条订阅规则”。特征分表示算法特征强度，
不是准确率或广告概率。用户允许域名优先；ABP 例外会阻止后续启发式覆盖。
实际流量计数是最终决策；底层 engine 统计仍只表示规则匹配。

`adblock.turtlecute.org` 检查域名连接、两项脚本和两项元素隐藏，
还包含分析、错误报告和设备遥测。网络故障/超时也能被网站计为 blocked，
因此不能把总分当成 NullAD 单独贡献，也不能为了满分阻断全部正常遥测。
比较启用/关闭结果时同时记录 DNR 请求错误与 DOM 标记；完整结果见
[本轮验收](heuristic-validation.md)。“支持保留已有代理路径”是架构属性，
“所有代理软件所有版本都已通过”不是当前验收结论。

## English usage

The extension leaves the existing browser/system/PAC/TUN/VPN route intact. Load
the unpacked ZIP in Chrome/Edge, opt in to HTTP/HTTPS resource access, then enable
one page or all pages. It blocks resource requests using browser DNR and performs
reversible local DOM cleanup. Site exceptions and Stop undo its own effects.

The native proxy can explicitly chain through an unauthenticated HTTP or SOCKS5
endpoint with `--upstream-proxy`. SOCKS domain resolution happens upstream.
An unavailable upstream never falls back to direct routing. Existing system
proxy takeover requires an explicit upstream; PAC takeover is refused. Use the
independent extension to keep PAC behavior. Neither path installs a root CA.

No subscription is needed for the bundled semantic heuristics. Their coverage
is deliberately narrower than broad curated lists; first-party encrypted video
ads and unlabelled content cannot always be distinguished safely. Compatibility
of each browser/proxy/version and the live test score must be measured separately.
