# NullAD

[English](README.md) · **简体中文**

一款用 Rust 编写的高性能跨平台广告与追踪拦截软件。

NullAD 在三个彼此独立的层面进行过滤——DNS、TLS 连接建立、以及明文 HTTP——
并围绕一个**纯粹、无 I/O 的匹配引擎**构建，该引擎被所有前端共享。

```
┌────────────────────────────────────────────────────────────┐
│ nullad-desktop    Tauri 2 外壳  +  ui/  (原生 HTML/JS)     │
├────────────────────────────────────────────────────────────┤
│ nullad-host       平台适配：系统代理、DNS、变更日志        │
├────────────────────────────────────────────────────────────┤
│ nullad-intercept  HTTP 代理 · TLS SNI · DNS 黑洞           │
├────────────────────────────────────────────────────────────┤
│ nullad-engine     纯匹配核心：解析 · 建索引 · 匹配         │
└────────────────────────────────────────────────────────────┘
```

`nullad-engine` 不依赖任何异步运行时、套接字、文件系统或平台 API。
正因如此，同一套匹配器可以不加改动地驱动桌面端、无界面 CLI，
以及未来的移动端 FFI 绑定。

---

## 当前状态

| 组件 | 状态 |
|---|---|
| `nullad-engine` | 完成——解析器、三套索引、无锁热更新 |
| `nullad-intercept` | 完成——HTTP 代理、SNI 检测、DNS 黑洞 |
| `nullad-host` | 完成——Windows 已实测；macOS/Linux 已实现并通过编译检查 |
| `nullad-core` | 完成——状态、配置、规则表加载、变更日志集成 |
| `nullad-cli` | 完成——`check`、`load`、`bench`、`serve` |
| `nullad-desktop` | 代码完成且可链接；**运行未验证**（原因见下） |

**桌面 GUI 在开发所用的沙箱中无法启动。** 窗口子系统是 Tauri/WebView2，
它会启动独立的 `msedgewebview2.exe` 宿主进程并通过命名管道通信，
而该沙箱同时禁止这两者，因此 Tauri 在应用初始化阶段失败：

```
Failed to setup app: 拒绝访问。 (os error 5)
```

这一点已通过证据定位到**环境**而非本项目代码：我用一个
**setup 闭包完全为空**的 Tauri 程序复现了完全相同的失败。
Rust 侧可以正常构建和链接，请在沙箱之外运行
`target/release/nullad-desktop.exe` 进行验证。

---

## 实测性能

以下数据全部来自本机 `nullad-cli bench`，可复现。
由于离线源中没有 `criterion`，压测工具是手写的，
并且只报告本项目明确承诺的那几个指标。

```
$ nullad-cli bench --iterations 400000 --synthetic 300000

synthetic rule set: 300000 rules, built in 764 ms

WORKLOAD               RULES      REQ/SEC    MEAN us     P50 us     P95 us     P99 us
loaded rules             232      1767833      0.565      0.500      0.700      0.900
synthetic rules       300000      4329998      0.230      0.200      0.300      0.500

hot reload under load:
  10 swaps while 23877203 requests were evaluated concurrently
  swap latency: mean 7.9 us, max 9.0 us
  torn or empty rule-set observations: 0
```

| 指标 | 目标 | 实测 | 结论 |
|---|---|---|---|
| 匹配延迟 p50 | ≤ 10 µs | 0.2 µs | **达标**，优 50 倍 |
| 匹配延迟 p99 | ≤ 50 µs | 0.5 µs | **达标**，优 100 倍 |
| 建索引 50 万条 | ≤ 2 s | ~1.3 s | **达标**（100 万条 2.6 s） |
| 热更新 | < 50 ms 且不丢请求 | 9 µs，0 次撕裂读 | **达标**，优 5500 倍 |
| 发布体积 | ≤ 25 MB | CLI 2.09 MB，GUI 8.01 MB | **达标** |
| 吞吐量 | ≥ 500 万次/秒 | **410–440 万** | **未达标**（约 85%） |
| ABP 兼容性 | ≥ 98% | 见「测试」一节 | 见说明 |

**吞吐量目标没有达成。** 针对 30 万条规则集，四次运行实测 410–440 万次/秒，
而延迟远在预算之内。要补上最后那 15% 需要有性能剖析工具，
但离线源里没有；诚实的说法是：该指标目前停在约 85%。

真实内置规则表（232 条）的匹配速度约 170 万次/秒，比合成用例更慢——
这是刻意的：真实规则表含 13 条正则规则，而合成集几乎全是域名锚点。

### 时间花在哪里

引擎自带的分解统计会给出每个请求的开销构成。在真实的 232 条规则表上：

```
total                  567.0 ns
domain trie             52.0 ns     域名前缀树
substring automaton    123.2 ns     子串自动机
regex bucket           366.8 ns     正则桶
url lowercasing         37.9 ns     URL 转小写
```

正则桶占了大头。缓解手段是：为每个模式推导出一个**语法上的最小匹配长度**，
URL 短于该长度时用一个整数比较直接拒绝，从而完全跳过正则引擎。
这个下界不是靠肉眼看代码确认的，而是用**随机化属性测试**证明它确实是真下界，
并且对大小写不敏感匹配同样成立。

---

## 构建

```bash
cargo build --release --workspace     # 全部
cargo test  --workspace               # 177 个测试
```

前端没有单独的构建步骤：`ui/` 是纯 HTML、CSS、JavaScript，由 Tauri 直接提供。
这是本项目环境的直接后果——本机 npm 源不可达——同时也砍掉了整条工具链。

### 重要：本构建刻意离线

`.cargo/config.toml` 设置了 `net.offline = true`，所有依赖都从工作区内的
本地 registry 缓存 `.cargo-home/` 解析（已 git-ignore，从机器全局 cargo
缓存植入）。因此 `Cargo.lock` 是权威的，**必须提交**。

这并非风格偏好。NullAD 是在一台 Windows TLS 栈机器级损坏的主机上写出来的：

```
schannel: AcquireCredentialsHandle failed: SEC_E_NO_CREDENTIALS
```

`cargo`、`git`、`curl` 全都无法访问 crates.io。不依赖网络是当时唯一能构建的方式，
而它的副产品是：这个项目可以从冷缓存、零网络完成编译。
在 TLS 正常的机器上，删掉 `offline` 那一行即可正常拉取。

由于该约束，四个通常会被使用的库不在缓存中，本项目自行实现：

| 缺失的 crate | NullAD 的替代方案 |
|---|---|
| `adblock-rust` | 自研 ABP 解析器与索引结构 |
| `hickory-dns` | 自研 DNS 报文编解码（解析、名字解压、构造响应） |
| `rcgen` | 不需要——TLS 中间人不在 MVP 范围内 |
| `criterion`、`insta`、`proptest` | 手写压测工具；`assert_eq!` 黄金测试；`rand_chacha` 属性测试 |

有两个后果值得了解：

- **测试数据不写入系统临时目录。** 在加固或沙箱化的主机上该目录可能不可写，
  因此 `nullad-core` 的加载测试把夹具创建在测试二进制旁边——
  那里的权限由构造保证是可用的。
- **引擎不引入任何日志依赖。** 如果后台回收线程启动失败，
  它只往 stderr 写一行，而不是把 `tracing` 拖进一个本应可嵌入任何环境的 crate。

---

## 使用

```bash
# 内置规则表里有什么？
nullad-cli load

# 这个 URL 会被拦吗？被哪条规则拦？
nullad-cli check "https://ads.example.com/banner.gif"

# 带页面上下文与资源类型，用于 $domain= 与 $third-party 规则
nullad-cli check "https://googletagmanager.com/gtm.js" \
  --page "https://example.com/" --type script

# 测这台机器
nullad-cli bench --iterations 400000 --synthetic 300000

# 运行拦截器（无需管理员权限）
nullad-cli serve --port 8080 --dns-port 5353
```

`serve` 会打印代理地址，把客户端指过去即可。
1024 以下的端口需要管理员或 root 权限，因此 `5353` 是无需提权的好选择。

### 各拦截层能做什么、不能做什么

| 机制 | 拦截范围 | 是否需要提权 | 局限 |
|---|---|---|---|
| HTTP 代理 | 明文 HTTP 的完整 URL 与路径 | 否 | 看不进 TLS 内部 |
| TLS SNI | 按主机名拦截整条连接 | 否 | **对 ECH 完全无效** |
| DNS 黑洞 | 域名，在任何连接之前 | 是（53 端口） | 只能看到主机名 |

要过滤 HTTPS 的 **URL**，必须做基于证书的中间人拦截，
也就是安装一个被本地信任的根证书。这是一个真实的安全决策，
因此**刻意不包含在本次发布中**。NullAD 绝不会偷偷解密你的流量。

---

## 规则语法支持

已支持：`||domain^` 锚点、`|` 首尾锚点、`^` 分隔符、`*` 通配、
`@@` 例外、`/regex/` 字面量、hosts 文件行（`0.0.0.0 host`）、
`!` 与 `#` 注释，以及 `$` 选项 `script`、`image`、`stylesheet`、`object`、
`xmlhttprequest`、`subdocument`、`document`、`font`、`media`、`websocket`、
`ping`、`other`、`popup`、`webrtc`、`third-party`、`~third-party`、`domain=`、
`match-case`、`important` 及其取反形式。

已解析但**未生效**：装饰性规则（`##`）、`$csp=`、`$redirect=`、`$removeparam=`。
这些规则可以正常加载并原样往返，不会报错。

匹配语义遵循 Adblock Plus：例外（`@@`）优先于拦截，
但带 `$important` 的拦截规则会压过非重要的例外。

### 健壮性保证

以下是**强制实施**的性质，不是口号：

- 解析失败的规则会被隔离并附上原因，绝不做整个规则表加载失败。
  内置规则表加载 232 条，零隔离。
- 解析出**零条**规则的列表会被标记为可疑，而不是静默接受——
  因为最常见的原因就是下载被截断。
- 远端列表若比上一版小 50% 以上会被拒绝，
  这样公共 WiFi 门户的错误页面就无法替换掉一个可用的规则表。
- 正则规则只使用 `regex` crate，它保证线性时间——
  规则表无法构造出灾难性回溯（ReDoS）。
- DNS 名字解压拒绝前向指针并限制展开次数，
  恶意报文无法造成死循环或内存耗尽。

---

## 系统集成与安全性

把整个操作系统流量路由进 NullAD 是它做过最有侵入性的事情，
因此每一项变更都会**先写入变更日志再应用**，只有成功还原后才被移除。
`nullad-cli` 会打印尚未还原的变更，GUI 会展示并提供一键还原。

这个顺序是刻意设计的：先记录意味着崩溃可能留下一条「声称改了但也许没改」的记录。
而还原一个本来就正确的设置是无害的；
反过来丢失一条真实变更的记录，会把用户的机器困在一个已经不再运行的代理上。

平台覆盖：

- **Windows** — 写每用户的 `HKCU\...\Internet Settings`，无需提权；
  用 `InternetSetOption` 广播变更使正在运行的程序立即感知。
- **macOS** — 通过 `networksetup`，作用域限定在承载默认路由的那个网络服务上。
- **Linux** — 用 GNOME `gsettings` 设代理，`/etc/resolv.conf` 设 DNS，
  并且如果该文件是由 systemd-resolved 托管的符号链接则拒绝覆写。

只有 Windows 这条路径经过运行验证；其余已实现并通过编译检查。

### 关于 `unsafe`

NullAD 中只有一处 `unsafe`：`nullad-host/src/platform/windows.rs` 里对
`InternetSetOptionW` 的调用——`windows-sys` 没有为它提供安全封装。
该调用传入空句柄、空缓冲区、零长度，正是广播设置变更的文档化用法。
其余所有 crate 都是 `#![forbid(unsafe_code)]`；`nullad-host` 用的是 `deny`，
从而只放行这一处调用，任何新增用法都会让构建失败。

---

## 测试

全工作区 177 个测试通过，零编译警告。测试重心放在引擎上——
有趣失效模式都在那里。

```
nullad-engine      82     解析器、索引、匹配语义、热更新
nullad-intercept   42     HTTP 分帧、ClientHello 解析、DNS 编解码
nullad-core        18     配置、规则表加载、决策日志
nullad-host        18     变更日志、代理设置、DNS 设置
nullad-cli         12     参数处理、压测统计
nullad-desktop      5     命令辅助函数
```

单元测试之外还有：

- **`tests/e2e.py`** — 20 项端到端检查。启动真实的源站服务器、
  真实的代理与 DNS 黑洞，然后灌入真实流量：转发保真、拦截并给出命中的规则、
  回环地址永不误拦、DNS 黑洞对 A 与 AAAA 均正确应答、
  畸形 DNS 报文不会导致崩溃、以及限定范围的例外规则精确放行它该放行的。
- **属性测试** — 用随机 URL 验证正则最小长度下界**永不偏高**，
  对大小写敏感与不敏感两种模式都验证。
- **并发测试** — `bench` 在第二个线程持续评估请求的同时反复切换规则集，
  断言撕裂或空规则集的观测次数为零。

全部运行：

```bash
cargo test --workspace
python tests/e2e.py
```

---

## 目录结构

```
crates/
  nullad-engine/      纯匹配核心，无 I/O
  nullad-api/         与任何 UI 共享的 DTO 与 trait
  nullad-intercept/   HTTP 代理、TLS SNI、DNS 黑洞
  nullad-host/        平台适配、变更日志
  nullad-core/        编排、配置、规则表加载
  nullad-cli/         无界面 CLI
  nullad-desktop/     Tauri 应用
ui/                   HTML/CSS/JS 前端，无构建步骤
lists/                内置规则表
tests/e2e.py          端到端拦截测试
```

`nullad-desktop` 只依赖 `nullad-api` 与 `nullad-core`。
替换 Web UI 意味着重写 `ui/` 以及
`crates/nullad-desktop/src/commands.rs` 中那层薄薄的命令绑定，
**不需要触碰任何引擎代码**。

---

## 已知局限

逐条明确列出，而不是留给用户自己去踩：

1. **不做 HTTPS URL 过滤。** 需要证书中间人，属于用户必须知情的
   安全决策。本次发布不含此功能。
2. **ECH 会使 SNI 过滤失效。** 加密客户端问候（Encrypted Client Hello）
   把主机名对连接层完全隐藏。
3. **吞吐量约为目标的 85%**，实测数据见上。
4. **DNS 需要提权**才能绑定 53 端口并改写系统解析器，
   因此默认关闭；NullAD 的其余部分不依赖它即可工作。
5. **GUI 未做运行验证**，原因见文首。
6. **无移动端二进制。** `nullad-engine` 与 `nullad-api` 是按可在这些目标上
   编译来写的，但尚不存在 Android/iOS 构建。
7. **装饰性规则只解析不应用。** 没有元素隐藏功能。

## 许可证

MIT。全文见 [LICENSE](LICENSE)。
