# NullAD

[English](README.md) · **简体中文**

NullAD 是用 Rust 编写的广告与追踪拦截软件，提供桌面界面和无界面 CLI。
它在明文 HTTP、TLS 连接主机名和 DNS 查询三个层面过滤流量。
匹配引擎不包含网络、文件系统或平台集成代码。

## 当前验收状态

| 范围 | 结果与证据 |
|---|---|
| Windows 工程检查 | **Pass**：格式、严格 Clippy、全工作区 229 项测试通过（3 项显式忽略）；release 构建见验收记录 |
| 网络与生命周期 | **Pass**：本地 HTTP/DNS 22 项验收；20 次循环与 40 个并发启停操作后端口可重绑 |
| 配置、规则更新与恢复 | **Pass**：core 30、host 32 项回归；配置写入失败不发布、旧加载不能覆盖新配置、失败恢复保留记录 |
| Windows 系统代理 | **Pass**：显式 apply/revert 与 CLI Ctrl+Break 恢复；四个注册表字段完整恢复，DNS 未变化、pending=0 |
| Windows 原生桌面 | **Pass**：四页、IPC、中文/英文、深色、真实流量和日志、显式保存、待重启提示、无托盘关闭清理 |
| 原生最小窗口 | **Pass**：最终便携 GUI 的四页均验证 840x560，包含修正后的日志时间列 |
| Windows 管理员 DNS / IPv6 UDP | **Unknown**：无管理员 DNS 写入验收；本机 IPv6 UDP loopback 未取得通过结果 |
| 托盘菜单 / 实际系统 125%/150% 缩放 | **Unknown**：浏览器等效尺寸测试通过，不能替代原生系统缩放与托盘菜单操作 |
| 交付包 / 远端 CI | **Pass**：NSIS/ZIP 构建、仓库外便携启动、[Windows CI](https://github.com/ZoeHao2026/NullAD/actions/runs/37203007636)；安装/卸载仍为 Unknown。详见 [Windows 验收](docs/windows-validation.md) |
| macOS 与 Linux | **Deferred**：存在已知恢复不足，未做原生验收 |

已执行的最终常规检查没有失败项；未验收项单列为 Unknown/Deferred。

构建或单元测试通过，不能证明安装成功、桌面界面可用，也不能替代其他系统的恢复验收。
完整流程与尚未确认的项目见 [Windows 验收](docs/windows-validation.md)。

## Windows 构建

需要 Rust 1.96 或以上版本、MSVC 工具链、Visual Studio C++ 构建工具及 Windows SDK。
桌面运行需要 WebView2 Runtime；UI 测试与 Tauri 打包命令需要 Node.js；
本地网络验收脚本需要 Python。

在仓库根目录执行：

```powershell
cargo build --release --workspace --locked
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
node --test ui/tests/ui.test.cjs
python tests/e2e.py
```

需要初始化 MSVC 环境时可使用：

```powershell
scripts\build.bat release
scripts\build.bat test
```

默认使用正常 Cargo 缓存并允许拉取依赖。只有提前缓存了所需依赖后，才显式选择离线构建：

```powershell
cargo build --release --workspace --locked --offline
scripts\build.bat release --offline
```

`Cargo.lock` 应提交到仓库。项目不要求私有或工作区内的 Cargo registry。
前端为 HTML、CSS、JavaScript，没有独立的前端编译步骤。

### Windows 交付形式

桌面 NSIS 安装包的构建命令：

```powershell
Push-Location crates/nullad-desktop
npx --yes @tauri-apps/cli@2.12.1 build --bundles nsis -- --locked
Pop-Location
```

安装包位于 `target/release/bundle/nsis/`，包含桌面资源和规则列表。
桌面通过 Tauri 资源目录定位内置列表，不依赖启动时的工作目录。

便携 CLI 目录应包含：

```text
NullAD-cli/
  nullad-cli.exe
  lists/
    nullad-base.txt
    nullad-hosts.txt
```

CLI 优先查找 `./lists`，随后查找可执行文件旁的 `lists`。
也可以重复使用 `--list <PATH>` 指定列表。
桌面便携 ZIP、CLI ZIP 与 NSIS 安装包由 `scripts/package-windows.ps1` 生成，
同时生成 SHA256SUMS.txt；三种交付物需分别验证启动。

## 使用

```powershell
# 查看内置列表与规则。
.\target\release\nullad-cli.exe load

# 判断一个 URL 是否会被拦截。
.\target\release\nullad-cli.exe check "https://ads.example.com/banner.gif"

# 提供发起页面和资源类型。
.\target\release\nullad-cli.exe check "https://googletagmanager.com/gtm.js" --page "https://example.com/" --type script

# 启动本地 HTTP 与 DNS 服务；客户端需要使用相应地址。
.\target\release\nullad-cli.exe serve --port 8080 --dns-port 5353

# 显式选择在服务运行期间修改系统代理。
.\target\release\nullad-cli.exe serve --port 8080 --system-proxy
```

桌面默认使用**简体中文**，设置中可切换**英文**。
运行期间修改监听配置，需要重启防护才生效；状态显示实际绑定端口，并提示是否需要重启。
DNS 默认关闭。启动 DNS 服务本身不会自动修改操作系统解析器。
CLI 仅在显式传入 `--system-proxy` 且所有监听器绑定成功后接管系统代理。
Ctrl+C（Windows 也支持 Ctrl+Break）会停止并等待连接任务退出，再恢复和核对原设置；
恢复失败会返回错误并保留记录。已有待恢复快照时拒绝覆盖。

| 机制 | 过滤范围 | 限制 |
|---|---|---|
| HTTP 代理 | 明文 HTTP URL 与路径 | 无法查看加密 HTTPS 路径或响应内容 |
| TLS SNI | 按主机名过滤 TLS 连接 | ECH 可以隐藏该主机名 |
| DNS 黑洞 | 使用该服务的域名查询 | 不知道 URL 路径，也无法控制使用其他解析器的应用 |

NullAD 不安装根证书，也不解密 HTTPS。
手动设置客户端和 `--system-proxy` 是两种接入方式；系统代理只能覆盖遵循平台代理设置的应用。
修改系统 DNS 需要管理员权限。低端口绑定规则因系统而异；
端口不可用或权限不足会由监听器报告。

### 配置隔离与 QA

默认配置、数据与日志使用操作系统的每用户目录。
将 `NULLAD_HOME` 设置为**非空绝对路径**，即可隔离这些文件：

```powershell
$env:NULLAD_HOME = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'NullAD-QA'
.\target\release\nullad-desktop.exe
```

隔离目录下分别使用 `config/`、`data/` 和 `logs/`。
这是环境变量选项，不写进配置文件。
Windows 还可使用 `NULLAD_WEBVIEW_DATA_DIR` 隔离 WebView2 用户数据。
这些变量只隔离应用文件；显式启用系统代理接入仍会修改真实操作系统配置。

## 规则与列表加载

支持域名锚点（`||domain^`）、起止锚点、分隔符、通配符、
例外（`@@`）、正则和 hosts 文件条目。
引擎处理资源类型、第三方、域名、大小写匹配和 important 选项。
通常例外优先于拦截；important 拦截规则优先于非 important 例外。

装饰性规则会被识别和计数，但不会隐藏页面元素。
`$csp`、`$redirect` 和 `$removeparam` 内容由解析器保留，拦截器不执行这些行为。

畸形规则会隔离处理。桌面加载器用实际列表 ID 解析一次，并复用 HTTP 客户端。
读取失败、零规则更新、HTML 响应或远端列表明显缩水时，
保留**相同列表 ID 与来源**的最后有效规则。
改换来源不会使用其他来源的缓存；禁用所有列表会显式安装空规则集。
依据旧配置发起的加载不会覆盖更新后的配置。

## 恢复机制与平台边界

系统变更先写恢复日志，再应用。
部分应用失败时会尝试回滚，并保留原始快照。
恢复完成后读回核对，成功才清除对应类型的记录；失败记录会继续显示，允许重试。
日志更新串行执行并原子写入。损坏的恢复文件会保留，并作为错误呈现。

Windows 代理修改当前用户的 Internet Settings，再向应用广播变更。
新快照保留实际触碰的四个注册表字段的存在性、类型和原始字节；恢复按快照设置或删除。
旧代理快照缺少这些信息时保留记录并报告，不能猜测。
Windows DNS 快照保存接口 GUID 和 IPv4 的 DHCP/静态模式，
恢复时重新确认当前接口索引。
旧 DNS 快照缺失模式时会保留并报错，不猜测原配置。
该适配器不修改 IPv6 系统解析器配置。

macOS 与 Linux 当前**尚未通过自动系统配置的发布验收**：

- **macOS**：网络服务解析与服务身份需要原生验证；
  通用代理快照不能完整保留 HTTP/HTTPS 独立配置和 PAC 状态。
  当前后端不能捕获 DHCP DNS 配置。
- **Linux**：代理集成面向 GNOME `gsettings`，并不覆盖所有桌面；
  自动模式、独立 HTTPS 状态和绕过列表恢复存在已知不足。
  重写普通 `resolv.conf` 不能保留全部原始指令，托管符号链接会被拒绝。
  尚未实现 NetworkManager/systemd-resolved 集成。

移动端二进制、HTTPS URL 检查和页面元素隐藏不在当前实现范围内。

## 测试与性能

常规测试使用模拟系统适配器、隔离文件和本地网络样例。
会写入真实代理设置的测试默认忽略；运行实机测试前请阅读
[Windows 验收](docs/windows-validation.md)。

已完成同机预热、各五轮的原版与优化版对比。固定 10 万条规则的混合负载下，
引擎吞吐约为原版的 **1.030 倍**，实际 `decide`（含 500 条环形日志）为 **11.485 倍**。
实际路径分配量从每请求约 480 KB 降至 116 B；引擎复用路径分配量基本不变。
方法、延迟、1,000 条规则结果与全部原始数据见 [性能实测](docs/performance.md)。
CLI 快速测量命令：

```powershell
.\target\release\nullad-cli.exe bench --iterations 400000 --synthetic 300000 --json
```

完整对比记录在 `docs/performance-comparison.json`。
合成规则匹配成绩只说明对应工作负载，不能证明真实网络吞吐量、
完整 Adblock Plus 一致性或其他机器上的性能。

## 架构

| 组件 | 职责 |
|---|---|
| `nullad-engine` | 解析、索引、匹配与原子替换规则集 |
| `nullad-api` | 共享状态类型与接口 |
| `nullad-intercept` | HTTP 代理、TLS 主机名检查、DNS UDP/TCP |
| `nullad-host` | 系统代理/DNS 适配、文件目录与恢复日志 |
| `nullad-core` | 配置、运行状态、列表加载与恢复报告 |
| `nullad-cli` | `check`、`load`、`bench`、`serve` |
| `nullad-desktop` + `ui/` | Tauri 外壳、IPC 命令、托盘与界面 |

CLI 与桌面共用匹配引擎。
桌面负责异步监听生命周期及任务取消，系统变更与匹配分别由对应层处理。

## 许可证

MIT。全文见 [LICENSE](LICENSE)。
