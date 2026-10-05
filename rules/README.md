# 可复现内置规则 / Reproducible bundled rule data

当前域名快照为 **44,442 条**，供 `lists/nullad-hosts.txt` 和
`extension/domain-rules.js` 共同使用。原生默认另外加载 165 条 base 规则，
因此 CLI 默认列表加载为 **44,607 条**；扩展只导入域名快照，分成 87 个 DNR
`requestDomains` 组，每组至多 512 域名。这些数字不是拦截率。

## 官方来源与版本

上游为 [easylist/easylist](https://github.com/easylist/easylist)，固定提交
[129e63db3096f78e6dc94ac7ca6a15e27b5d1b79](https://github.com/easylist/easylist/commit/129e63db3096f78e6dc94ac7ca6a15e27b5d1b79)，
提交时间 `2026-10-05T10:22:01Z`。不是运行时请求 `master`，也不是测试站定制名单。
七份原始文件保存在 `vendor/*.source`，URL、原始字节 SHA-256 与上游路径记录于
[sources.lock.json](sources.lock.json)，输出说明见 [metadata.json](metadata.json)。

| 上游路径 | 用途 |
|---|---|
| `easylist/easylist_adservers.txt` | 广告服务器候选 |
| `easyprivacy/easyprivacy_trackingservers.txt` | 跟踪服务器候选 |
| `easyprivacy/easyprivacy_trackingservers_general.txt` | 通用跟踪服务器候选 |
| `easyprivacy/easyprivacy_trackingservers_international.txt` | 国际跟踪服务器候选 |
| `easylist/easylist_allowlist.txt` | 广告规则例外 |
| `easyprivacy/easyprivacy_allowlist.txt` | 跟踪规则例外 |
| `easyprivacy/easyprivacy_allowlist_international.txt` | 国际跟踪规则例外 |

EasyList 的目标是广告过滤；EasyPrivacy 还覆盖分析、跟踪、遥测等隐私项目，
详见 [官方政策](https://easylist.to/pages/policy.html)。遥测不等同于广告，
名单规模不能证明每个条目适合所有应用；用户可关闭规则层或添加允许项。

## 派生边界

生成器只接受无选项的完整 ASCII 域名锚点 `||domain^`，并去重、排序，移除
已被父域规则覆盖的冗余子域。带 `$third-party`、资源类型、页面范围的规则
不会去掉条件后转为整站阻断；路径、通配域名、正则和装饰性规则不导入此子集。

从上游允许文件识别字面主机例外，即使该例外只作用于路径或资源类型，也保守
排除会覆盖它的父域阻断及其子域阻断。泛化/正则例外不能全部表达，因此不能
把快照称为完整 Adblock Plus 或 EasyList 执行。独立原有本地域名保存在
[nullad-local-domains.txt](nullad-local-domains.txt)；`graph.facebook.com` 和
`device-provisioning.googleapis.com` 等正常业务端点被显式排除。
没有从外部验收站抄入 128 域名，也没有按测试站成绩选择条目。

输出数据可独立于启发式使用：原生关闭启发式但保留列表，扩展仅勾内置规则并
点击启用。仅识别时原生禁用全部列表或 CLI 使用 `--no-lists`；扩展取消规则层
并勾识别层。两层也可共同启用，详见 [使用说明](../docs/no-subscription.md)。

## 许可与分发

[EasyList 官方许可](https://easylist.to/pages/licence.html)允许选择 GPL 或
Creative Commons Attribution-ShareAlike；这里对派生域名数据选择
[CC BY-SA 3.0 Unported](https://creativecommons.org/licenses/by-sa/3.0/)。
归因于 **The EasyList authors (https://easylist.to/)**，保留上游出处、许可与
抽取/去重/例外排除等修改说明。对该数据的修改或重新分发应遵循其署名和相同
方式共享条件；独立应用代码仍为 [MIT](../LICENSE)，不能将整包数据改标 MIT。

原生包携带 [lists/THIRD_PARTY_NOTICES.md](../lists/THIRD_PARTY_NOTICES.md)，
扩展包携带 [extension/THIRD_PARTY_NOTICES.md](../extension/THIRD_PARTY_NOTICES.md)。
原始输入保留上游字节；`.gitattributes` 对 vendor 源关闭文本转换，对生成数据
指定 LF，使 Windows 检出也能重现锁定哈希。更新快照时同时更新两个载体与通知。

## 更新、检查和恢复

在仓库根目录运行，Python 标准库即可：

```powershell
# 离线重现已锁定版本；不访问上游。
python scripts/update-bundled-rules.py

# 只核验输入 SHA-256 与生成输出，不写文件；CI 使用此项。
python scripts/update-bundled-rules.py --check

# 维护者明确选择更新：联网获取官方仓库当前提交，并固定所有输入到该 SHA。
python scripts/update-bundled-rules.py --refresh

# 抽取边界、来源哈希、发布失败与恢复备份回归。
python tests/bundled-rules.py
```

默认重现读取 vendor 与 lock；`--refresh` 才联网，下载有超时、大小与重定向
检查。全部输入获取并验证成功后，生成器先暂存新版本和旧版本，再逐项发布；
普通发布失败会尝试恢复旧文件。回滚也失败时保留磁盘恢复副本，并在错误中
报告路径，不假报更新成功。不要删除错误中列出的 `.nullad-rule-old-*` 文件，
先核对其对应路径，完成恢复后再重跑 `--check`。此机制不能代替进程中断后的
人工核对；更新/打包期间应避免另一进程同时重写这些文件。

运行软件不调用这个维护脚本，也不会自动下载新快照。版本更新必须重新验收；
浏览器组合结果与原生组合、包、性能分别记录在
[增强验收](../docs/enhanced-validation.md)。旧 232 规则/60 分属于历史记录。

English: The reproducible 44,442-domain snapshot comes from seven official,
commit-pinned EasyList/EasyPrivacy source files and independent legacy local
input. Only unconditional ASCII domain anchors are imported; conditional rules
are never widened by dropping options. Literal-host exceptions conservatively
remove affected parent/child blocks. This is a subset, not complete ABP execution.
Derived data is CC BY-SA 3.0, independent code MIT. Keep attribution and change
notices when redistributing. Generation is offline by default; only explicit
`--refresh` downloads new official input. Failed publication attempts rollback;
failed rollback retains recovery files and reports their paths.
