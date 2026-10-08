# Windows CVM 部署实测报告 — 2026-10-08

[English](WINDOWS-CVM-ACCEPTANCE.md) · [部署兼容矩阵](DEPLOYMENT.zh-CN.md) · [结构化证据](evidence/windows-cvm-2026-10-08.json)

在腾讯云国际站 `ap-singapore-2` 真实创建四台 CVM，通过 TAT 执行安装和服务验收，测试后销毁。以下结果证明 **STS Bridge 的真实安装／服务兼容性**，不代表 CyberArk／Idira 认证或 PSM 端到端验收。

| Windows Server 版本 | OS build | Windows PowerShell | 官方公共镜像 | Bridge 结果 |
|---|---|---|---|---|
| 2022 数据中心版英文 x64 | 20348 | 5.1.20348.4294 | `img-9tzezztj` | 通过 |
| 2019 数据中心版英文 x64 | 17763 | 5.1.17763.8755 | `img-bhvhr6pr` | 通过 |
| 2016 数据中心版英文 x64 | 14393 | 5.1.14393.9140 | `img-1eckhm4t` | 通过 |
| 2012 R2 数据中心版英文 x64 | 9600 | 5.1.14409.2001 | `img-2tddq003` | 通过 |

每台使用 `SA9.MEDIUM4`（2 vCPU、4 GiB）、50 GiB 系统盘、机器级 **Python 3.13.7**、按仓库 SHA256 校验的 **WinSW 2.12.0**。Python 安装包 Authenticode 签名通过验证，签发对象为 Python Software Foundation。2022／2019／2016 测试源码为 `401ad3c`，加上下述原生命令错误流修正；后续 2012 R2 测试使用已包含该修正的 `3e78aec`。未在这些 CVM 上测试 Python 3.11／3.12／3.14；Windows 2025 的 CI 证据另行记录。

## 实际通过的检查

四台均通过现有 `scripts/ci/` 检查：WinSW 哈希校验、合成配置、篡改 WinSW 拒绝、哈希锁定依赖安装、以 `NT SERVICE\PSMTencentCloudSTS` 注册并启动服务、ACL 检查、带凭证健康／就绪探测、匿名健康／就绪请求拒绝（HTTP 403）、匿名存活探测（HTTP 200）、非法表单字段拒绝（HTTP 400）及对应审计原因、服务重启后就绪，以及卸载后保留配置和运行文件。

测试配置为合成数据，不含可用云凭证；调用者 AK/SK 留在编排主机，未下发到 CVM。借用不允许公网 TCP 入站的现有安全组，未修改规则，通过 TAT 执行而非 RDP／WinRM。四台临时实例均已销毁，并通过 CVM API 确认；未创建新安全组。

## 发现并修复的问题

2022 和 2019 首次运行在依赖安装阶段失败，尚未注册服务。CI 包装脚本在 `$ErrorActionPreference='Stop'` 下用 `2>&1` 合并原生命令错误流；Windows PowerShell 5.1 在此组合下会把 pip 提示提升为终止错误。`scripts/ci/install-service.ps1` 已保留独立错误流，原安装器的退出码检查继续生效。2022／2019 修正后重测通过，2016 使用相同修正通过；兼容矩阵依据通过的重测结果。

## 复现步骤

使用表中官方英文 x64 镜像创建隔离 CVM，启用 TAT，安装机器级 Python 3.13.7，下载并核对 WinSW。设置 `RUNNER_TEMP`、`GITHUB_WORKSPACE`、`INSTALL_DIR`、`WINSW_URL`、`WINSW_SHA256` 和 Python `PATH`，依次执行仓库脚本：

1. `fetch-winsw.ps1`、`write-acceptance-settings.ps1`、`assert-tampered-winsw-refused.ps1`。
2. `install-service.ps1`、`assert-installer-acls.ps1`、`assert-readiness-probe.ps1`、`assert-tampered-form-refused.ps1`。
3. 重启 `PSMTencentCloudSTS`，等待就绪，再执行 `assert-readiness-probe.ps1`。
4. `assert-uninstall-preserves-files.ps1`。
5. 保留脱敏证据，销毁临时 CVM，并确认销毁完成。

## 尚需验收

IIS／ARR、Windows 身份认证、TLS、原生 PSM 组件启动、浏览器控制台登录、会话隔离、录屏回放和 PSM 浏览器清理尚未测试。生产部署仍必须符合实际 PSM／Connector 的官方 OS 支持矩阵。原版 Windows Server 2012 及更早版本、桌面 Windows、Server Core、ARM64 不在本次范围内。

## 2012 R2 与原版 2012 补测

2012 R2 已通过全部 Bridge 检查。TAT 首次返回 `START_FAILED`，原因是镜像上不存在默认工作目录；重试显式指定 `WorkingDirectory=C:\` 后通过。测试编排使用 .NET `ZipFile` 解压源码；实际系统为 Windows PowerShell 5.1，未测试更旧的 PowerShell。R2 临时实例已销毁，独立 CVM 查询确认实例已不存在。

原版 Windows Server 2012（非 R2）尚无法实测：完整分页查询新加坡、香港、东京公共镜像，以及账号新加坡区可见镜像，均只找到 R2。这是指定地域的镜像可用性结果，不代表全球无此镜像或插件不兼容。继续测试需要获授权的原版自定义／共享镜像 ID 和地域；不得把 R2 结果用于原版 2012。
