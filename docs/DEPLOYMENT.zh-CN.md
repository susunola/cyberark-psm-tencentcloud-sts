# 部署、升级与回滚

[English](DEPLOYMENT.md)

## Windows 部署兼容范围

下表描述本仓库的验证证据，不代表 CyberArk／Idira 认证。**目前没有任何 Windows 版本完成本组件的端到端 PSM 部署验收。**

| Windows 主机版本 | 仓库验证状态 | 部署条件 |
|---|---|---|
| Windows Server 2025 | `windows-2025` CI 覆盖 Python 3.11–3.14、源码测试及 PowerShell 语法/文件测试；另有 Python 3.13 作业执行 WinSW 安装、服务就绪、ACL 和卸载检查 | IIS 认证及真实 PSM 浏览器／会话仍需现场验收 |
| Windows Server 2022 | 未测试；可作为环境评估候选 | 先确认实际 PSM／Privilege Cloud Connector 版本的官方支持矩阵 |
| Windows Server 2019 | 未测试；可作为环境评估候选 | 同样需官方版本支持及完整现场验收 |
| Windows Server 2016 及更早版本 | 未测试，不声明兼容 | 本仓库不提供部署推荐 |
| Windows 10／11 | 未作为 PSM 部署主机验证 | 本仓库不声明支持其作为 PSM 生产主机 |
| Server Core／ARM64 | 未验证 | 不声明部署支持 |

部署采用能够运行原生 PSM 图形界面／浏览器的 Windows x64 主机。实际支持组合必须同时满足：对应 PSM／Connector 版本的官方 OS 矩阵、Python 3.11–3.14、经审核的 WinSW／IIS 组件，以及本插件现场验收结果。Windows 版本较新不等于 PSM 自动支持；PAM SaaS 也需具备相应客户侧 Connector／PSM 能力。

验收记录应填写 Windows 版本/edition/build、图形界面安装模式、PSM／Connector、浏览器及驱动、Python、PowerShell、WinSW、IIS／ARR／Rewrite 版本，并验证安装、服务重启、HTTPS 身份、云登录、录屏和退出清理。取得实测证据后才扩充支持矩阵。

先在与生产版本一致的测试 PSM 部署。需要服务账号可读取的机器级 Python 3.11–3.14、经核验的 WinSW 二进制及 SHA256、IIS Windows Authentication、URL Rewrite、ARR。WinSW 不随本包分发。安装脚本和代理模板尚待真实 Windows 环境验收。

1. 在管理员控制的目录解压代码，填写 `settings.json`。每个 SecretId 只能绑定一个角色配置；云端 SecretKey 保存在 Vault。
2. 执行 `python scripts/check_config.py settings.json`，校验配置，不调用云 API。
3. 管理员 PowerShell 执行：

```powershell
.\scripts\Install-Bridge.ps1 -PythonExe 'C:\Python312\python.exe' `
  -WinSWExe 'C:\Staging\WinSW.exe' -WinSWSha256 '<核验的64位SHA256>' `
  -SettingsFile 'C:\Staging\settings.json'
```

脚本创建 venv、安装锁定依赖、生成独立随机代理/会话密钥并存入受 ACL 保护的服务 XML，以专用虚拟账号安装并启动服务。失败保留诊断文件。不要启用捕获秘密变量的调试或脚本跟踪。

4. 创建独立的 IIS HTTPS 站点与物理目录，使用可信证书；启用 Windows 认证、禁用匿名访问、仅授权实际 PSM 会话身份。
5. 启用 ARR 代理，允许 Rewrite 服务变量 `HTTP_X_PSM_BRIDGE_KEY` 和 `HTTP_X_PSM_AUTHENTICATED_USER`。将安装目录的 `web.config.generated` 复制到专用站点为 `web.config`。安装器已把该文件权限收紧为仅 SYSTEM 与管理员可读，复制完成后请从安装目录删除它；站点副本仅授权管理员和该应用池身份读取。服务 XML 和配置不能放入站点目录。
6. 验证实际 IIS 管线在重写阶段能取得 `{REMOTE_USER}`。取不到应拒绝访问，不能信任浏览器提交的身份头。这是必须现场验证的项目。
7. 关闭请求正文、Cookie 和响应 Location 跟踪，限制访问及请求速率，确保 ARR 不改写云端重定向地址。
8. 认证后的 `/readyz`（以及仅在名称上被它取代的 `/healthz`）应返回 `ok`；对两者的匿名请求应由 IIS 返回 401/403，直连本机且不带代理密钥应返回后端 403，伪造身份头不能通过。`/livez` 是后端唯一允许无密钥访问的路由，只回答存活状态，因此允许监督进程直接探测本机回环；不要经 IIS 对外发布它。
9. 按 README 配置 PVWA，完成腾讯云真实登录、角色身份核对、隔离、录屏、退出和有效期验收。

升级前停止新连接，等待在途会话完成，备份受 ACL 保护的配置、服务 XML、IIS、代码及 venv。停止服务，在隔离目录安装/验证新版本，再替换代码与依赖，保留密钥和 ACL；启动后检查 health 和只读角色会话。安装器故意拒绝覆盖已有安装，不能在运行中的目录直接重装。重启会使未完成表单失效。

回滚：停止服务，恢复旧代码、venv、配置/服务 XML，检查 ACL 后启动。按需恢复专用 IIS 配置，再做 health 与只读会话检查。回滚不撤销已签发临时凭据。

卸载：管理员执行 `scripts/Uninstall-Bridge.ps1`，停止/删除服务但保留文件。另行禁用 PVWA 关联、移除专用 IIS 站点/规则、撤销不再使用的调用密钥和信任授权；满足审计保留要求后再删除文件。不要卸载其他站点共用的 IIS 模块。

排错：401 检查浏览器集成认证及实际 PSM Windows 身份；500.50 检查 Rewrite/ARR 和允许服务变量；403 检查代理密钥、身份头、环回来源和 CSRF；400 检查字段、角色绑定及审计标签；502 根据关联 ID 检查 STS 网络、密钥、角色信任和权限；云端登录失败检查时间同步、角色允许控制台登录及云端策略。录屏由 PSM 框架完成，桥接服务不能代替录屏。服务启动失败检查 Python/venv ACL、服务账号日志写权限和配置。

工单只附去敏诊断，不能附完整登录链接、Cookie、SecretKey、代理密钥、服务 XML 或原始请求正文。

0.5.0 运行服务还依赖 `pam/__init__.py`、`pam/audit.py`；升级根目录运行文件时同时部署这两个文件，见[交付清单](DELIVERY.zh-CN.md)。
