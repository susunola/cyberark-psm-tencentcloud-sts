# PAM 能力与版本边界

[English](PAM-CAPABILITIES.md) | **简体中文**

0.3.0 在控制台桥接服务之外增加独立管理工具，使用腾讯云公开 SDK 和 PVWA REST，不依赖 CPM SDK。请在受保护的管理工作站运行，避免让 PSM 浏览器或桥接服务拥有密钥管理权限。尚未认证任何 CyberArk 版本：优先使用 `/PasswordVault/API` 的现代账户接口，只有旧接口的环境需要适配；接口或权限不支持时拒绝继续。`capabilities` 探测账户/会话/录屏/申请只读接口，不证明写权限或组件可用。

| 能力 | 已提供 | 边界 |
|---|---|---|
| 控制台登录 | STS 角色联邦、角色与调用密钥限制 | 腾讯云国际站；真实 PSM 验收待完成 |
| 密钥生命周期 | 验证、两阶段轮换、旧密钥恢复 | 外部管理流程；不是原生 CPM 包；支持定时准备但切换需验收 |
| 发现与纳管 | CAM 子用户/密钥元数据、分地域 CVM 分页、PVWA 纳管 | 不发现密码；需已有 Safe、平台和自定义属性 |
| SSH/RDP | 客户机账户规划及原生 PSMConnect 调用 | 需原生连接组件、网络及有效客户机凭据 |
| 审批 | 创建连接申请、列出申请、逐条批准/拒绝 | 双人审批、MFA、工单和审批权限由 PAM 控制 |
| 会话管理 | 列表、暂停、恢复、终止 | 依赖目标 PVWA/PSM 接口和操作者权限 |
| 录屏 | 录屏详情/活动/有效性及受保护播放响应 | 录制、保留和播放由 PSM 执行；不自行录制或导出视频 |
| 密码轮换/对账 | 触发原生 CPM 验证/改密/对账及查询状态 | 密钥重新启用不等于密码对账，也不能恢复已删除密钥 |
| Vault 权限、隔离、分析、灾备 | 对接原生 PAM 运维 | 不替代这些功能；默认本地令牌；可选 Redis 共享，故障转移有边界 |

0.4.0 补充原生 CPM/PSM/录屏操作、中断恢复、定时维护和可选 Redis 共享令牌。见[运维说明](OPERATIONS.zh-CN.md)。

## 环境与权限

在管理工作站的 Python 环境安装 `requirements.lock.txt`。通过获准的登录/MFA 流程取得 PVWA 会话令牌，设置 `PVWA_API_URL`（HTTPS，末尾 `/PasswordVault/API`）和 `PVWA_TOKEN`。可选 `PVWA_CA_BUNDLE` 指向可信 CA 文件。强制验证 TLS、禁止重定向、不使用环境代理/netrc；写请求不自动重试。

云端操作使用管理进程的 `TENCENTCLOUD_SECRET_ID` 和 `TENCENTCLOUD_SECRET_KEY`，由独立 CAM 子用户提供。发现需要 ListUsers/ListAccessKeys/DescribeInstances；轮换还需要目标子用户的 CreateAccessKey/UpdateAccessKey。桥接调用主体只需要 AssumeRole，不应持有上述管理权限。PVWA 权限限定到所需 Safe 和操作；申请者与审批者遵守企业双人控制要求。

环境变量只是输入通道，请使用获准的凭据提供方式，避免把凭据字面量写进 shell 历史，并在完成后清理进程环境。SecretKey 不通过命令行参数传递。清单、录屏元数据、申请和轮换票据含敏感标识，应保护且不提交 Git。

## 使用

```text
python scripts/pamctl.py capabilities
python scripts/pamctl.py discover --regions ap-guangzhou ap-shanghai
python scripts/pamctl.py cvm-plan --inventory inventory.json --usernames usernames.json --safe CloudGuests --linux-platform UnixSSH --windows-platform WinServerLocal
python scripts/pamctl.py list LiveSessions --limit 100 --offset 0
python scripts/pamctl.py list Recordings --limit 100 --offset 0
python scripts/pamctl.py list MyRequests
python scripts/pamctl.py list IncomingRequests
python scripts/pamctl.py request --account 1_2 --component PSM-SSH --reason "Approved maintenance"
python scripts/pamctl.py decision --id request-123 --decision confirm --reason "Reviewed scope"
python scripts/pamctl.py session --id session-123 --action suspend
```

写命令默认输出 `no-write`，不访问云或 Vault；确认参数后显式添加 `--apply` 才执行。这是防误写开关，不是完整执行预检。列表返回单页原生数据，会话和录屏用 `--offset` 翻页。审批前在 PVWA 查看申请详情，避免批量自动审批。终止 PSM 会话不会自动撤销已签发的腾讯云凭据或独立云端会话。

`usernames.json` 为实例 ID 到已确认客户机用户名的对象。规划选择首个私网 IP；系统未知、用户名或私网 IP 缺失时跳过。不开放网络、不猜密码。逐条审核后，通过安全 stdin 向 `onboard --safe CloudGuests --platform UnixSSH --apply` 提供含有效 `secret` 的账户对象。规划字段 `connection_component` 提交时移除；实际组件关联在原生平台配置。客户机 CPM 尚未验收时保持自动管理关闭。

## 两阶段密钥轮换

旧 Vault 账户的平台必须支持 `TencentSecretId`、`TencentRoleProfile` 属性。替换密钥创建独立账户，避免覆盖唯一可用凭据。同一目标 UIN 的操作应串行执行。

1. `prepare --old-account 1_2 --target-uin 123456789 --profile readonly --ticket rotation.json --apply`：先独占预留日志文件，保守检查双密钥容量、归属，创建并验证新密钥，将新配对保存到 Vault，保留旧密钥。只允许已列出的 CAM 子用户，拒绝管理根密钥。
2. 在同一桥接角色配置加入新 SecretId，先保留旧 ID；给新 Vault 账户配置原生权限和连接设置。使用新账户验证真实控制台登录、审批、录屏和角色权限。
3. `finalize --ticket rotation.json --settings settings.json --confirm-psm-cutover --apply`：确认上一步真实验收，再核验账户范围、密钥绑定、新主体和 AssumeRole 后停用旧密钥。程序不能代替人工确认浏览器登录与录屏结果。
4. 回滚使用 `restore-old --ticket rotation.json --settings settings.json --apply`，同时恢复 PVWA 访问并复测。该命令会复核 Vault 绑定、账号范围与桥接白名单并回读状态，目标上不恰好是那把轮换密钥对时会拒绝。密钥必须尚未删除。工具不提供密钥删除；后续清理由企业变更与保留策略执行。

以上命令均以 `python scripts/pamctl.py` 为前缀。成功票据仅含标识。失败可能只留下操作 ID 和 UIN；**不能删除日志后盲目重试**。按云端描述 `psm-rotation:<operation>`、Vault 名称 `tc-rotation-<operation>` 检查是否已写入，并记录对账结果。停用超时也可能已生效，应查询真实状态。避免把含 SecretKey 的原始响应写入日志；Python 不保证秘密内存彻底清零。

## 验证与生产门槛

离线测试验证默认禁写、TLS/重定向、请求结构、身份归属、旧密钥保留、写入结果不确定、范围变化、角色验证失败、恢复和客户机规划。CI 覆盖 Windows/Ubuntu 的 Python 3.11–3.14。SDK/PVWA 调用使用模拟，未执行真实腾讯云或 PAM 变更。

生产前仍需确认目标接口、平台属性、权限、PSM 连接框架，以及控制台/SSH/RDP、审批、录屏、轮换、回滚验收。公开接口降低版本依赖，但不等于全版本兼容。可直接导入的原生平台/CPM 包仍需针对目标版本打包和验收。

接口依据为 [CyberArk 官方 EPV API scripts](https://github.com/cyberark/epv-api-scripts/tree/main/EPV-API-Common)（该公共模块标为 Alpha，不随本包复制）、[腾讯云 CAM API](https://www.tencentcloud.com/document/api/598/37088) 和 [STS GetCallerIdentity](https://www.tencentcloud.com/document/product/1150/49453)。
