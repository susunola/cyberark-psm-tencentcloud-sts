# 原生运维、定时维护和共享令牌

[English](OPERATIONS.md) | **简体中文**

## 客户机 CPM 与 PSM

以下接口调用已安装的 CyberArk 原生组件。Windows/Linux 客户机账户必须已配置经过验证的平台；对账还需配置原生 reconcile 账户。写操作默认不执行。

```text
python scripts/pamctl.py cpm --account 1_2 --action Verify --safe CloudGuests --platform UnixSSH
python scripts/pamctl.py cpm --account 1_2 --action Change --safe CloudGuests --platform UnixSSH
python scripts/pamctl.py cpm --account 1_2 --action Reconcile --safe CloudGuests --platform UnixSSH
python scripts/pamctl.py status --account 1_2
python scripts/pamctl.py connect --account 1_2 --component PSM-SSH --reason "Approved maintenance" --ticket-id CHG1 --ticket-system ServiceNow --out connection.json
python scripts/pamctl.py recording --id recording-123 --section activities
python scripts/pamctl.py recording --id recording-123 --section valid
python scripts/pamctl.py playback --id recording-123 --out playback.json
```

审核范围与原生策略后添加 `--apply`。CPM 返回 `submitted-to-CPM` 只表示异步任务已提交，不能当成改密成功；后续查看 `status` 与原生 CPM 日志。客户机 CPM 命令拒绝 CAM 密钥配对账户，后者使用两阶段轮换。

连接与播放响应仅写入独占文件，不输出到终端；按目标版本配置交给原生 PSM 客户端/播放器。非 JSON 连接响应拒绝解析。工具不自动执行 RDP 文件、跟随播放 URL、下载视频或绕过审批/工单策略。响应可能包含短期认证材料：Unix 文件权限为 0600；Windows 必须使用只授权操作者/系统的目录 ACL。使用后按策略清理。接口或落盘失败可能留下空/部分文件，重试前先检查。

`capabilities` 现在只读探测 Accounts、LiveSessions、Recordings、IncomingRequests、MyRequests，区分认证、权限、隐藏/缺失接口及其他失败。404 不等于确定不支持；可读也不证明可写、组件已安装或全版本兼容。

## 中断轮换的恢复

```text
python scripts/pamctl.py recover-ticket --journal rotation.json --ticket rotation-recovered.json
```

添加 `--apply` 后只读取云和 Vault，要求操作描述对应唯一启用的新密钥、唯一已保存新账户、Safe/平台/用户名/地址一致，并核验新凭据的主体身份。恢复票据仅含标识，不创建新密钥、不停用旧密钥；随后按正常流程完成真实 PSM 切换验收再 finalize。

Vault 保存缺失或存在歧义时不能自动恢复：腾讯云清单无法重新读取已生成的 SecretKey。保留旧可用密钥，按变更流程对账。0.3.0 旧日志缺少账户/角色范围字段，需要人工对账。

## 定时维护

`deployment/maintenance.example.json` 只包含非秘密配置。`verify-cam` 从 Vault 获取授权凭据，验证目标 UIN 与指定角色 AssumeRole；`prepare-key` 只准备替换，等待后续验收。每项作业固定 Safe、平台、角色与调用密钥白名单。未知操作及自动 finalize 均被拒绝。

```text
python scripts/run_maintenance.py --jobs maintenance.json --settings settings.json --state-dir maintenance-state
```

默认不执行；预先建立受保护状态目录、审核配置后添加 `--apply`。企业调度器应通过受保护包装程序，在每次运行前取得新 PVWA 会话和云凭据；不把令牌/密钥放进任务参数或配置文件。客户机周期改密使用原生 CPM 平台调度。

同一状态目录只允许一个运行实例。崩溃锁不自动抢占，确认进程与写入结果后才能清理。prepare 作业保留日志/票据，同一 ID 再次运行会被拒绝；切换完成并审核保留策略后再归档。失败停止后续作业，不确定写入保留恢复日志。同一 UIN 只使用一个调度权威，文件锁不是分布式云锁。定时作业不自动停用旧密钥，也不宣称浏览器/录屏验收通过。

## 多节点共享令牌

默认使用单进程内存令牌。多节点使用 Redis 7+、TLS、ACL、相同会话签名密钥和独立部署命名空间；各节点 IIS 认证和代理密钥仍独立保护。所有节点需采用一致的认证身份格式和角色配置；STS 并发上限仍是每节点两个。

设置无查询参数的 `PSM_TC_REDIS_URL=rediss://...`，可选可信 CA 文件 `PSM_TC_REDIS_CA_BUNDLE` 和独立 `PSM_TC_REDIS_NAMESPACE`。也可令 `PSM_TC_SHARED_CONFIG` 指向基于 `deployment/shared-secrets.example.json` 的受保护配置，使用其中的集群会话密钥。示例必须替换凭据并生成独立随机密钥，实际文件不要提交 Git。

```powershell
.\scripts\Configure-SharedTokens.ps1 -InstallDir C:\PSM-TencentCloud -SharedSettingsFile C:\Protected\shared-secrets.json
```

默认不修改。先停止接收新连接，再添加 `-Apply -Restart`：验证 Redis/TLS、以受限 ACL 复制配置、更新 WinSW 服务。CA 文件必须能被 LocalService 读取。服务 XML 先禁用 DTD 预检，再持有独占更新锁进行原子替换。实际秘密文件与备份不覆盖；崩溃锁需检查后清理。旧 XML 备份到受保护安装目录的 `PSMTencentCloudSTS.xml.before-shared`。部分失败时检查服务和配置，必要时恢复备份与原令牌模式。脚本仅完成语法检查，未在目标 PSM 实机执行。

Lua 使用 Redis 服务端时间，限制共享令牌总容量，并在主节点原子验证身份、过期和消费。只存令牌/身份摘要。Redis 故障返回 503，无本地回退，不自动重试消费结果不确定的请求；带代理认证的 `/healthz` 检测 Redis。更换会话密钥会使待提交表单失效，需重新发起连接。

**故障转移边界：** 主节点原子操作不等于异步复制切换或备份恢复后的“恰好一次”。状态回退可能恢复已消费令牌。恢复流量前必须协调更换所有节点的共享会话密钥，使旧连接失效；不将旧令牌备份恢复进活跃集群。负载均衡健康检查不能隔离旧 Redis 主节点，需要单写主节点与协调切换流程。生产 TLS、ACL、复制隔离和负载均衡仍需现场验收。

独立 CI 使用真实 Redis 7.2.5 验证跨节点消费、并发重放、服务端过期、容量、摘要存储和跨应用实例提交表单。TLS 参数与故障关闭使用单元测试；CI Redis 为本机明文连接，不能当成生产 TLS 验收。

接口依据：[CyberArk 官方模块](https://github.com/cyberark/epv-api-scripts/tree/main/EPV-API-Common)、[Redis Lua](https://redis.io/docs/latest/develop/programmability/eval-intro/)、[redis-py 生产配置](https://redis.io/docs/latest/develop/clients/redis-py/produsage/)。

## 输入与轮换检查（0.4.1）

任何远端作业开始前，完整检查清单中的 ID、UIN、账户与角色语法，拒绝同一 UIN 的别名及大小写文件名冲突。Safe/平台/角色/白名单仍在各作业使用前动态核验，批量流程不是跨系统事务。纳管要求完整、有长度限制的字符串元数据和字符串凭据；CAM 密钥账户必须显式关闭原生自动管理。票据验证标识及不同的新旧配对。创建云密钥前检查旧账户字段；角色验证后再次检查密钥状态，停用后读取确认。读取确认失败（包括可能的状态一致性延迟）报告结果不确定，需对账，不自动重试。多次检查缩短竞态窗口，但云/Vault 独立操作无法变成原子事务，请串行处理目标变更。
