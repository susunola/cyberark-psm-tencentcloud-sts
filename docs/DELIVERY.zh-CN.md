# 交付清单 — 0.5.1

[English](DELIVERY.md) | **简体中文**

本仓库实现腾讯云国际站控制台联邦桥接和公开 API 管理工具，不是 CyberArk PAM 产品本身，也不是已认证的全版本原生平台包或 AWS 官方连接器等价包。以下清单区分实现功能、原生提供者能力和外部交付，模拟测试不当作生产验收。

| 领域 | 仓库已实现 | 原生/环境边界 |
|---|---|---|
| 控制台 | STS、角色/调用密钥白名单、认证代理、审计关联 | PSM 浏览器隔离、真实登录/录屏验收 |
| 密钥 | 验证、准备、验收后切换、恢复、中断票据恢复、定时验证/准备 | 未提供原生 CPM 引擎包；不自动 finalize/删除 |
| 发现 | CAM/CVM 分地域发现及客户机规划 | 客户机密码、网络和原生 SSH/RDP 组件 |
| 纳管 | 单条/批量、输入与范围检查、持久化写入日志 | 原生 Safe/平台/属性配置和权限 |
| 申请 | 创建、工单/时间窗口、申请详情、逐条审批/拒绝、本人申请删除 | 原生双人控制、MFA、工单策略及审批权限 |
| 会话 | 原生连接响应、详情/活动/属性、暂停/恢复/终止 | 原生客户端、组件及真实运行 |
| 录屏 | 目录/详情/活动/属性/有效性/播放响应 | 原生录制、保留、播放，不自建视频引擎 |
| 客户机密码 | 原生 CPM 验证/改密/对账触发及状态查询 | 已验证平台/对账账户，异步完成 |
| 导出 | 账户/会话/录屏有界分页 JSONL | 非事务一致性快照 |
| 审计 | UTC/版本字段、本地去重汇总 | 原生威胁分析及企业获准的 SIEM 传输 |
| 可用性 | TLS Redis、故障关闭、原子配置替换与备份 | 生产 TLS/ACL、主节点隔离与协调故障切换 |
| 预检 | 本地严格配置、账户绑定及只读接口检查 | 不证明写权限、已安装引擎、真实登录或兼容性 |
| 交付 | 默认英文/双语文档、CI、可重现 ZIP/SHA256 | 原生包验收、认证及官方提交 |

## 仍未完成的外部交付

1. **原生 CPM/PVWA 导入包：未提供。** 需要匹配实际安装环境的授权框架和导出的平台/组件格式。公开 REST/Python 源码不能替代该引擎或导入包；不包含专有 SDK/二进制，也不编造 process/INI 平台包。
2. **目标环境验收：未执行。** 包括真实腾讯云登录/轮换、PVWA/PSM/CPM、审批、录屏、Windows 服务、生产 TLS/ACL/故障切换。源码测试通过不证明这些能力在目标环境可用。
3. **版本认证与官方贡献：未取得/未提交。** 没有明确支持矩阵和实测证据，不能声称全版本兼容；Marketplace 协议与提交由所有者/客户完成。

Vault 权限、MFA、原生录屏、客户机密码协议、Safe 策略和 PAM 灾备应配置并验收原生能力，不应在插件内重新复制整套 PAM。腾讯云角色联邦覆盖国际站与中国站（`site` 成套选择控制台、回调签名主机及 STS/CAM/CVM 端点）；只有旧接口的 PVWA 适配不在范围。两站真实登录均需现场验收。

## 补齐的管理命令

所有示例以 `python scripts/pamctl.py` 为前缀，既有命令见[能力说明](PAM-CAPABILITIES.zh-CN.md)和[运维说明](OPERATIONS.zh-CN.md)。

```text
request --account 1_2 --component PSM-SSH --reason "Maintenance" --ticket-id CHG1 --ticket-system ServiceNow --from-date 1791331200 --to-date 1791334800
request-info --id request-123 --incoming
cancel-request --id request-123
session-info --id session-123 --section activities
export Accounts --out accounts-export.jsonl --limit 100 --max-pages 100
export LiveSessions --out sessions-export.jsonl
export Recordings --out recordings-export.jsonl
onboard-batch --safe CloudGuests --platform UnixSSH --journal batch-journal.jsonl
preflight --account 1_2 --safe TencentSafe --platform TencentSTS --component PSM-TencentCloud --settings settings.json
audit-report --input bridge.log --max-lines 100000
```

时间为 UTC Unix 秒，示例只展示语法，不是当前获批窗口。窗口两端及工单字段必须成对提供，原生策略仍有效。删除申请不终止已有会话或撤销云凭据。写操作需 `--apply`；默认禁写不请求网络。批准前查看原生申请详情，不自动审批。

导出写入独占受保护 JSONL；只有最后出现 `export-completed` 且 `complete: true` 才表示在指定边界内遍历完成。重复页、不一致空页、页数上限导致失败且没有完成标记。部分文件不是完整证据。工具不跟随响应中的下一页 URL，只向固定 PVWA 主机构造 offset。并发变化可能改变分页，因此不是时点备份。记录缓冲写入以降低磁盘开销，完成标记刷新并 fsync。

批量纳管从安全 stdin 接收完整账户数组，不把秘密放进参数或仓库。先验证全部条目/名称、查询已有 Safe/名称，再顺序创建。日志只保存元数据/ID，每次尝试与确认都刷新到磁盘。失败不自动重试或回滚；有尝试、无确认的账户可能已经创建，应按 Safe/名称查询对账，不能换一个日志文件盲目重跑整批。查询与创建间的原生竞态仍需注意。

预检仅只读，输出有限绑定/接口证据；范围/调用绑定失败退出码为 3。平台和组件列表接口可读，不证明组件已关联或引擎可运行。客户机检查范围，控制台账户另检查调用密钥/角色绑定。输出 `not_verified` 列明仍需现场验收的项目。

审计汇总按 request ID 去重，只输出状态和角色配置计数，不输出身份、URL、任意原始字段或凭据；输入超限报错。它是本地使用/错误统计，不替代原生威胁检测或录屏审计。保护输入/输出，按需选择不重叠日志集合。

## 升级注意

0.5.0 桥接服务新增 `pam.audit` 依赖：除根目录运行文件外，必须部署 **`pam/__init__.py`、`pam/audit.py`** 并保留受保护 ACL。安装器只复制该最小运行子集，不把管理/轮换代码部署到服务目录。已有环境按停服、隔离验证、备份/回滚步骤升级，不覆盖服务秘密；安装布局已通过独立子进程导入测试。
