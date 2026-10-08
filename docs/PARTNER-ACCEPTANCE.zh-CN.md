# 合作伙伴授权实验室验收

[English](PARTNER-ACCEPTANCE.md)

## 适用方式与边界

由实验室持有人在自己的合法授权、隔离环境中安装插件并执行测试，只向项目返回脱敏证据，无需把许可证或 CyberArk 安装包交给开发者。本文是验收流程，不是已认证的原生平台导入包；源码测试通过不能证明某个 PAM 版本已兼容或获得官方支持。

预约前请实验室持有人确认：许可证允许此类测试、允许安装自定义 PSM 连接组件、具备 Windows PSM 主机管理权限。明确 PAM/PSM 版本及其官方支持的 Windows、浏览器版本。桥接服务的 Windows 测试矩阵不等于厂商支持矩阵。只使用隔离测试账号。

## 交付材料

从待验收的准确提交构建源码包：

```bash
python scripts/build_release.py --out dist
```

一并交付源码 ZIP、SHA256SUMS、依赖 SBOM，并另行记录 Git commit；开发版本不能只靠版本号定位。传输后核验哈希。源码包包含[安装手册](INSTALLATION-AND-USAGE.zh-CN.md)、[验收记录](ACCEPTANCE.zh-CN.md)、部署模板、测试和[结果模板](PARTNER-ACCEPTANCE-RESULTS.example.json)。不得打包本地配置、环境变量文件、令牌或完整回调 URL。

## 没有授权时可以先运行的测试

```bash
python -m unittest discover -s tests -p test_pvwa_https_contract.py -v
```

这组测试启动真实本地 HTTPS 服务，使用临时证书和虚构 PVWA 响应，通过实际 Requests 适配器验证证书信任、主机名校验、审批请求序列化、拒绝/重定向处理、失败写操作不重试，以及轮换恢复拒绝不完整查询。它不模拟真实 Vault、PSM 会话或录屏。需要 OpenSSL；跳过不等于通过。完整测试和 CI 还覆盖并发、轮换与异常场景。

## 实验室实施步骤

1. 建立独立测试 Safe、腾讯云国际站最小权限调用身份及只读角色。准备两个独立 Windows 人员身份和测试账号，用于隔离验证。真实密钥只保存在实验室管理的 Vault 中，提前确定资源清理负责人。
2. 按安装手册部署到官方支持的 PSM 主机。配置 IIS Windows 身份认证、匿名拒绝、转发身份/密钥请求头覆盖和后端 loopback 限制。按所安装 PSM 版本支持的流程导入或配置连接组件，保存脱敏后的配置导出和版本信息。
3. 通过实验室正常认证/MFA 流程获取 PVWA 会话。在私有 shell 设置 `PVWA_API_URL`、`PVWA_TOKEN`，必要时设置 `PVWA_CA_BUNDLE`，执行只读探测：

```bash
python scripts/pamctl.py capabilities
```

不支持的接口和权限拒绝应如实记录，不能当成通过。

4. 使用手册中的 preflight 命令核验账号、Safe、平台及 profile 绑定，审核结果后再执行写操作。按[验收步骤](ACCEPTANCE.zh-CN.md)完成下表项目。越权角色、审批绕过和凭据提取尝试应被拒绝。
5. 在实验室内关联桥接 request ID、角色会话名、PSM 录屏和腾讯云审计事件。返回脱敏引用，原始录屏和敏感证据由实验室保管。分别检查控制台 cookie 与 STS 生命周期；PSM 断开不能证明云凭据已经撤销。
6. 卸载桥接服务，只删除本次测试创建的账号、角色和资源，并核实不存在。记录配置/ACL 保留情况、浏览器进程清理和任何残留资源。PAM 安装介质与授权继续由实验室负责。

## 必测项目

| ID | 项目 | 通过所需证据 |
|---|---|---|
| AUTH-01 | 匿名、伪造请求头拒绝 | 脱敏状态码、IIS 身份认证及配置证据 |
| LOGIN-01 | PSM 授权控制台登录 | PAM/PSM/浏览器版本、组件修订、目标及实际测试身份 |
| DENY-01 | 错误/禁用密钥、越权角色拒绝 | 拒绝记录及没有可用登录的证据 |
| REPLAY-01 | CSRF 重放、重复字段拒绝 | 状态码及关联审计引用 |
| ISOLATE-01 | 双用户顺序/并发隔离 | 独立身份、cookie、进程和角色会话名 |
| RECORD-01 | 录屏回放与审计关联 | 实验室保存的录屏引用和关联证据 |
| CLEANUP-01 | 注销、断开、超时 | 进程清理、录屏可用性、实际 cookie/STS 行为 |
| SECRET-01 | 凭据暴露检查 | 进程参数、浏览器、代理/服务日志和回调处理审查 |
| ROLLBACK-01 | 升级、回滚、卸载 | 版本哈希、配置/ACL 保留及就绪检查 |
| CPM-01 | 原生 CPM 完成状态（适用时） | 已安装平台/CPM 版本及任务完成状态；提交成功不等于执行成功 |

填写[结果模板](PARTNER-ACCEPTANCE-RESULTS.example.json)。未执行保留 `pending`；缺少前置条件用 `blocked`；观察到失败用 `failed`；不适用用 `not-applicable` 并说明原因。每个 `passed` 项必须引用实验室保留的证据。共享前去掉密钥、完整回调 URL、租户/账号标识及个人信息。合作伙伴验收通过只证明该具体环境的结果，不代表 CyberArk 官方认证或全版本兼容。
