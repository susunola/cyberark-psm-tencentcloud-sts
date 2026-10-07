# 安装与使用手册

[English](INSTALLATION-AND-USAGE.md) | **简体中文** · [返回 README](../README.zh-CN.md)

适用源码版本：0.5.2。本文从首次部署到日常操作给出完整流程。目标是通过 CyberArk PVWA 授权，在 PSM 浏览器中使用 Vault 保存的 CAM 密钥登录腾讯云国际站控制台；CVM 客户机连接使用已安装的原生 SSH/RDP 组件。

本项目提供桥接服务及管理工具源码，不提供可直接导入的原生平台/CPM ZIP。自动化验证覆盖 Windows/Ubuntu、Python 3.11–3.14，以及真实 Redis 的共享令牌行为；目标 PSM 上的服务运行、腾讯云登录、录屏和审批仍须现场验收。不能把源码测试通过理解为全版本认证。[交付边界](DELIVERY.zh-CN.md)和[验收记录](ACCEPTANCE.zh-CN.md)列明了这些状态。

## 目录

1. [架构与部署准备](#preparation)
2. [腾讯云和角色配置](#cloud)
3. [安装 Windows 服务](#install)
4. [配置 IIS HTTPS 代理](#proxy)
5. [配置 PVWA 和 PSM](#pam)
6. [用户如何连接](#use)
7. [管理工具与完整命令表](#admin)
8. [密钥轮换与失败恢复](#rotation)
9. [定时维护和多节点部署](#advanced)
10. [升级、回滚、卸载](#maintenance)
11. [排错和验收](#troubleshooting)

<a id="preparation"></a>
## 1. 架构与部署准备

```text
用户 → PVWA（Safe 权限 / MFA / 审批 / 工单）
     → PSM Web 浏览器 → IIS HTTPS + Windows Authentication
     → 本机 127.0.0.1:8765 桥接服务 → 腾讯云 STS
     → 腾讯云角色登录回调 → 控制台
```

PVWA 控制连接授权，原生 PSM 控制浏览器隔离、录屏和退出清理，桥接服务负责凭据校验、角色白名单和 STS 登录。单独打开桥接网页不能替代 PVWA 授权。

准备以下资源：

| 资源 | 要求 / 用途 |
|---|---|
| 测试 PAM 环境 | 可管理 PVWA 平台、Safe 和连接组件；可验证 PSM Web 登录与录屏 |
| Windows PSM 主机 | 由管理员部署；先核对组织 PSM 加固基线是否允许新增服务和 IIS |
| Python | 机器级安装，LocalService 可执行；CI 覆盖 3.11–3.14 |
| WinSW | 管理员从可信来源取得并审核；提供可信 SHA256，不随源码提供 |
| IIS | Windows Authentication、URL Rewrite、ARR；独立 HTTPS 站点与受信任证书 |
| 腾讯云 | 专用 CAM 子用户、API 密钥、可登录控制台的普通 CAM 角色 |
| 网络与时间 | DNS、证书链、时间同步；桥接服务能访问国际站 STS；PSM 浏览器能访问腾讯云登录/控制台 |
| 管理工作站（可选） | 完整源码、独立 Python 环境、PVWA API 会话；执行纳管、审计、轮换 |

后端 8765 仅监听环回，不向远端开放。CVM SSH/RDP 需要 PSM 到客户机私网的相应端口；管理工具需要 PVWA/CAM/CVM HTTPS。Redis 多节点模式另需受控的 TLS 连接。按实际区域和组织网络策略核准地址，不使用公网开放全部端口的方式部署。

本文路径示例：源码 `C:\Admin\psm-tencentcloud-sts`，受保护配置 `C:\Protected\TencentPSM`，服务 `C:\PSM-TencentCloud`，HTTPS 地址 `https://psm-tc-bridge.internal/`。它们均需替换成现场值。**首次安装前不要创建服务目录**：安装器会创建它并设置 ACL。源码管理环境与服务运行环境是两个独立目录。

### 从 0.5.0 迁移到国际站

旧实现签名使用中国站主机。0.5.1 改为 `www.tencentcloud.com/login/roleAccessCallback`，仅允许 `https://console.tencentcloud.com/` 目的地址，显式调用 `sts.intl.tencentcloudapi.com`、`cam.intl.tencentcloudapi.com`、`cvm.intl.tencentcloudapi.com`。升级时一起更新配置、运行代码/CSP、Vault 地址元数据及网络白名单；排空连接后按升级流程操作。旧中国站目的地址会被启动校验拒绝。使用国际站账号密钥，并核对区域可用性；选择地理区域本身不会切换账号站点。依据为[国际站回调规范](https://www.tencentcloud.com/document/product/614/36997)和[STS API](https://www.tencentcloud.com/document/product/1150/49456)。回调文档标题标注 old scheme，通用控制台登录仍须现场验收。

<a id="cloud"></a>
## 2. 腾讯云和角色配置

1. 创建专用 CAM **子用户**，取得调用 API 的 SecretId/SecretKey。不同权限等级使用不同调用子用户或密钥绑定；不使用主账号密钥。
2. 创建普通 CAM 角色，开启其控制台登录能力；角色信任关系允许指定调用主体扮演。
3. 给调用主体授予针对该角色的 `sts:AssumeRole` 权限。参考 [权限示例](../cam-assume-policy.example.json)，替换账号、角色后按腾讯云策略格式审核。角色信任与调用权限两侧都要允许。
4. 给目标角色授予业务权限，第一次验收使用只读权限。桥接服务不会自动创建角色或放宽云端 MFA、网络、登录策略。
5. 记录角色 ARN、调用子用户 UIN、SecretId。SecretKey 后续保存到 Vault 密码字段，不放进桥接配置。

在受保护目录复制 [配置模板](../settings.example.json) 为 `settings.json`：

```json
{
  "profiles": {
    "tc-readonly": {
      "role_arn": "qcs::cam::uin/100000000001:roleName/PSMReadOnly",
      "allowed_secret_ids": ["REPLACE_WITH_BROKER_CAM_SECRET_ID"],
      "destination": "https://console.tencentcloud.com/",
      "duration_seconds": 300,
      "region": "ap-singapore"
    }
  }
}
```

替换示例账号、角色和 SecretId；`REPLACE` 占位值会被校验拒绝。`tc-readonly` 是配置键，必须与 Vault 的 `TencentRoleProfile` 完全一致。每个 SecretId 只能出现在一个 profile 中；轮换时同一 profile 可暂时包含新旧 SecretId。目的地址限腾讯云控制台 HTTPS；当前仅支持国际站普通角色。300 秒是临时凭据申请时长，不代表控制台 Cookie 或 PSM 会话时长。

从源码目录执行离线校验（不连接腾讯云、不读取 SecretKey）：

```powershell
Set-Location C:\Admin\psm-tencentcloud-sts
& 'C:\Python313\python.exe' .\scripts\check_config.py C:\Protected\TencentPSM\settings.json
```

输出成功并且退出码为 0 后再安装。未知字段、重复 JSON 键、无效角色或跨 profile 重复 SecretId 应先修正。

<a id="install"></a>
## 3. 安装 Windows 服务

在源码目录打开**管理员 PowerShell**。确认 Python、WinSW 文件路径存在，校验配置成功，服务目录不存在。把下方 64 位摘要占位符替换为经可信来源确认的 WinSW SHA256；仅计算本地下载文件摘要并不能证明来源可信。

```powershell
Set-Location C:\Admin\psm-tencentcloud-sts
.\scripts\Install-Bridge.ps1 `
  -PythonExe 'C:\Python313\python.exe' `
  -WinSWExe 'C:\Admin\tools\WinSW-x64.exe' `
  -WinSWSha256 'REPLACE_WITH_VERIFIED_64_HEX_SHA256' `
  -SettingsFile 'C:\Protected\TencentPSM\settings.json' `
  -InstallDir 'C:\PSM-TencentCloud'
```

安装器校验 WinSW 摘要，创建 venv，安装锁定依赖，复制最小运行代码和配置，生成两个独立随机秘密，注册并启动 `PSMTencentCloudSTS` 服务，并以受信任头验证本机 `/healthz` 就绪。首次安装需要可用的依赖源；隔离网络须按组织流程提供审核过的包源，避免临时改用未知镜像。

| 安装结果 | 说明 |
|---|---|
| `venv\Scripts\python.exe` | 服务使用的独立 Python 环境 |
| `settings.json` | 角色/SecretId 白名单，不含 CAM SecretKey |
| `PSMTencentCloudSTS.exe` / `.xml` | WinSW 和服务配置；XML 含代理密钥与会话签名密钥 |
| `web.config.generated` | 将代理密钥带入 IIS 的模板；含秘密，权限收紧为仅 SYSTEM/管理员，复制到站点后应从安装目录删除 |
| `logs` | 服务运行日志，LocalService 可写 |
| `pam\__init__.py` / `pam\audit.py` | 最小运行依赖；完整管理工具和测试不复制到服务目录 |

服务以 `NT AUTHORITY\LocalService` 运行，安装目录允许它读取运行代码，日志目录允许写入；普通会话账户不能修改服务代码、配置和秘密。不要将整个安装目录作为 IIS 网站根目录。不要把 XML、生成的代理配置、共享秘密或含凭据的诊断输出提交 Git。

```powershell
Get-Service PSMTencentCloudSTS
```

预期为 `Running`。安装失败时脚本尝试撤销已注册服务，并保留受保护文件用于诊断；不要删除文件后盲目重复安装，先查日志、目录和服务状态。现有目录安装会被拒绝，升级使用第 10 节流程。

<a id="proxy"></a>
## 4. 配置 IIS HTTPS 代理

1. 在 PSM 上准备独立站点根目录，仅存放网站所需配置；为管理员和该站点应用池身份设置合适 ACL。
2. 安装/启用组织批准的 IIS Windows Authentication、URL Rewrite 和 ARR。启用该代理所需 ARR 转发能力；避免修改其他站点的策略。
3. 绑定受信任 HTTPS 证书和内部 FQDN；让 PSM 浏览器能解析并信任该地址。
4. 站点关闭匿名访问、启用 Windows Authentication，仅允许批准的 PSM 会话身份访问。实际集成认证身份需要现场确认。
5. 将安装生成的 `web.config.generated` 受控复制为站点 `web.config`。按照 [代理模板](../deployment/web.config.template) 在适当 IIS 配置范围允许设置 `HTTP_X_PSM_BRIDGE_KEY` 和 `HTTP_X_PSM_AUTHENTICATED_USER`。
6. 确认重写规则把浏览器传入的两项头**覆盖**为服务私密代理密钥和 IIS 已认证的 `{REMOTE_USER}`，固定转发到 `http://127.0.0.1:8765`；不能信任浏览器提供的身份。需要在现场验证 `REMOTE_USER` 在所用 IIS 管线/重写阶段确实可用；没有身份时应拒绝请求。
7. 不记录 POST 正文、Cookie、响应 Location 和完整角色回调 URL；不缓存登录响应。确认代理不会改写腾讯云外部重定向的目标地址。

验证结果：

| 检查 | 预期 |
|---|---|
| 未认证访问 HTTPS 根路径 | 401/403，不能看到可用登录表单 |
| 未认证伪造两项代理头 | 仍然 401/403 |
| 无可信头直连 `127.0.0.1:8765/` | 403 |
| 授权身份经 HTTPS 访问 `/healthz` | 200，`status` 为 `ok` |
| 授权身份经 HTTPS 访问 `/` | 表单加载，浏览器侧始终为 HTTPS |

健康检查不证明腾讯云登录成功。代理密钥不提供给用户，也不通过命令行例子打印出来。不要为排错启用 Flask debug 或记录完整请求。

<a id="pam"></a>
## 5. 配置 PVWA 和 PSM

菜单名称和属性语法取决于安装版本。以下是要完成的配置事项；使用目标版本自带的 Web 应用示例和管理文档，不导入臆造的跨版本平台包。

1. 复制本版本 Web 应用连接组件，命名 `PSM-TencentCloud-STS`。保留原生支持的浏览器、驱动、启动程序、PID 上报、录屏和退出处理。
2. 将 `LogonURL` 设置为已完成认证代理的 HTTPS 根地址。
3. 创建/复制适用的 API 凭据平台，关联该组件；新增精确属性名 `TencentSecretId`、`TencentRoleProfile`。
4. 在指定 Safe 中建立账号：`TencentSecretId` = 专用 CAM SecretId；`TencentRoleProfile` = `tc-readonly`；密码字段 = 对应 CAM SecretKey。账号用户名/地址作为受控管理元数据保存，不能代替 SecretId 属性。
5. CAM 密钥账号不能直接套用客户机密码轮换；未部署经过验证的原生 CAM CPM 时关闭该账号的自动密码管理。本工具采用第 8 节两阶段密钥轮换。
6. 按 [WebFormFields 模板](../WebFormFields.template.txt) 设置并核对本版本展开语法：

```text
secret_id > {TencentSecretId} (searchby=id)
secret_key > {Password} (searchby=id)
profile > {TencentRoleProfile} (searchby=id)
audit_label > {ClientUserName} (searchby=id)
connect_button > (Button) (searchby=id)
```

7. 保留桥接表单的隐藏 CSRF 字段，让浏览器正常提交；不要自行固定或复用令牌。
8. 在 Safe/平台上给申请人配置原生账号使用和 PSM 连接权限，按策略设置 MFA、双人审批和工单要求。禁止普通用户任意覆盖 SecretId/profile/目的地址；审批人权限独立配置。
9. 配置并验证腾讯云控制台成功登录判定；桥接页面出现或收到 303 不能作为登录完成依据。
10. 用真实 PSM 会话验证：角色正确、业务权限符合预期、录像可回放、超时/退出清理浏览器、不同用户 Cookie 隔离。验收后再由目标 PVWA 导出平台/组件包。

`ClientUserName` 仅是云端审计标签来源，不能独立证明实际操作者；代理身份也可能是 PSM 服务/会话账户。应通过 PSM 原生记录、桥接请求 ID 和角色会话名关联审计。

<a id="use"></a>
## 6. 用户如何连接

1. 登录 PVWA，按组织要求完成 MFA。
2. 找到有使用权限的腾讯云账号；若需审批，提交原因、工单和允许时间，等待原生审批生效。
3. 选择 `PSM-TencentCloud-STS` 发起连接，使用组织提供的 PSM 客户端/浏览器流程。
4. PSM 注入 Vault 密钥和 profile；桥接服务调用 STS 后进入腾讯云控制台。用户不需要在桥接页输入或查看密钥。
5. 确认控制台显示预期角色及权限，再执行批准的工作。失败时记录时间、账号 ID 和请求 ID，交管理员处理；不要截图完整回调地址。
6. 完成后按 PSM 正常退出。关闭 PSM 会话不会撤销已签发的云凭据，也不保证控制台全局登出；云端会话寿命和访问限制单独验收。

连接 CVM 客户机时，在 PVWA 选择纳管的 Windows/Linux 客户机账号，分别使用已验证的 `PSM-RDP` / `PSM-SSH`。客户机密码/SSH 凭据与 CAM API 密钥是不同账号，不能互换。

<a id="admin"></a>
## 7. 管理工具与完整命令表

### 7.1 准备管理环境

管理命令在**完整源码目录**执行；安装器创建的服务目录没有完整 `scripts` 和 `tests`。在受保护管理工作站建立独立环境：

```powershell
Set-Location C:\Admin\psm-tencentcloud-sts
& 'C:\Python313\python.exe' -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r requirements.lock.txt
& .\.venv\Scripts\python.exe scripts\pamctl.py --help
& .\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

后续命令表中的 `python` 指该管理环境解释器。CI Redis 集成用例需要单独服务和对应环境；本地默认测试可能跳过这些用例。

| 环境变量 | 使用场景 |
|---|---|
| `PVWA_API_URL` | PVWA API HTTPS 根路径，例如 `https://pvwa.internal/PasswordVault/API` |
| `PVWA_TOKEN` | 已通过组织登录/MFA 策略取得、仍有效且有相应权限的 API 会话 |
| `PVWA_CA_BUNDLE` | 可选，内部 CA 文件路径；不关闭证书验证 |
| `TENCENTCLOUD_SECRET_ID` / `TENCENTCLOUD_SECRET_KEY` | 发现/轮换/维护所需的管理主体，由批准的秘密提供程序注入 |

可以设置不含秘密的 URL；秘密由现有批准流程注入进程环境，不能写进示例命令、Git、任务参数或日志。工具不实现绕过 MFA 的登录，不把无效会话自动降级为其他认证。管理主体与控制台 AssumeRole 调用主体应按各自权限管理。

所有修改操作默认返回 `no-write`，必须明确添加 `--apply` 才执行。**默认模式只是禁止写入，不是远端执行计划**：不会读取秘密 stdin，也不会验证远端对象或写权限。`--help` 可查看每个子命令参数。读取命令也受 PVWA 原生权限控制。

### 7.2 查询、连接、审批与会话

以下 ID、Safe、平台和工单均为示例，先替换真实值。修改命令表中未加 `--apply`，审核后才添加。

| 目的 | 命令 |
|---|---|
| 探测可读接口 | `python scripts/pamctl.py capabilities` |
| 检查账号/组件/配置绑定 | `python scripts/pamctl.py preflight --account 1_2 --safe CloudConsole --platform TencentAPI --component PSM-TencentCloud-STS --settings C:\Protected\TencentPSM\settings.json` |
| 列表 | `python scripts/pamctl.py list Accounts --limit 100 --offset 0` |
| 原生账号状态 | `python scripts/pamctl.py status --account 1_2` |
| 请求连接 | `python scripts/pamctl.py connect --account 1_2 --component PSM-TencentCloud-STS --reason "Approved maintenance" --ticket-id CHG1 --ticket-system ServiceNow --out C:\Protected\TencentPSM\connection.json` |
| 请求审批 | `python scripts/pamctl.py request --account 1_2 --component PSM-TencentCloud-STS --reason "Approved maintenance" --ticket-id CHG1 --ticket-system ServiceNow` |
| 查看申请 | `python scripts/pamctl.py request-info --id REQUEST_ID`；审批人查看加 `--incoming` |
| 审批决定 | `python scripts/pamctl.py decision --id REQUEST_ID --decision confirm --reason "Approved scope"`；拒绝使用 `reject` |
| 撤销自己的申请 | `python scripts/pamctl.py cancel-request --id REQUEST_ID` |
| 会话详情 | `python scripts/pamctl.py session-info --id SESSION_ID --section details` |
| 会话控制 | `python scripts/pamctl.py session --id SESSION_ID --action terminate`；也支持 `suspend` / `resume` |
| 录像元数据 | `python scripts/pamctl.py recording --id RECORDING_ID --section details`；支持 `activities` / `properties` / `valid` |
| 取得原生播放响应 | `python scripts/pamctl.py playback --id RECORDING_ID --out C:\Protected\TencentPSM\playback.json` |

`list` 还支持 `LiveSessions`、`Recordings`、`IncomingRequests`、`MyRequests`；后两项使用原生请求接口，不承诺 offset 分页。申请时间限制使用成对的 `--from-date` / `--to-date`，单位为 UTC Unix 秒，结束大于开始，并与批准窗口一致。原生权限和审批最终决定能否执行，工具不会自动批准。

连接/播放响应保存到**不覆盖已有文件**的受保护 JSON 文件，由现场原生客户端/播放器使用；工具不会自动启动 RDP、打开播放 URL 或下载录像。响应可能包含临时认证材料，Windows 目录需管理员/授权操作员专属 ACL，用后按保留策略清理。原生接口非 JSON 的启动格式会被拒绝，需要目标版本适配。

### 7.3 发现、纳管与客户机 CPM

```text
python scripts/pamctl.py discover --regions ap-singapore ap-hongkong
python scripts/pamctl.py cvm-plan --inventory inventory.json --usernames usernames.json --safe CloudGuests --linux-platform UnixSSH --windows-platform WinServerLocal
python scripts/pamctl.py cpm --account 2_3 --action Verify --safe CloudGuests --platform UnixSSH
python scripts/pamctl.py cpm --account 2_3 --action Change --safe CloudGuests --platform UnixSSH
python scripts/pamctl.py cpm --account 2_3 --action Reconcile --safe CloudGuests --platform UnixSSH
```

发现结果为 CAM/CVM 元数据，不含客户机密码；如保存输出，先保护目标目录。`usernames.json` 是实例 ID 到实际已核实用户名的映射，例如 `{"ins-example":"opsuser"}`；不能凭操作系统推断可用账号。计划采用私网地址并跳过未知操作系统，不会生成密码或自动关联组件。

纳管输入为完整账号 JSON，通过安全 stdin 提供，不把密码写进参数。最小字段为 `name`、`address`、`userName`、`platformId`、`safeName`、`secretType`（`password`）、`secret`；平台属性使用 `platformAccountProperties`。CAM 账号同时设置两个腾讯云属性，并在 `secretManagement` 中明确 `automaticManagementEnabled: false`。以下命令只演示非秘密参数：

```text
python scripts/pamctl.py onboard --safe CloudGuests --platform UnixSSH --apply
python scripts/pamctl.py onboard-batch --safe CloudGuests --platform UnixSSH --journal C:\Protected\TencentPSM\onboarding.jsonl --apply
```

由批准的秘密提供程序把一个账号对象或完整账号数组流入 stdin；不要交互粘贴到可记录的终端。批量最多 100 个账号、输入 1 MiB，先校验完整数组并检查 Safe 中同名账号；日志只保存操作元数据。若日志有尝试但没有确认，远端账号可能已创建，先核对 PVWA 再恢复，不能换个日志文件直接重复整批。

原生 CPM 的 `submitted-to-CPM` 仅表示提交，不表示完成；查询账号状态和原生 CPM 日志确认结果。Reconcile 需配置原生协调账号。CAM 密钥账号会被客户机 CPM 命令拒绝。

独立身份校验：`python scripts/pamctl.py verify --target-uin 100000000002` 从批准的安全 stdin 接收包含 `secret_id` 和 `secret_key` 的 JSON 对象。它通过国际站身份接口核对调用者 UIN，不证明控制台登录成功；该只读命令不需要 `--apply`。

发现限制为 20 个不重复且全部预校验的区域、1,000 个 CAM 用户、每区域 100 页、单次合计 10,000 个 CVM 实例。重复实例、不完整页或分页中总数变化会令整个命令失败，不返回“成功”的部分结果。库存变化稳定后重新执行只读发现；不承诺一致性快照。`ap-shanghai-fsi` 等后缀通过语法校验，但仍需云端确认账号/服务区域可用性。

### 7.4 导出与审计

```text
python scripts/pamctl.py export Accounts --out C:\Protected\TencentPSM\accounts.jsonl --limit 100 --max-pages 100
python scripts/pamctl.py audit-report --input C:\Protected\TencentPSM\bridge.log --max-lines 100000
```

导出还支持 `LiveSessions` / `Recordings`；最多 100 页，每页最多 100。成功文件最后一条包含 `export-completed` 和 `complete: true`；缺少结束记录的文件应视为不完整。导出不是事务快照。审计汇总统计状态/profile 和请求关联，不输出密钥、回调 URL 或任意身份字段；不能替代原生 PSM 录像和审计。

<a id="rotation"></a>
## 8. 密钥轮换与失败恢复

针对专用 CAM 子用户实施，维护同一目标 UIN 的单一变更负责人，避免并行修改云端和 Vault。轮换前确认旧密钥有效、Vault 账号元数据正确、子用户剩余密钥容量允许新增，以及管理主体权限符合范围。

```text
python scripts/pamctl.py prepare --old-account 1_2 --target-uin 100000000002 --profile tc-readonly --ticket C:\Protected\TencentPSM\rotation.json
```

审核后加 `--apply`。工具先独占创建日志，再建立并校验新密钥，保存为同 Safe/平台的新 Vault 账号，返回只含标识的票据；**不会停用旧密钥**。

1. 在桥接 `settings.json` 同一 profile 白名单添加新 SecretId，暂时保留旧值；离线校验后受控部署并重启服务。
2. 给替换 Vault 账号配置组件和使用权限。通过新账号真实 PSM 登录，验证角色、业务权限、审批、录屏和退出。
3. 成功后审核票据与目标配置，显式确认切换：

```text
python scripts/pamctl.py finalize --ticket C:\Protected\TencentPSM\rotation.json --settings C:\Protected\TencentPSM\settings.json --confirm-psm-cutover --apply
```

工具重新校验新旧绑定、身份、AssumeRole 与云端状态，停用旧密钥并读取状态确认。若请求或状态回读失败，结果可能不确定；先查实际密钥状态，不盲目重试。确认完成后移除旧白名单，按保留策略处理旧 Vault 账号和票据，不把已签发的临时云凭据视为已撤销。

准备过程被中断时：

```text
python scripts/pamctl.py recover-ticket --journal C:\Protected\TencentPSM\rotation.json --ticket C:\Protected\TencentPSM\rotation-recovered.json --apply
```

恢复要求云端和 Vault 各存在唯一匹配项，且新凭据身份/元数据正确；不创建新密钥、不停用旧密钥。若新 SecretKey 没成功保存到 Vault，腾讯云库存不能读回它，必须保留旧密钥并人工对账。

需要回退且旧密钥尚未删除时：

```text
python scripts/pamctl.py restore-old --ticket C:\Protected\TencentPSM\rotation.json --settings C:\Protected\TencentPSM\settings.json --apply
```

该命令会先复核 Vault 绑定、账号范围与桥接白名单，再重新启用并回读状态；它只恢复密钥状态，还需恢复相应 PVWA 权限并重新验收。已删除的密钥无法恢复。轮换期间不要手动删除旧密钥。

<a id="advanced"></a>
## 9. 定时维护和多节点部署

### 定时维护

复制 [维护模板](../deployment/maintenance.example.json)，填写真实账号、Safe、平台、目标子用户 UIN；profile 改为配置中的 `tc-readonly`。只支持 `verify-cam` 和 `prepare-key`。

```text
python scripts/run_maintenance.py --jobs maintenance.json --settings C:\Protected\TencentPSM\settings.json --state-dir C:\Protected\TencentPSM\maintenance-state
```

先审核，再加 `--apply`。调度器调用受保护包装程序，每次取得新的 PVWA 会话和管理密钥，不把秘密放进任务参数/清单。`prepare-key` 只准备新密钥，仍须第 8 节人工验收切换；不会自动 finalize。原生客户机密码轮换使用 CPM 自身计划。

状态目录独占锁不自动抢占；进程异常后先核对存活状态和远端结果。已有准备票据阻止同一 job 再次生成密钥，完成切换和保留审核后才归档。失败停止后续任务；该文件锁不是跨节点云端分布式锁。

### 多节点共享令牌

单节点默认进程内令牌。多节点准备 Redis 7+、TLS、ACL、单一可写主节点；各节点使用相同角色配置、namespace、会话签名密钥和代理身份格式。代理密钥可以按节点独立配置。STS 并发上限为每节点两个，并非集群全局限制。

从 [共享秘密模板](../deployment/shared-secrets.example.json) 创建受保护 JSON，替换 Redis 地址/认证信息、namespace 和随机共享 `session_key`；使用 `rediss://`，必要时提供 CA 文件。共享会话密钥独立于代理密钥；不要输出或提交该文件。CA 文件须 LocalService 可读。

```powershell
.\scripts\Configure-SharedTokens.ps1 `
  -InstallDir C:\PSM-TencentCloud `
  -SharedSettingsFile C:\Protected\TencentPSM\shared-secrets.json
```

默认不修改。排空连接并审核后添加 `-Apply -Restart`；脚本验证 Redis/TLS、保护复制文件、独占锁定并原子更新服务 XML，原始 XML 备份为 `.xml.before-shared`。已有共享文件、锁或备份不会覆盖；部分失败需先核对文件与服务状态，必要时恢复受保护备份。

Redis 失败时拒绝请求（503），不回退本地令牌。异步副本切换/恢复备份可能使已消费令牌重新出现：恢复流量前在所有节点轮换共享会话密钥，废弃待处理连接，确认主节点隔离和唯一写入。不能把原子 Lua 执行理解为跨异步故障切换的绝对一次保证。生产 TLS、负载均衡和故障切换需要现场验收，见[共享令牌运维说明](OPERATIONS.zh-CN.md)。

<a id="maintenance"></a>
## 10. 升级、回滚、卸载

**升级：**排空 PSM 连接，受保护备份运行代码、venv、角色配置、服务 XML、IIS 配置、共享秘密/CA 和日志；记录当前版本与校验值。先在测试环境验证新源码和配置，再停止服务，在维护窗口更新运行文件与依赖；必须包含 `pam/__init__.py`、`pam/audit.py`。保留现有随机秘密和 ACL，不对现有目录重复运行首次安装器。启动后核对 `/healthz`、真实登录、录像和清理；多节点分批升级前先验证共享协议兼容性。

**回滚：**停止服务，恢复同一备份版本的代码/venv/配置及权限，按受控方案恢复代理配置；启动后重新验收。若修改过共享会话密钥或 Redis 状态，协调全部节点并废弃旧表单。代码回滚不会撤销云端凭据，也不会自动撤销已完成的云端/Vault 操作。

**卸载：**在管理员 PowerShell 从完整源码执行：

```powershell
.\scripts\Uninstall-Bridge.ps1 -InstallDir C:\PSM-TencentCloud
```

脚本停止/卸载服务，保留文件供保留审计和人工清理。分别处理 PVWA 组件关联、IIS 专用站点、云端密钥及角色授权；先核对依赖，避免影响其他站点/账号。按组织策略销毁含秘密配置和连接响应文件。

<a id="troubleshooting"></a>
## 11. 排错和验收

| 现象 | 检查与处理 |
|---|---|
| 安装提示目录/服务存在 | 查看既有安装或失败残留；使用升级/恢复流程，先备份再处理 |
| WinSW 摘要不匹配 | 停止安装，重新核对可信发行文件与摘要 |
| 服务启动失败 | 配置离线校验；检查 Python/LocalService 权限、依赖、日志、CA 可读性和环回端口占用 |
| IIS 401/403 | 核对 Windows Authentication、匿名访问关闭、授权身份、证书和浏览器集成认证 |
| IIS 500 / 后端始终 403 | 查 ARR/Rewrite、允许的 server variables、REMOTE_USER 管线可用性和代理密钥一致性；不要用客户端身份头绕过 |
| 表单失效 / 429 | 表单单次且有效期 120 秒，容量有限；等待后从 PVWA 发起新连接，不重放原 POST |
| 503 / Retry-After | 检查每节点 STS 并发、Redis/TLS/健康检查；等待后发起新连接，禁止失败时绕过共享存储 |
| STS 拒绝 | 核对密钥状态、准确 SecretId/profile、角色信任、调用权限、云策略、DNS/时间/出站连接 |
| 已重定向但未登录 | 核对角色控制台登录资格、业务权限和云端策略；303 不代表登录成功 |
| PVWA API 401/403 | 更新过期会话，核对相应账号/Safe/审批权限；不关闭 MFA 或证书验证 |
| API 404 / 非 JSON 启动响应 | 可能为权限隐藏或版本差异，按目标版本适配；不能宣称接口不存在或全版本支持 |
| CPM 显示提交但密码没变 | 查询原生 CPM 状态/日志、目标连通性、平台及协调账号 |
| 轮换/批量纳管中断 | 保留日志，对账云端/Vault 实际结果；按恢复流程处理，禁止自动重复不确定写入 |
| 输出文件/共享备份已存在 | 工具有意拒绝覆盖，先核对文件内容和前次操作状态 |

管理 CLI：退出码 `0` 表示命令成功或 no-write；`2` 表示参数/运行失败或不完整；preflight 的 `3` 表示范围/绑定检查失败。preflight 的 `not_verified` 项仍需现场验证；可读接口探测不能证明写权限、组件安装或录屏可用。

验收至少记录：正确角色与权限；错误密钥/越权 profile 拒绝；匿名/伪造头/后端绕过拒绝；CSRF 重放和过期拒绝；双用户隔离；真实审批/工单；录像回放及退出清理；轮换新账号切换/旧密钥停用回读与回退；共享模式 TLS、故障关闭和协调故障切换；所有层日志没有长期密钥或完整临时回调 URL。使用 [验收记录](ACCEPTANCE.zh-CN.md)填写环境、证据和结果，再评估生产上线。

临时回调 URL 含临时凭据，Python 不保证内存清零；按组织 PSM 加固基线限制调试工具、剪贴板/文件通道及诊断访问。遇到问题收集时间、版本、账号 ID、请求 ID 和脱敏状态，不分享密钥、Cookie、token 或完整回调链接。

更多资料：[部署说明](DEPLOYMENT.zh-CN.md) · [运维说明](OPERATIONS.zh-CN.md) · [PAM 能力](PAM-CAPABILITIES.zh-CN.md) · [安全策略](../SECURITY.md)

源码质量检查还包括 `python scripts/check_docs.py` 和 `python -m pip check`。打包时在 ZIP/校验清单旁生成 `dependency-sbom.cdx.json`（CycloneDX 1.5），列明锁定源码依赖；不代表生产主机软件清单或已证明无漏洞。
