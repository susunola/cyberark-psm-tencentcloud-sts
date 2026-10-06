# PSM-TencentCloud-STS

[English](README.md) | **简体中文**

给 CyberArk PSM 用的腾讯云国内站角色控制台登录桥。PSM 注入经纪 CAM 密钥，本进程调用 STS `AssumeRole`，再把签好的 `roleAccessCallback` 交给 PSM 浏览器。

```text
PVWA 授权 → PSM Web 注入保险库凭据 → STS AssumeRole
          → 签名后的角色登录请求 → PSM 浏览器控制台会话
```

这是可运行的桥和离线测试，不是能直接导入 PVWA 的平台包，也不是 CyberArk Marketplace 产品。Windows 部署、PSM 录像和真实腾讯云登录仍要在目标环境验收。

## 1.0 收紧了什么

签名仍按官方 HMAC-SHA256 回调，信任边界更硬：

- 默认用自动提交的 POST 交接。临时凭据不再出现在 `Location` 头。PSM 跑不了交接脚本时，把 `submit_method` 设为 `get`。
- 角色、目的页、时长、调用方 SecretId、ExternalId、会话策略都在服务端配置。表单不能自选。
- 只认环回对端，再加代理共享密钥。忽略 `X-Forwarded-For`。不相信浏览器自报的身份头。
- 一次性 CSRF、120 秒过期、按身份限速，时长上限 300 秒。腾讯云建议这条登录链路不要超过 5 分钟。
- 审计只打显式字段。密钥、token、签名不是日志参数。
- 启动时拒绝占位 SecretId、未知键、服务角色 ARN、非控制台目的页、任意 STS 端点。

## 文件

| 文件 | 作用 |
|---|---|
| `psm_tc_bridge/` | 配置、联邦登录、应用、审计 |
| `app.py` | 兼容旧启动方式 `python app.py` |
| `settings.example.json` | 服务端角色配置。填完再加载 |
| `cam-assume-policy.example.json` | 调用方 `sts:AssumeRole` 权限 |
| `session-policy.example.json` | 可选的内联会话策略，不能带 principal |
| `WebFormFields.template.txt` | PSM 字段映射。以已安装版本的语法为准 |
| `deploy/iis-proxy.md` | 桥所依赖的代理边界 |
| `tests/` | 签名、CSRF、白名单、SDK 请求形状、脱敏 |

## 腾讯云

1. 建经纪 CAM 子用户。SecretId 放账号属性 `TencentSecretId`，SecretKey 放保险库密码。不要用根密钥。
2. 建可登录控制台的普通角色。信任经纪用户，并给经纪用户该角色的 `sts:AssumeRole`。两边都要允许。角色上设置 ExternalId，再写进 profile。
3. 业务权限挂在角色上。验收从只读开始。可选 `session_policy` 只能再收窄临时凭据。
4. 复制 `settings.example.json` 为 `settings.json`。配置里还有 `REPLACE` 时进程拒绝启动。

时长上限 300 秒。关掉 PSM 会话不会吊销已经发出的临时凭据。

## 运行

```powershell
py -3 -m venv C:\PSM-TencentCloud\venv
C:\PSM-TencentCloud\venv\Scripts\python.exe -m pip install -r C:\PSM-TencentCloud\requirements.lock.txt
```

密钥放环境变量，不要放命令行：

| 变量 | 值 |
|---|---|
| `PSM_TC_CONFIG` | `settings.json` 的绝对路径 |
| `PSM_TC_PROXY_KEY` | 至少 32 字符，只和代理共享 |
| `PSM_TC_SESSION_KEY` | 另一组至少 32 字符的值 |

监听 `127.0.0.1:8765`。不要对外发布。CSRF 状态在进程内存里，只用一个进程。不要开 Flask debug。

```powershell
C:\PSM-TencentCloud\venv\Scripts\python.exe -m psm_tc_bridge
```

## 代理和 PVWA

代理才是认证边界。它必须先剥掉客户端带来的 `X-PSM-Bridge-Key` 和 `X-PSM-Authenticated-User`，再自己写入密钥，并把用户设成它认证到的 Windows 身份。见 [deploy/iis-proxy.md](deploy/iis-proxy.md)。

复制 PSM Web 应用示例，命名为 `PSM-TencentCloud-STS`。`LogonURL` 指向带认证的 HTTPS 桥。套用 `WebFormFields.template.txt`。`TencentRoleProfile` 选择服务端 profile，例如 `tc-readonly`。`ClientUserName` 只是审计标签，不是身份证明；注入前先处理域反斜杠和不支持的字符。

桥页面打开不等于云登录成功。在目标 PSM 版本上核对控制台身份、录像和浏览器清理。

## 测试

```powershell
python -m unittest discover -s tests -v
```

模拟 STS 不能证明真实登录兼容。

## 参考

- [腾讯云角色免密登录控制台](https://cloud.tencent.com/document/product/598/45529)
- [AssumeRole](https://cloud.tencent.com/document/api/1312/48197)
- [CyberArk PSM Web 应用](https://docs.cyberark.com/pam-self-hosted/latest/en/Content/PASIMP/psm_WebApplication.htm)

独立实现，不含 CyberArk SDK。Apache-2.0。
