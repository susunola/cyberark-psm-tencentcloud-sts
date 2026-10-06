# PSM-TencentCloud-STS

**English** | [简体中文](README.zh-CN.md)

CyberArk PSM bridge for Tencent Cloud mainland role-console login. PSM injects a broker CAM key, this process calls STS `AssumeRole`, and the PSM browser is handed a signed `roleAccessCallback` session.

```text
PVWA authorization → PSM Web injects Vault credentials → STS AssumeRole
                   → signed role login request → PSM browser console session
```

This is a runnable bridge and an offline test suite. It is not a PVWA platform ZIP, and it is not a CyberArk Marketplace product. Windows deployment, PSM recording, and live Tencent Cloud login still have to be accepted in the target environment.

## What changed in 1.0

The bridge stays on the documented HMAC-SHA256 callback, and the trust boundary is tighter:

- Default handoff is an auto-submitted POST. Temporary credentials no longer sit in a `Location` header. `submit_method=get` remains for a PSM build that cannot run the handoff script.
- Role, destination, duration, caller SecretId, ExternalId, and session policy come from server config. The form cannot choose them.
- Loopback peer check plus a proxy shared key. `X-Forwarded-For` is ignored. Client-supplied identity headers are not trusted.
- Single-use CSRF, 120 second expiry, per-identity rate limit, and a 300 second duration cap. Tencent recommends no more than five minutes for this login flow.
- Audit events are explicit JSON fields. Secret keys, tokens, and signatures are not log arguments.
- Startup rejects placeholder SecretIds, unknown keys, service-role ARNs, non-console destinations, and arbitrary STS endpoints.

## Files

| File | Purpose |
|---|---|
| `psm_tc_bridge/` | Package: config, federation, app, audit |
| `app.py` | Compatible launcher for `python app.py` |
| `settings.example.json` | Server-side role profiles. Not loaded until copied and filled in |
| `cam-assume-policy.example.json` | Caller `sts:AssumeRole` permission |
| `session-policy.example.json` | Optional inline session policy, no principal |
| `WebFormFields.template.txt` | PSM field map. Confirm syntax on the installed version |
| `deploy/iis-proxy.md` | Proxy boundary the bridge assumes |
| `tests/` | Offline signature, CSRF, allowlist, SDK shape, redaction |

## Tencent Cloud

1. Create a broker CAM sub-user. Store its SecretId in account property `TencentSecretId` and its SecretKey in the Vault password. Do not use root keys.
2. Create an ordinary role with console login enabled. Trust the broker, and grant the broker `sts:AssumeRole` on that role. Both sides must allow it. Set an ExternalId on the role and copy it into the profile.
3. Attach business permissions to the role. Start with read-only. Optional `session_policy` can only narrow the temporary credentials.
4. Copy `settings.example.json` to `settings.json`. The process refuses to start while `REPLACE` is present.

Duration is capped at 300 seconds. Closing the PSM session does not revoke credentials already issued.

## Run

```powershell
py -3 -m venv C:\PSM-TencentCloud\venv
C:\PSM-TencentCloud\venv\Scripts\python.exe -m pip install -r C:\PSM-TencentCloud\requirements.lock.txt
```

Environment, not the command line:

| Variable | Value |
|---|---|
| `PSM_TC_CONFIG` | Absolute path to `settings.json` |
| `PSM_TC_PROXY_KEY` | At least 32 characters, shared only with the proxy |
| `PSM_TC_SESSION_KEY` | Independent value, at least 32 characters |

The listener is `127.0.0.1:8765`. Do not publish it. Use one process: CSRF state is in memory. Do not enable Flask debug.

```powershell
C:\PSM-TencentCloud\venv\Scripts\python.exe -m psm_tc_bridge
```

## Proxy and PVWA

The proxy is the authentication boundary. It must strip client `X-PSM-Bridge-Key` and `X-PSM-Authenticated-User`, then set the key itself and set the user to the Windows identity it authenticated. See [deploy/iis-proxy.md](deploy/iis-proxy.md).

Duplicate the PSM Web application sample as `PSM-TencentCloud-STS`. Point `LogonURL` at the authenticated HTTPS bridge. Apply `WebFormFields.template.txt`. `TencentRoleProfile` selects a server profile such as `tc-readonly`. `ClientUserName` is an audit label, not an identity proof; normalize domain backslashes and unsupported characters before injection.

A loaded bridge page is not a successful cloud login. Verify the console identity, recording, and browser cleanup on the target PSM version.

## Tests

```powershell
python -m unittest discover -s tests -v
```

Mock STS calls do not prove live login compatibility.

## References

- [Tencent Cloud role console login](https://cloud.tencent.com/document/product/598/45529)
- [AssumeRole](https://cloud.tencent.com/document/api/1312/48197)
- [CyberArk Web applications for PSM](https://docs.cyberark.com/pam-self-hosted/latest/en/Content/PASIMP/psm_WebApplication.htm)

Independent implementation. No CyberArk SDK. Apache-2.0.
