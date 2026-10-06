# Deployment, upgrade and rollback

[中文说明](DEPLOYMENT.zh-CN.md)

## Prerequisites

Use a staging PSM matching the target production version. Supply a machine-wide supported Python 3.11–3.13 installation readable by LocalService, a reviewed WinSW binary with its verified SHA256, IIS Windows Authentication, URL Rewrite and ARR. No WinSW executable is distributed here. Compare the XML/commands with the selected WinSW release before deployment.

Official references: [WinSW](https://github.com/winsw/winsw), [IIS reverse proxy](https://learn.microsoft.com/en-us/iis/extensions/url-rewrite-module/reverse-proxy-with-url-rewrite-v2-and-application-request-routing), [URL Rewrite configuration](https://learn.microsoft.com/en-us/iis/extensions/url-rewrite-module/url-rewrite-module-configuration-reference).

## Install

1. Extract the source to an administrator-controlled staging directory. Configure `settings.json` using real role ARN and caller SecretId values. Each SecretId belongs to only one profile. Keep the cloud SecretKey in Vault.
2. Validate without network calls: `python scripts/check_config.py settings.json`.
3. From elevated PowerShell run:

```powershell
.\scripts\Install-Bridge.ps1 -PythonExe 'C:\Python312\python.exe' `
  -WinSWExe 'C:\Staging\WinSW.exe' -WinSWSha256 '<verified-64-character-sha256>' `
  -SettingsFile 'C:\Staging\settings.json'
```

The script creates a venv, installs locked dependencies, generates independent random proxy/session keys in ACL-protected service XML, installs the service as LocalService, and starts it, then verifies authenticated backend readiness. It preserves diagnostic files on failure. It is not safe to run under transcript logging that captures generated secret values; do not enable debug tracing.

4. Create a dedicated IIS HTTPS site with a trusted certificate and its own physical root. Enable Windows Authentication, disable anonymous authentication, and restrict authorization to intended PSM service accounts. Do not alter unrelated IIS sites.
5. Enable ARR proxy forwarding. Permit `HTTP_X_PSM_BRIDGE_KEY` and `HTTP_X_PSM_AUTHENTICATED_USER` as URL Rewrite server variables at the necessary scope. Copy `web.config.generated` from the installation directory to the dedicated site as `web.config`. Restrict its read access to administrators and the site's application pool identity. Never serve service XML/configuration files from that web root.
6. The rule replaces inbound headers with a private key and `{REMOTE_USER}`. Verify authenticated identity availability at rewrite time on the actual IIS pipeline. If it is unavailable, the rule must fail closed; do not substitute an incoming identity header. Authentication ordering is an explicit Windows acceptance item.
7. Disable request-body tracing, failed request tracing containing credentials, response Location tracing, and cache behavior. Prevent ARR from rewriting the external cloud Location header. Configure perimeter limits/rate limits and allow only necessary access.
8. Through the authenticated HTTPS endpoint, `/healthz` should return status `ok`. An anonymous request should receive IIS 401/403. Direct loopback access without the key should receive backend 403. Forged headers cannot authorize a request.
9. Configure PVWA using the README and WebFormFields template. Verify the full live-cloud and PSM recording matrix before promoting.

## Upgrade

Quiesce new connections and let existing sessions finish. Back up ACL-protected settings, service XML, IIS configuration and current source/venv. Stop `PSMTencentCloudSTS`. Install and test the new source/dependencies in an administrator-only staging directory. Validate settings, replace code and rebuild the service venv while stopped, preserving secrets and ACLs. Start the service, test authenticated health and one read-only console session. Record the version, commit, dependency lock and test evidence.

The installer intentionally rejects an existing directory/service. Never rerun it over a live installation. A restart invalidates outstanding form nonces. Allow for dropped issuance requests; no automatic retry or credential reuse is implemented.

## Rollback

Stop the service, restore the prior code/venv and settings/service XML snapshot, verify ACLs, then restart. Restore the dedicated IIS site only if it changed. Verify health and a read-only PSM connection. Previously issued cloud credentials remain governed by their cloud lifetime; rollback does not revoke them.

## Uninstall

Run elevated PowerShell: `.\scripts\Uninstall-Bridge.ps1`. It stops/removes the service and retains files. Disable the component/platform association in PVWA, remove the dedicated IIS site/rule, revoke unused caller keys and trust grants, and remove files only after retention requirements are met. Do not remove shared IIS modules used by other applications.

## Troubleshooting

| Symptom | Check |
|---|---|
| IIS 401 | Browser integrated authentication, site authorization and actual PSM Windows account |
| IIS 500.50 / rewrite error | ARR/Rewrite installation, permitted server variables, configuration scope |
| Backend 403 | Loopback peer, overwritten identity/key headers, correct proxy secret, expired/replayed CSRF |
| Backend 400 | Form field mapping, duplicate fields, role profile/caller binding, audit label length/control characters |
| Backend 503 | STS issuance is at capacity; respect Retry-After and start a new form |
| Backend 502 | Safe correlation ID, STS network reachability, key state, trust policy, AssumeRole permission, duration |
| Cloud login failure | Clock synchronization, role console-login enabled, signature/callback and cloud policy |
| Recording absent | PSM framework/driver/PID configuration; bridge cannot create recordings |
| Service fails to start | Machine-wide Python ACLs, LocalService venv read access, log folder write access, invalid settings |

Only collect sanitized diagnostics. Do not attach complete URLs, cookies, SecretKeys, proxy secrets, service XML or raw request bodies to tickets.

From 0.5.0, the runtime also requires `pam/__init__.py` and `pam/audit.py`. Include this minimal package when upgrading root runtime files; see the [delivery ledger](DELIVERY.md).
