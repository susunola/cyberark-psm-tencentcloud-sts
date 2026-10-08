# Deployment, upgrade and rollback

[中文说明](DEPLOYMENT.zh-CN.md)

## Windows deployment compatibility

This matrix describes this repository's evidence, not CyberArk/Idira certification. **No Windows version has completed end-to-end PSM deployment acceptance for this component.**

| Windows host | Repository status | Deployment condition |
|---|---|---|
| Windows Server 2025 | CI on `windows-2025`, Python 3.11–3.14; source tests and PowerShell parsing/file tests; a separate Python 3.13 job exercises WinSW installation, service readiness, ACLs and uninstall | IIS authentication and real PSM browser/session acceptance remain required |
| Windows Server 2022 | Not tested; candidate for environment evaluation | Verify support in the installed PSM/Privilege Cloud Connector release before deployment |
| Windows Server 2019 | Not tested; candidate for environment evaluation | Same release-specific vendor check and full acceptance required |
| Windows Server 2016 or earlier | Not tested; no compatibility claim | No deployment recommendation from this repository |
| Windows 10/11 | Not tested as a PSM deployment host | Not a supported PSM production host claimed by this repository |
| Server Core / ARM64 | Not validated | No deployment support claimed |

Use a Windows x64 host capable of running the native PSM GUI/browser stack. The supported deployment combination must be the intersection of the vendor's specific PSM/Connector OS matrix, Python 3.11–3.14, the reviewed WinSW/IIS components and this plugin's acceptance results. A newer Windows release is not automatically a supported PSM host. PAM SaaS still needs the appropriate customer-side Connector/PSM capability.

Record the Windows edition/build, GUI installation mode, PSM/Connector version, browser/driver, Python, PowerShell, WinSW and IIS/ARR/Rewrite versions in the acceptance record. Validate installation, service restart, HTTPS identity, cloud login, recording and cleanup on that exact combination. Expand this matrix only when evidence is available.

## Live international-cloud compatibility evidence

On **2026-10-08 (UTC)**, the caller AK/SK supplied by the repository owner was tested from **macOS (Darwin), Python 3.14.7**, using source commit `abfbd4e`, region `ap-singapore`, and `sts.intl.tencentcloudapi.com`. Credential values, account IDs, role ARNs and login URLs are omitted from this public record.

| Check | Result | Scope |
|---|---|---|
| International STS `GetCallerIdentity` | Passed; `Type=CAMUser`, `UserId=PrincipalId` | Confirms this caller credential and identity comparison against the real international API |
| Temporary test role and cleanup | Passed | With owner authorization, created a console-enabled role without attached permission policies; deleted it after testing and confirmed `GetRole` reports it absent |
| International STS `AssumeRole` | Passed | `DurationSeconds=300` returned a 300-second session; the role ceiling was 7200 seconds |
| International console callback | Inconclusive | Correct and tampered signatures both returned HTTP 200 without a redirect; signature acceptance and browser login remain unverified |
| Windows / IIS / PSM / recording | Not tested by this cloud check | This macOS API result does not expand the Windows support matrix |

The initial identity inspection was read-only; the subsequent authorized test created and deleted only the temporary role. The narrow sub-user trust was rejected with `InvalidParameter.PrincipalQcsError`; account-scoped trust was accepted. The role had no attached permission policies, and its deletion was independently confirmed. It is separate from the earlier partial cloud acceptance recorded in [acceptance evidence](ACCEPTANCE.md). A successful identity check does not establish role authorization, browser console login or end-to-end PSM compatibility.

## Prerequisites

Use a staging PSM matching the target production version. Supply a machine-wide supported Python 3.11–3.14 installation readable by the service account, a reviewed WinSW binary with its verified SHA256, IIS Windows Authentication, URL Rewrite and ARR. No WinSW executable is distributed here. Compare the XML/commands with the selected WinSW release before deployment.

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

The script creates a venv, installs hash-verified dependencies (`--require-hashes` against `requirements.lock.hashes.txt`; regenerate that file with `scripts/pin_lock_hashes.py` after any lock change, otherwise the install falls back to version pins with a warning), generates independent random proxy/session keys in ACL-protected service XML, installs the service under its own virtual account, and starts it, then verifies authenticated backend readiness. It preserves diagnostic files on failure. It is not safe to run under transcript logging that captures generated secret values; do not enable debug tracing.

4. Create a dedicated IIS HTTPS site with a trusted certificate and its own physical root. Enable Windows Authentication, disable anonymous authentication, and restrict authorization to intended PSM service accounts. Do not alter unrelated IIS sites.
5. Enable ARR proxy forwarding. Permit `HTTP_X_PSM_BRIDGE_KEY` and `HTTP_X_PSM_AUTHENTICATED_USER` as URL Rewrite server variables at the necessary scope. Copy `web.config.generated` from the installation directory to the dedicated site as `web.config`. The installer re-protects that file so only SYSTEM and administrators can read it, and you should delete it from the installation directory once it is in place. Restrict the site copy's read access to administrators and the site's application pool identity. Never serve service XML/configuration files from that web root.
6. The rule replaces inbound headers with a private key and `{REMOTE_USER}`. Verify authenticated identity availability at rewrite time on the actual IIS pipeline. If it is unavailable, the rule must fail closed; do not substitute an incoming identity header. Authentication ordering is an explicit Windows acceptance item.
7. Disable request-body tracing, failed request tracing containing credentials, response Location tracing, and cache behavior. Prevent ARR from rewriting the external cloud Location header. Configure perimeter limits/rate limits and allow only necessary access.
8. Through the authenticated HTTPS endpoint, `/readyz` - and `/healthz`, which it replaces in name only - should return status `ok`. An anonymous request to either should receive IIS 401/403, and a direct loopback request without the key should receive backend 403. Forged headers cannot authorize a request. `/livez` is the single route the backend answers without the key and it reports liveness alone, so a supervisor may probe it on the loopback interface; do not publish it through IIS.
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
| Service fails to start | Machine-wide Python ACLs, service-account venv read access, log folder write access, invalid settings |

Only collect sanitized diagnostics. Do not attach complete URLs, cookies, SecretKeys, proxy secrets, service XML or raw request bodies to tickets.

From 0.5.0, the runtime also requires `pam/__init__.py` and `pam/audit.py`. Include this minimal package when upgrading root runtime files; see the [delivery ledger](DELIVERY.md).
