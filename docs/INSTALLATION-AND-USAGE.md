# Installation and usage manual

**English** | [简体中文](INSTALLATION-AND-USAGE.zh-CN.md) · [Back to README](../README.md)

Applies to source version 0.5.2. This guide takes an administrator from first installation to console access, guest access, maintenance and recovery. The console flow uses Vault-managed CAM keys in a CyberArk PSM Web session. CVM guest access uses the installed native SSH/RDP components.

The deliverable is bridge and administrative source code, not an importable native platform/CPM ZIP. Automated checks cover Windows/Ubuntu, Python 3.11–3.13 and actual Redis token sharing. Service operation on a target PSM, live Tencent Cloud login, recording and approval still require environment acceptance. Passing source tests does not certify every PAM version. See the [delivery ledger](DELIVERY.md) and [acceptance record](ACCEPTANCE.md).

## Contents

1. [Architecture and prerequisites](#preparation)
2. [Tencent Cloud configuration](#cloud)
3. [Windows service installation](#install)
4. [Authenticated IIS HTTPS proxy](#proxy)
5. [PVWA and PSM configuration](#pam)
6. [End-user connection workflow](#use)
7. [Administrative tools and command reference](#admin)
8. [Key rotation and recovery](#rotation)
9. [Scheduled maintenance and multiple nodes](#advanced)
10. [Upgrade, rollback and uninstall](#maintenance)
11. [Troubleshooting and acceptance](#troubleshooting)

<a id="preparation"></a>
## 1. Architecture and prerequisites

```text
User → PVWA (Safe authorization / MFA / approval / tickets)
     → PSM Web browser → IIS HTTPS + Windows Authentication
     → local bridge at 127.0.0.1:8765 → Tencent Cloud STS
     → role login callback → Tencent Cloud console
```

PVWA governs authorization. Native PSM governs browser isolation, recording and cleanup. The bridge validates credentials, enforces caller/role allowlists and performs STS login. Opening the bridge directly does not replace PVWA authorization.

| Resource | Requirement |
|---|---|
| Test PAM environment | Permission to manage platforms, Safes and connection components; ability to test PSM Web and playback |
| Windows PSM host | Administrator access; organizational approval for the additional service/IIS under the PSM hardening baseline |
| Python | Machine-wide installation executable by LocalService; CI covers 3.11–3.13 |
| WinSW | Separately obtained, reviewed binary and a SHA256 verified against a trusted source |
| IIS | Windows Authentication, URL Rewrite, ARR, dedicated HTTPS site and trusted certificate |
| Tencent Cloud | Dedicated CAM sub-user/API key and ordinary CAM role eligible for console login |
| Network/time | DNS, certificate trust and synchronized clocks; bridge access to international STS and browser access to cloud login/console |
| Optional management workstation | Full source, separate Python environment and an authorized PVWA API session |

Do not expose backend port 8765 remotely. Guest connections require PSM-to-guest private SSH/RDP connectivity. Management needs PVWA/CAM/CVM HTTPS; shared token mode also needs controlled Redis TLS access. Approve destinations for your region and network policy rather than opening all ports.

Examples use source at `C:\Admin\psm-tencentcloud-sts`, protected configuration at `C:\Protected\TencentPSM`, service at `C:\PSM-TencentCloud` and HTTPS at `https://psm-tc-bridge.internal/`. Replace these with actual paths. **Do not create the service directory before first installation.** The installer creates it and applies ACLs. Source tooling and installed service runtime are separate directories.

### International-site migration from 0.5.0

Earlier code signed the mainland host. Version 0.5.1 uses `www.tencentcloud.com/login/roleAccessCallback`, permits only `https://console.tencentcloud.com/` destinations and explicitly calls `sts.intl.tencentcloudapi.com`, `cam.intl.tencentcloudapi.com` and `cvm.intl.tencentcloudapi.com`. Update settings, runtime/CSP, Vault address metadata and network allowlists together; drain connections and follow the upgrade procedure. Existing mainland destination settings intentionally fail startup validation. Use international-account keys and verify regional availability; choosing a geographic region alone does not change the account site. Review the [international callback specification](https://www.tencentcloud.com/document/product/614/36997) and [STS API](https://www.tencentcloud.com/document/product/1150/49456). The callback page is labeled “old scheme”; generic console login remains a live acceptance requirement.

<a id="cloud"></a>
## 2. Tencent Cloud configuration

1. Create a dedicated CAM **sub-user** with API keys. Use distinct caller bindings for different privilege tiers; do not use root keys.
2. Create an ordinary CAM role with console login enabled and a trust relationship allowing the intended caller.
3. Grant that caller `sts:AssumeRole` for the target role. Review the [permission example](../cam-assume-policy.example.json), replacing account/role values. Both trust and caller permission must allow the operation.
4. Attach only required business permissions to the role; start acceptance with read-only access. The bridge does not provision roles or relax cloud MFA/network/login policies.
5. Record the role ARN, caller sub-user UIN and SecretId. Store SecretKey in the Vault password field, never in bridge settings.

Copy [settings.example.json](../settings.example.json) into a protected `settings.json`:

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

Replace account, role and SecretId. `REPLACE` placeholders fail validation. The profile key `tc-readonly` must exactly match the Vault `TencentRoleProfile` property. A SecretId may belong to only one profile; during rotation the same profile may temporarily allow old and new IDs. Destinations are restricted to Tencent console HTTPS. Only international-site ordinary CAM roles are implemented. Requested 300-second STS validity is separate from console cookies and PSM session lifetime.

Run the offline check from full source; it makes no cloud calls and needs no SecretKey:

```powershell
Set-Location C:\Admin\psm-tencentcloud-sts
& 'C:\Python313\python.exe' .\scripts\check_config.py C:\Protected\TencentPSM\settings.json
```

Proceed only after success/exit 0. Fix unknown fields, duplicate JSON keys, invalid roles or caller/profile conflicts first.

<a id="install"></a>
## 3. Windows service installation

Open **administrator PowerShell** in the source directory. Verify Python/WinSW paths, validated settings and an absent installation directory. Replace the checksum placeholder below with the trusted 64-hex WinSW SHA256. A locally calculated hash alone does not establish download provenance.

```powershell
Set-Location C:\Admin\psm-tencentcloud-sts
.\scripts\Install-Bridge.ps1 `
  -PythonExe 'C:\Python313\python.exe' `
  -WinSWExe 'C:\Admin\tools\WinSW-x64.exe' `
  -WinSWSha256 'REPLACE_WITH_VERIFIED_64_HEX_SHA256' `
  -SettingsFile 'C:\Protected\TencentPSM\settings.json' `
  -InstallDir 'C:\PSM-TencentCloud'
```

The installer verifies WinSW, creates a venv, installs locked dependencies, copies minimal runtime/configuration, generates two independent random secrets, registers/starts `PSMTencentCloudSTS` and checks local authenticated `/healthz`. Initial installation needs an approved dependency source; disconnected sites must supply reviewed packages through their normal process.

| Installed item | Purpose |
|---|---|
| `venv\Scripts\python.exe` | Dedicated service interpreter |
| `settings.json` | Role/SecretId allowlist; no CAM SecretKey |
| `PSMTencentCloudSTS.exe` / `.xml` | WinSW and service configuration; XML contains proxy/session secrets |
| `web.config.generated` | IIS template containing the private proxy key; ACL-restricted to SYSTEM/administrators, delete it from the installation directory after copying |
| `logs` | LocalService-writable runtime logs |
| `pam\__init__.py`, `pam\audit.py` | Minimal runtime dependencies; full scripts/tests are not installed |

The service runs as `NT AUTHORITY\LocalService`, with read access to runtime/configuration and write access to logs. Ordinary session users must not modify code/settings/secrets. Never serve the installation directory as the IIS site root or commit service XML/generated proxy/shared-secret configuration.

```powershell
Get-Service PSMTencentCloudSTS
```

Expect `Running`. On installation failure the script attempts to remove a registered service while retaining protected files for diagnosis. Inspect logs, files and service state before retrying. Existing directories are intentionally refused; use the upgrade procedure.

<a id="proxy"></a>
## 4. Authenticated IIS HTTPS proxy

1. Create a dedicated site root containing only web configuration; apply administrator/application-pool ACLs.
2. Install/enable approved Windows Authentication, URL Rewrite and ARR, including proxy forwarding. Avoid changing unrelated sites.
3. Bind a trusted certificate/internal FQDN resolvable and trusted by the PSM browser.
4. Disable anonymous access; enable Windows Authentication and restrict authorized PSM session identities. Confirm the actual integrated-authentication identity in your environment.
5. Copy the generated `web.config.generated` (readable only by SYSTEM and administrators) to that site's `web.config` under restricted access, then delete it from the installation directory. Following the [rewrite template](../deployment/web.config.template), permit `HTTP_X_PSM_BRIDGE_KEY` and `HTTP_X_PSM_AUTHENTICATED_USER` at the appropriate IIS configuration scope.
6. Overwrite browser-supplied headers with the private proxy key and authenticated `{REMOTE_USER}`; forward only to `http://127.0.0.1:8765`. Verify `REMOTE_USER` is populated at the relevant rewrite stage in your actual IIS pipeline. Missing identity must fail closed, without trusting client headers.
7. Disable request-body, Cookie, response Location and full callback-URL tracing/caching. Preserve external Tencent Cloud redirect destinations.

| Check | Expected result |
|---|---|
| Unauthenticated HTTPS root | 401/403, no usable form |
| Unauthenticated request with forged proxy headers | Still 401/403 |
| Direct local backend request without trusted headers | 403 |
| Authorized HTTPS `/healthz` | 200 with `status: ok` |
| Authorized HTTPS `/` | Form loads over browser-side HTTPS |

Health does not establish cloud login. Do not expose the proxy key to users or enable Flask debug/request logging to troubleshoot.

<a id="pam"></a>
## 5. PVWA and PSM configuration

Menu names/property expansion vary by installed version. Complete these configuration tasks using that version's shipped Web sample and documentation; there is no universal native import package.

1. Duplicate the native Web application component as `PSM-TencentCloud-STS`, retaining supported browser/driver/launcher, PID reporting, recording and exit handling.
2. Set `LogonURL` to the authenticated HTTPS bridge root.
3. Duplicate/create an appropriate API credential platform, associate the component and add exact account property names `TencentSecretId` and `TencentRoleProfile`.
4. Create the account in the intended Safe: caller SecretId in `TencentSecretId`, `tc-readonly` in `TencentRoleProfile`, corresponding SecretKey in the password field. Controlled username/address metadata does not replace SecretId.
5. Do not apply guest password rotation to CAM keys. Unless a verified native CAM CPM is installed, disable automatic password management for those accounts; use staged rotation below.
6. Apply [WebFormFields](../WebFormFields.template.txt), checking expansion syntax for your version:

```text
secret_id > {TencentSecretId} (searchby=id)
secret_key > {Password} (searchby=id)
profile > {TencentRoleProfile} (searchby=id)
audit_label > {ClientUserName} (searchby=id)
connect_button > (Button) (searchby=id)
```

7. Preserve the hidden CSRF field and normal browser submission; do not hardcode/reuse tokens.
8. Set native Safe/account-use/PSM permissions, MFA, dual control and ticket policy. Prevent arbitrary caller/profile/destination overrides; configure reviewers separately.
9. Validate successful Tencent console login using the native version's framework. A loaded bridge page or HTTP 303 is not sufficient.
10. Test correct role/business permissions, recording playback, timeout/exit cleanup and cross-user cookie isolation before exporting a native package from target PVWA.

`ClientUserName` is an audit label, not independent identity proof. The proxy identity may be a PSM service/session account. Correlate native PSM records, bridge request IDs and cloud role session names.

<a id="use"></a>
## 6. End-user connection workflow

1. Sign in to PVWA and complete required MFA.
2. Select an authorized Tencent Cloud account; submit reason/ticket/allowed time and wait for native approval when required.
3. Connect using `PSM-TencentCloud-STS` through the organization's native client/browser workflow.
4. PSM injects Vault credentials/profile; STS federation opens the console. Users do not need to enter/view keys on the bridge page.
5. Verify the intended role/permissions before approved work. On failure provide time, account ID and request ID to the administrator, never a complete callback URL screenshot.
6. Exit through normal PSM controls. Session closure does not revoke issued cloud credentials or guarantee global console logout; verify cloud lifetime/restrictions separately.

For CVM guests, select an onboarded Windows/Linux guest account and use verified native `PSM-RDP` / `PSM-SSH`. Guest credentials and CAM API credentials are separate accounts.

<a id="admin"></a>
## 7. Administrative tools and command reference

### 7.1 Management environment

Run tools from **full source**, not the minimal service directory. On a protected workstation:

```powershell
Set-Location C:\Admin\psm-tencentcloud-sts
& 'C:\Python313\python.exe' -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r requirements.lock.txt
& .\.venv\Scripts\python.exe scripts\pamctl.py --help
& .\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Below, `python` means this management interpreter. Optional Redis integration tests require a separate Redis service/environment and may be skipped locally.

| Environment | Purpose |
|---|---|
| `PVWA_API_URL` | HTTPS API root, e.g. `https://pvwa.internal/PasswordVault/API` |
| `PVWA_TOKEN` | Valid authorized API session obtained through approved login/MFA |
| `PVWA_CA_BUNDLE` | Optional internal CA path; never disable TLS verification |
| `TENCENTCLOUD_SECRET_ID` / `TENCENTCLOUD_SECRET_KEY` | Scoped management credentials for discovery/rotation/maintenance |

Inject secrets through an approved provider into process environment, not command arguments, repository, scheduler manifests or logs. The tool does not implement MFA-bypassing authentication. Keep management and console caller permissions separately scoped.

Writes default to `no-write`; explicitly add `--apply` after review. **This guard is not a remote execution preview:** without apply it does not read secret stdin or check remote objects/write permissions. Use subcommand `--help` for arguments. Read operations also require native authorization.

### 7.2 Queries, approval, connections and sessions

Replace example identifiers, Safes, platforms and tickets. Write examples deliberately omit `--apply`.

| Task | Command |
|---|---|
| Read capability probes | `python scripts/pamctl.py capabilities` |
| Binding checks | `python scripts/pamctl.py preflight --account 1_2 --safe CloudConsole --platform TencentAPI --component PSM-TencentCloud-STS --settings C:\Protected\TencentPSM\settings.json` |
| List | `python scripts/pamctl.py list Accounts --limit 100 --offset 0` |
| Account state | `python scripts/pamctl.py status --account 1_2` |
| Native connection response | `python scripts/pamctl.py connect --account 1_2 --component PSM-TencentCloud-STS --reason "Approved maintenance" --ticket-id CHG1 --ticket-system ServiceNow --out C:\Protected\TencentPSM\connection.json` |
| Access request | `python scripts/pamctl.py request --account 1_2 --component PSM-TencentCloud-STS --reason "Approved maintenance" --ticket-id CHG1 --ticket-system ServiceNow` |
| Request details | `python scripts/pamctl.py request-info --id REQUEST_ID`; reviewer adds `--incoming` |
| Decision | `python scripts/pamctl.py decision --id REQUEST_ID --decision confirm --reason "Approved scope"`; use `reject` to reject |
| Cancel own request | `python scripts/pamctl.py cancel-request --id REQUEST_ID` |
| Session details | `python scripts/pamctl.py session-info --id SESSION_ID --section details` |
| Session control | `python scripts/pamctl.py session --id SESSION_ID --action terminate`; also `suspend` / `resume` |
| Recording metadata | `python scripts/pamctl.py recording --id RECORDING_ID --section details`; also `activities` / `properties` / `valid` |
| Playback response | `python scripts/pamctl.py playback --id RECORDING_ID --out C:\Protected\TencentPSM\playback.json` |

Lists also support `LiveSessions`, `Recordings`, `IncomingRequests`, `MyRequests`; the latter two use native request listing without an offset-pagination guarantee. Request windows use paired `--from-date` / `--to-date` UTC Unix seconds, end greater than start, matching the approved window. Native authorization remains authoritative; no automatic approval occurs.

Connection/playback responses are saved to exclusive protected JSON files for the configured native client/player. The tool does not launch RDP, follow playback URLs or download recordings. These responses can contain temporary authentication material: use operator/system-only Windows directory ACLs and retention cleanup. Non-JSON native launch formats require target-version adaptation and are rejected.

### 7.3 Discovery, onboarding and guest CPM

```text
python scripts/pamctl.py discover --regions ap-singapore ap-hongkong
python scripts/pamctl.py cvm-plan --inventory inventory.json --usernames usernames.json --safe CloudGuests --linux-platform UnixSSH --windows-platform WinServerLocal
python scripts/pamctl.py cpm --account 2_3 --action Verify --safe CloudGuests --platform UnixSSH
python scripts/pamctl.py cpm --account 2_3 --action Change --safe CloudGuests --platform UnixSSH
python scripts/pamctl.py cpm --account 2_3 --action Reconcile --safe CloudGuests --platform UnixSSH
```

Discovery returns CAM/CVM metadata, not guest passwords. Protect output directories before saving inventory. `usernames.json` maps instance IDs to verified usernames, e.g. `{"ins-example":"opsuser"}`; do not infer credentials from operating systems. Plans use private addresses, skip unknown operating systems and neither create passwords nor automatically assign components.

Onboarding consumes complete account JSON through secure stdin, never password arguments. Required fields: `name`, `address`, `userName`, `platformId`, `safeName`, `secretType` (`password`) and string `secret`. Use `platformAccountProperties` for custom fields. CAM accounts need both Tencent properties and explicit `secretManagement.automaticManagementEnabled: false`.

```text
python scripts/pamctl.py onboard --safe CloudGuests --platform UnixSSH --apply
python scripts/pamctl.py onboard-batch --safe CloudGuests --platform UnixSSH --journal C:\Protected\TencentPSM\onboarding.jsonl --apply
```

An approved provider must stream a complete object/array into stdin; do not paste secrets into a recorded terminal. Batches allow up to 100 accounts/1 MiB, validate the entire array and check existing Safe names first. Journals contain operation metadata. An attempted but unconfirmed write may already have created an account: reconcile PVWA before recovery, never rerun the entire batch with a new journal blindly.

`submitted-to-CPM` is asynchronous submission, not a successful change. Verify native status/logs; Reconcile needs a configured reconciliation account. Guest CPM commands reject CAM key accounts.

Standalone identity verification: `python scripts/pamctl.py verify --target-uin 100000000002` consumes a JSON object with `secret_id` and `secret_key` from approved secure stdin. It checks caller UIN through the international identity endpoint, not successful console login. No `--apply` is required for this read-only command.

Discovery is bounded to 20 unique, fully prevalidated regions, 1,000 CAM users, 100 pages per region and 10,000 CVM instances across the run. Duplicate instances, incomplete pages or changed totals fail the whole command rather than produce a success with partial results. Retry a fresh read after inventory changes settle; no consistent snapshot is guaranteed. Region suffixes such as `ap-shanghai-fsi` pass syntax validation, but account/service availability still needs cloud confirmation.

### 7.4 Export and audit

```text
python scripts/pamctl.py export Accounts --out C:\Protected\TencentPSM\accounts.jsonl --limit 100 --max-pages 100
python scripts/pamctl.py audit-report --input C:\Protected\TencentPSM\bridge.log --max-lines 100000
```

Exports also support `LiveSessions` / `Recordings`, up to 100 pages of 100 records. The final `export-completed` record must contain `complete: true`; missing footer means incomplete. Exports are not transactional snapshots. Audit aggregation counts status/profile and request correlation without secrets, callback URLs or arbitrary identity fields; it does not replace native recordings/audit.

<a id="rotation"></a>
## 8. Key rotation and recovery

Use dedicated CAM sub-users and one change authority per target UIN. Confirm old-key validity, Vault metadata, available key capacity and scoped management permission. Serialize cloud/Vault changes.

```text
python scripts/pamctl.py prepare --old-account 1_2 --target-uin 100000000002 --profile tc-readonly --ticket C:\Protected\TencentPSM\rotation.json
```

After review add `--apply`. Preparation reserves an exclusive journal, creates/verifies the replacement and saves a new Vault account in the same Safe/platform. The ticket contains identifiers only; the old key remains active.

1. Add the new SecretId to the same bridge profile while retaining the old ID; validate and deploy settings, then restart under change control.
2. Configure replacement-account permissions/component. Test real PSM login, role, business permission, approval, recording and cleanup.
3. Review ticket/settings and explicitly confirm cutover:

```text
python scripts/pamctl.py finalize --ticket C:\Protected\TencentPSM\rotation.json --settings C:\Protected\TencentPSM\settings.json --confirm-psm-cutover --apply
```

Finalize rechecks bindings, identity, AssumeRole and cloud state, disables the old key and reads state back. Failed requests/readback may have an uncertain outcome: inspect actual inventory before retrying. After confirmed completion remove the old allowlist entry and retain/retire Vault accounts/tickets under policy. Previously issued cloud credentials are not revoked by this operation.

For interrupted preparation:

```text
python scripts/pamctl.py recover-ticket --journal C:\Protected\TencentPSM\rotation.json --ticket C:\Protected\TencentPSM\rotation-recovered.json --apply
```

Recovery requires unique matching cloud/Vault records and valid new identity/metadata. It creates no key and disables nothing. If Vault never saved the new SecretKey, cloud inventory cannot return it; keep the old working key and reconcile manually.

For rollback while the old key still exists:

```text
python scripts/pamctl.py restore-old --ticket C:\Protected\TencentPSM\rotation.json --settings C:\Protected\TencentPSM\settings.json --apply
```

This rechecks the Vault bindings, the account scope and the bridge allowlist before reactivating, then reads the state back. It restores key state only; restore PVWA permissions and retest. A deleted key cannot be recovered. Do not delete the old key during cutover.

<a id="advanced"></a>
## 9. Scheduled maintenance and multiple nodes

### Scheduled maintenance

Copy the [maintenance template](../deployment/maintenance.example.json), supply real account/Safe/platform/sub-user UIN and set profile to configured `tc-readonly`. Only `verify-cam` and `prepare-key` are allowed.

```text
python scripts/run_maintenance.py --jobs maintenance.json --settings C:\Protected\TencentPSM\settings.json --state-dir C:\Protected\TencentPSM\maintenance-state
```

Review before adding `--apply`. A protected scheduler wrapper must obtain fresh PVWA and cloud credentials each run; keep them out of task arguments/manifests. `prepare-key` still requires tested manual cutover, never automatic finalize. Native guest rotation uses CPM's own schedule.

Crash locks are not stolen: inspect processes and remote outcomes first. Existing prepare tickets block repeated creation for the same job; archive only after completed cutover/retention review. Failures stop later jobs. The filesystem lock is not a distributed cloud lock.

### Shared tokens

Single-node default uses process-memory tokens. Multiple nodes require Redis 7+, TLS/ACLs, a single writable primary, identical role settings/namespace/session key and authenticated identity format. Proxy keys can be node-specific. STS admission is two concurrent calls per node, not globally.

Create protected JSON from the [shared-secret template](../deployment/shared-secrets.example.json), replacing Redis credentials/URL, namespace and a random independent shared `session_key`. Use `rediss://` and a CA file when needed, readable by LocalService. Do not print/commit the file.

```powershell
.\scripts\Configure-SharedTokens.ps1 `
  -InstallDir C:\PSM-TencentCloud `
  -SharedSettingsFile C:\Protected\TencentPSM\shared-secrets.json
```

Default changes nothing. Drain connections and review, then add `-Apply -Restart`. The script validates Redis/TLS, copies protected configuration and atomically updates service XML under an exclusive lock. Original XML is saved as `.xml.before-shared`; existing files/backups/locks are not overwritten. After partial failure inspect state before restoring the protected backup.

Redis failures return 503 without local fallback. Asynchronous failover/backup restoration can resurrect consumed tokens: rotate the shared session key on all nodes and invalidate pending connections before resuming traffic, with primary fencing/single-writer enforcement. Atomic Lua is not an exactly-once guarantee across asynchronous failover. Production TLS/load balancing/failover require acceptance; see [operations](OPERATIONS.md).

<a id="maintenance"></a>
## 10. Upgrade, rollback and uninstall

**Upgrade:** drain PSM connections; protect backups of runtime/venv, settings, service XML, IIS configuration, shared secrets/CA and logs; record version/checksums. Test new source/settings first. Stop the service and update runtime/dependencies during maintenance, including `pam/__init__.py` and `pam/audit.py`. Preserve existing secrets/ACLs; do not rerun first-install against an existing directory. Restart and check health, live login, playback and cleanup. Verify shared-protocol compatibility before rolling multi-node upgrades.

**Rollback:** stop service and restore matching-version runtime/venv/settings/ACLs and controlled proxy configuration. Restart and repeat acceptance. Coordinate all nodes if session keys/Redis state changed and invalidate old forms. Code rollback neither revokes cloud credentials nor undoes completed cloud/Vault writes.

**Uninstall:** from full source in administrator PowerShell:

```powershell
.\scripts\Uninstall-Bridge.ps1 -InstallDir C:\PSM-TencentCloud
```

The script stops/unregisters the service and retains files for audit/manual cleanup. Separately retire PVWA associations, the dedicated IIS site and cloud keys/permissions after dependency review; do not affect unrelated accounts/sites. Dispose of secret configuration and launch responses according to policy.

<a id="troubleshooting"></a>
## 11. Troubleshooting and acceptance

| Symptom | Check/action |
|---|---|
| Existing directory/service | Inspect previous installation/failure; back up and follow upgrade/recovery |
| WinSW checksum mismatch | Stop and verify trusted release binary/digest |
| Startup failure | Offline settings validation, Python/LocalService ACLs, dependencies, logs, CA access, loopback port |
| IIS 401/403 | Windows Authentication, anonymous disabled, allowed identity, certificate and browser integrated authentication |
| IIS 500 / backend always 403 | ARR/Rewrite, allowed server variables, REMOTE_USER pipeline availability, matching private proxy key; never bypass with client identity headers |
| Expired form / 429 | Tokens are single-use/120 seconds with bounded capacity; wait and start a new PVWA connection |
| 503 / Retry-After | Per-node STS load, Redis/TLS/health; wait and reconnect, without shared-store bypass |
| STS denied | Key status, exact SecretId/profile, trust/caller permissions, cloud policy, DNS/time/egress |
| Redirect but no login | Console eligibility/business permissions/cloud policy; 303 is not login proof |
| PVWA 401/403 | Refresh expired session/check scope; do not disable MFA or certificate verification |
| API 404 / non-JSON launch | Hidden permissions or version differences; adapt to target version, do not infer universal support |
| CPM submitted but unchanged | Native CPM state/logs, guest connectivity, platform/reconciliation account |
| Interrupted rotation/onboarding | Retain journals and reconcile actual cloud/Vault writes before recovery |
| Existing output/backup/lock | Intentional overwrite protection; inspect previous outcome first |

CLI exit `0` means successful command or no-write; `2` means argument/runtime failure or incomplete operation; preflight `3` means scope/binding failure. `not_verified` fields still require environment testing. Read probes establish neither write permission nor installed component/recording compatibility.

Record at least: correct role/permission; invalid keys/unauthorized profiles rejected; anonymous/forged-header/backend bypass rejected; CSRF replay/expiry rejected; two-user isolation; native approval/tickets; recording playback and exit cleanup; replacement cutover/old-key readback/rollback; shared TLS/fail-closed/coordinated failover; absence of long-term keys/full callback URLs in every log layer. Fill the [acceptance record](ACCEPTANCE.md) with environment/evidence/results before production assessment.

Callback URLs contain temporary credentials and Python cannot guarantee memory zeroization. Apply the organization's PSM baseline to debugging, clipboard/file channels and diagnostics. Share time/version/account ID/request ID and sanitized status, never keys, cookies, tokens or full callback URLs.

Further reading: [Deployment](DEPLOYMENT.md) · [Operations](OPERATIONS.md) · [PAM capabilities](PAM-CAPABILITIES.md) · [Security](../SECURITY.md)

Source distribution quality checks also run `python scripts/check_docs.py` and `python -m pip check`. The build produces `dependency-sbom.cdx.json`, a CycloneDX 1.5 inventory of locked source dependencies beside the archive/manifest. It does not certify deployed-host contents or absence of vulnerabilities.
