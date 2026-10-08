# Acceptance record

[中文](ACCEPTANCE.zh-CN.md)

## Evidence status

The local suite includes real loopback HTTP requests to Waitress, with mocked STS calls. TLS/IIS remain untested; live international STS and Windows CVM evidence are recorded below. Windows CI can validate Python compatibility and parse PowerShell; it cannot establish real PSM/browser/cloud behavior. Record actual environment results below. Do not convert a pending row into a pass without reproducible evidence.

| Area | Required evidence | Status |
|---|---|---|
| Offline unit tests | Test output, source commit, Python and dependency lock | Run locally; see delivery report |
| Windows/Linux CI | GitHub Actions run for this commit | Check workflow run |
| Windows service | WinSW version/hash, installation/start/stop/uninstall, ACL review | **Passed 2026-10-08 on real Tencent Cloud Windows Server 2022/2019/2016/2012 R2 CVMs**, Python 3.13.7 / PowerShell 5.1 / WinSW 2.12.0; see [CVM report](WINDOWS-CVM-ACCEPTANCE.md) |
| IIS authentication | Anonymous denial, genuine Windows identity, header overwrite, pipeline ordering | Pending environment |
| PSM launch | PAM/PSM version, browser/driver version, imported component export | Pending environment |
| Cloud role login | CAM trust, AssumeRole policy, console-enabled role, destination/identity evidence | **Partially verified 2026-10-07** on an international account: AssumeRole succeeded for a probe role with `ConsoleLogin=1` and a 300-second request was accepted and returned `expires in 300s`. Console-side login in a browser is still pending. |
| STS duration | The configured `duration_seconds` is accepted by the API, and the role's own limit does not floor it | **Verified 2026-10-07**: `AssumeRole` with `DurationSeconds=300` succeeded against a role whose `SessionDuration` is 7200s, so the role value is a ceiling rather than a floor and the project's 300-second policy is usable. Re-check against your own role. |
| Callback signature | Tencent's role-login callback accepts a signature built by this project | **Cannot be verified without a browser.** A server-side request to `www.tencentcloud.com/login/roleAccessCallback` returns the same 29 KB HTML shell with or without parameters, and identically for a correct and a deliberately tampered signature, so the endpoint does not validate the signature for a plain GET. |
| Identity binding | `GetCallerIdentity.UserId` equals the caller UIN for the credential kind `pam/cloud.py` verifies | **Partially verified 2026-10-07** against `sts.intl.tencentcloudapi.com` with an international CAM sub-user caller: `Type=CAMUser`, `UserId=200037920937` equals the caller UIN, so the comparison in `verify()` holds for the permanent caller keys it is used with. It would not hold for temporary credentials, whose `UserId` is `roleId:roleSessionName`; `verify()` must not be called with those. |
| Cloud restrictions | Invalid/disabled key, unauthorized role, MFA/network conditions | Pending environment (duration verified above) |
| Session isolation | Two users and two roles, separate cookies and processes | Pending environment |
| Recording | PSM recording ID/playback and audit correlation | Pending environment |
| Cleanup | Browser exits on logout/disconnect/timeout, no orphan process | Pending environment |
| Credential exposure | Browser tools, process args, service/proxy logs and callback URL review | Pending environment |
| Lifetime | Actual console cookie behavior vs STS and PSM durations | Pending environment |
| Upgrade/rollback | Previous/new versions, settings/ACL preservation, successful rollback | Pending environment |

## Test steps

1. Record tester, date, operating system, PAM/PSM version, Web framework, browser/driver, Python, WinSW, role ARN (sanitize for public records), source commit and configuration revision.

Role trust on this international account: `qcs::cam::uin/<root>:uin/<sub-user>` was rejected as `InvalidParameter.PrincipalQcsError` even for a sub-user that `ListUsers` reports, while `qcs::cam::uin/<root>:root` is accepted and is what existing roles in the same account use. `scripts/acceptance_live.py --provision` therefore tries the narrow form first and falls back to the account scope, reporting which it used; the probe role carries no policies, so the wider trust confers no permissions, and the role is deleted again unless `--keep-role` is given.

`scripts/acceptance_live.py` performs the read-only part of this ledger (caller identity and AssumeRole durations) against the real international endpoint, reporting credential names and error codes but never their values. Run it before the PSM work so a broken trust relationship or an unacceptable duration is found early.
2. Use a dedicated read-only role and test caller. Confirm destination identity and allowed operations. Verify disallowed resource operations fail.
3. Retry with a bad/disabled key, missing trust and missing AssumeRole permissions; each must fail without issuing a usable login. Restore test configuration afterwards.
4. Attempt a different profile with the same caller SecretId, duplicate form fields, replayed CSRF, anonymous proxy access and forged headers; confirm denial.
5. Test two users and roles sequentially and concurrently. Verify no reused browser identity/cookies and unique request IDs/role session names.
6. Exercise browser close, PVWA disconnect and timeout. Confirm process cleanup and recording availability. Compare role session name in cloud audit records to the bridge correlation ID and PSM session.
7. Test credential expiration and actual console session lifetime independently. Do not assume closing PSM revokes cloud credentials.
8. Inspect all logging and browser extraction paths. Retain only sanitized screenshots and recording references. Never publish complete callback URLs or secrets.
9. Install, upgrade, rollback and uninstall on a staging clone. Verify no unrelated site/component is modified.

## Release gate

Production support and AWS-connector quality equivalence cannot be claimed until the environment rows pass and documented version coverage exists. Unit tests and source packaging are necessary but not sufficient.

## Administrative toolkit (0.3.0)

Offline tests cover lifecycle retention, uncertain writes, scope/identity checks, role failures, explicit write guards, REST request shapes and CVM plans. API calls are mocked. Live CAM rotation, PVWA onboarding/approval/session controls and guest SSH/RDP require separate target-environment acceptance. See [capability boundaries](PAM-CAPABILITIES.md).

## Shared tokens and native operations (0.4.0)

Dedicated CI validates actual Redis token races/expiry/cross-node form consumption. Production TLS/failover fencing and target PSM remain unverified. Native CPM task completion, connection/playback response compatibility and maintenance jobs need target acceptance. No native platform/CPM import package is certified.

2026-10-08 retest: international `GetCallerIdentity` and 300-second `AssumeRole` passed. The authorized policy-free temporary role was deleted and its absence verified. Correct/tampered callback signatures both returned HTTP 200 without redirect, so browser/signature acceptance remains pending. See [current cloud compatibility evidence](DEPLOYMENT.md).
