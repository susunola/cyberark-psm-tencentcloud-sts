# Acceptance record

[中文](ACCEPTANCE.zh-CN.md)

## Evidence status

The local offline suite is executed with mocked STS calls. Windows CI can validate Python compatibility and parse PowerShell; it cannot establish real PSM/browser/cloud behavior. Record actual environment results below. Do not convert a pending row into a pass without reproducible evidence.

| Area | Required evidence | Status |
|---|---|---|
| Offline unit tests | Test output, source commit, Python and dependency lock | Run locally; see delivery report |
| Windows/Linux CI | GitHub Actions run for this commit | Check workflow run |
| Windows service | WinSW version/hash, installation/start/stop/uninstall, ACL review | Pending environment |
| IIS authentication | Anonymous denial, genuine Windows identity, header overwrite, pipeline ordering | Pending environment |
| PSM launch | PAM/PSM version, browser/driver version, imported component export | Pending environment |
| Cloud role login | CAM trust, AssumeRole policy, console-enabled role, destination/identity evidence | Pending environment |
| Cloud restrictions | Invalid/disabled key, unauthorized role, duration, MFA/network conditions | Pending environment |
| Session isolation | Two users and two roles, separate cookies and processes | Pending environment |
| Recording | PSM recording ID/playback and audit correlation | Pending environment |
| Cleanup | Browser exits on logout/disconnect/timeout, no orphan process | Pending environment |
| Credential exposure | Browser tools, process args, service/proxy logs and callback URL review | Pending environment |
| Lifetime | Actual console cookie behavior vs STS and PSM durations | Pending environment |
| Upgrade/rollback | Previous/new versions, settings/ACL preservation, successful rollback | Pending environment |

## Test steps

1. Record tester, date, operating system, PAM/PSM version, Web framework, browser/driver, Python, WinSW, role ARN (sanitize for public records), source commit and configuration revision.
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
