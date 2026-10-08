# Partner lab acceptance without distributing a PAM license

[中文](PARTNER-ACCEPTANCE.zh-CN.md)

## Purpose and limits

An authorized lab owner can run this procedure in their own licensed, isolated lab and return sanitized evidence. No license or installation media needs to be shared with the project. This is an acceptance procedure, not a certified native platform import package. A source test pass does not establish vendor support or compatibility with any PAM release.

Before scheduling, the lab owner must confirm that their license permits this use, custom PSM connection components are allowed, and they can administer the Windows PSM host. Do not use customer production credentials. Agree on the exact PAM/PSM release and its supported Windows/browser versions; the bridge's Windows test matrix is not the vendor's support matrix.

## Delivery contents

Build a source archive from the exact commit being tested:

```bash
python scripts/build_release.py --out dist
```

Deliver the resulting source ZIP, SHA256SUMS and dependency SBOM together. The ZIP contains the [installation manual](INSTALLATION-AND-USAGE.md), [acceptance ledger](ACCEPTANCE.md), deployment templates, tests and the [result template](PARTNER-ACCEPTANCE-RESULTS.example.json). Record the Git commit separately: a version string alone does not identify a development build. Verify hashes after transfer. Never include local settings, environment files, tokens or a complete callback URL.

## Before obtaining the environment

Run the transport contracts without a PAM license:

```bash
python -m unittest discover -s tests -p test_pvwa_https_contract.py -v
```

These tests use a loopback HTTPS server with synthetic PVWA responses and temporary certificates. They exercise the actual Requests adapter, TLS trust/hostname verification, approval payload serialization, denial/redirect handling, one-attempt writes and partial recovery inventory refusal. They do not emulate a Vault, a PSM session or a recording. OpenSSL is required; a skipped suite is not a pass. The full suite and CI cover further concurrency, rotation and failure cases.

## Lab setup and execution

1. Create a dedicated test Safe, least-privilege international Tencent Cloud caller and a read-only role. Use two separate human Windows identities and test accounts for isolation checks. Keep real keys inside the lab owner-controlled Vault. Establish who is authorized to clean up cloud resources.
2. Follow the installation manual on the supported PSM host. Configure IIS Windows authentication, deny anonymous requests, overwrite forwarded identity/key headers and restrict direct backend access to loopback. Import/configure the connection component using the installed PSM release's supported workflow. Capture the resulting component export and version, excluding secrets.
3. Obtain an authorized PVWA session using the lab's normal authentication/MFA process. Set `PVWA_API_URL`, `PVWA_TOKEN` and, when needed, `PVWA_CA_BUNDLE` in a private shell. Run the read-only probe below. Unsupported resources and denied permissions must be recorded as such, not converted into successful tests.

```bash
python scripts/pamctl.py capabilities
```

4. Run the account/profile preflight with the documented CLI and review the output before any writes. Follow the [acceptance steps](ACCEPTANCE.md#test-steps). Approval bypass, credential extraction and unauthorized roles must fail. Complete every required case below.
5. Correlate the bridge request ID and role session name with the PSM recording and cloud audit event inside the lab. Return sanitized references, not recordings containing keys or personal data. Compare console-cookie lifetime with STS lifetime; PSM disconnect does not itself prove cloud credential revocation.
6. Uninstall the bridge, remove only test-created accounts/roles/resources, and verify their absence. Record settings/ACL preservation, absence of orphan browser processes and any remaining resources. The lab owner retains responsibility for PAM media and licenses.

## Required cases and evidence

| ID | Case | Evidence needed to mark passed |
|---|---|---|
| AUTH-01 | Anonymous and forged-header requests denied | Sanitized HTTP status and IIS authentication/configuration evidence |
| LOGIN-01 | Authorized PSM console login | PAM/PSM/browser versions, component revision, destination and signed-in test identity |
| DENY-01 | Wrong/disabled keys and unauthorized role rejected | Sanitized refusal and absence of a usable login |
| REPLAY-01 | CSRF replay and duplicate fields rejected | Refusal statuses and correlated bridge audit references |
| ISOLATE-01 | Two users sequentially and concurrently | Separate identities, cookies/processes and role session names |
| RECORD-01 | Recording playback and audit correlation | Lab-retained recording reference and matching correlation evidence |
| CLEANUP-01 | Logout, disconnect and timeout | Process cleanup, recording availability and actual cookie/STS behavior |
| SECRET-01 | Credential exposure review | Review of process arguments, browser surfaces, proxy/service logs and callback handling |
| ROLLBACK-01 | Upgrade, rollback and uninstall | Version hashes, settings/ACL preservation and readiness checks |
| CPM-01 | Native CPM completion, if in scope | Installed platform/CPM revision and completed task status; submission alone is insufficient |

Use [the result template](PARTNER-ACCEPTANCE-RESULTS.example.json). Leave unexecuted cases `pending`; use `blocked` for absent prerequisites, `failed` for observed failures, and `not-applicable` only with an explanation. Every `passed` case needs a lab-retained evidence reference. Redact credentials, full callback URLs, tenant/account identifiers and personal data before sharing. Keep raw evidence private with the lab owner. A partner pass is an environment-specific result, not CyberArk certification or universal version support.
