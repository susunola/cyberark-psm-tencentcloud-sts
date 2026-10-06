# PAM capabilities and version boundaries

**English** | [简体中文](PAM-CAPABILITIES.zh-CN.md)

0.3.0 adds an administrative toolkit alongside the console bridge. Run it from a protected administrative workstation, not from the PSM browser or its service account. It uses public Tencent SDK APIs and PVWA REST; no CPM SDK is required. No CyberArk version has been certified. Prefer the modern `/PasswordVault/API` account API family; legacy-only installations need an adapter. Unsupported APIs or insufficient permissions fail closed. `capabilities` probes account/session/recording/request read endpoints, not write permissions or installed components.

| Capability | Delivery | Boundary |
|---|---|---|
| Console federation | Bridge, caller/role restrictions, short-lived STS | Mainland Tencent role callback; live PSM acceptance pending |
| Key lifecycle | Verify, prepare replacement, finalize, restore old | External workflow; not a native CPM plug-in; scheduled preparation requires tested cutover |
| Discovery | CAM users/key metadata, paginated regional CVM inventory | Explicit authorized regions; no passwords discovered |
| Onboarding | PVWA account creation and CVM proposals | Existing Safe/platform/custom properties required |
| SSH/RDP | Guest proposals and native PSMConnect invocation | Existing native components and valid guest credentials required |
| Approval | Create connection requests; list requests; individual confirm/reject | Native dual-control, reason/ticket policies and approver permissions remain authoritative |
| Session administration | List, suspend, resume, terminate | Authorized operator; endpoint support depends on PVWA/PSM version |
| Recording | Metadata/activity/validity queries and protected playback response | PSM produces and retains recordings; this tool does not record or export video |
| Vault authorization, MFA, Safe policies, credential checkout | Existing PAM controls | Configure in PAM; no replacement or bypass is supplied |
| CPM reconciliation, CVM password rotation | Scoped native guest CPM task submission / external key reactivation | Key restoration is not password reconciliation or recovery of deleted keys |
| HA / disaster recovery / analytics | Deployment and native PAM operations | Local tokens by default; optional shared Redis with documented failover boundaries |

0.4.0 adds native CPM/PSM/recording operations, recovery, one-shot maintenance and optional Redis tokens. See [operations guide](OPERATIONS.md).

## Authentication and permissions

Install `requirements.lock.txt` into an administrative Python environment. Set `PVWA_API_URL` to an HTTPS URL ending in `/PasswordVault/API`; set `PVWA_TOKEN` to an existing authorized session token. Optional `PVWA_CA_BUNDLE` supplies a trusted CA file. Tokens must come from your approved authentication/MFA flow. TLS verification is mandatory, redirects are rejected, environment proxy/netrc settings are not used. REST calls have bounded timeouts and do not automatically retry writes.

For cloud discovery/rotation set `TENCENTCLOUD_SECRET_ID` and `TENCENTCLOUD_SECRET_KEY` in the administrator process. Use a dedicated CAM sub-user, not root credentials. Read-only discovery needs CAM ListUsers/ListAccessKeys and CVM DescribeInstances. Rotation additionally needs CreateAccessKey/UpdateAccessKey for the intended target sub-user. Keep those management permissions separate from console bridge callers, which need only AssumeRole. Verify target UIN ownership before cutover. Restrict PVWA tokens to required Safes and actions; approver and requester identities should follow your dual-control policy.

Environment variables are a process input, not a recommended long-term secret store. Use an approved credential provider, avoid shell-history literals, and clear the process environment after use. CLI never accepts SecretKeys on argv. Inventory, request/recording metadata and ticket files may contain sensitive identifiers; protect them and never publish them.

## CLI examples

Commands below omit `--apply` deliberately: mutations return `no-write` without accessing cloud/Vault. This is a guard, not a validated execution plan. Read commands access the APIs with your configured credentials.

```text
python scripts/pamctl.py capabilities
python scripts/pamctl.py discover --regions ap-guangzhou ap-shanghai
python scripts/pamctl.py cvm-plan --inventory inventory.json --usernames usernames.json --safe CloudGuests --linux-platform UnixSSH --windows-platform WinServerLocal
python scripts/pamctl.py list LiveSessions --limit 100 --offset 0
python scripts/pamctl.py list Recordings --limit 100 --offset 0
python scripts/pamctl.py list MyRequests
python scripts/pamctl.py list IncomingRequests
python scripts/pamctl.py request --account 1_2 --component PSM-SSH --reason "Approved maintenance"
python scripts/pamctl.py decision --id request-123 --decision confirm --reason "Reviewed scope"
python scripts/pamctl.py session --id session-123 --action suspend
```

List commands return one native page, not a complete export. Use `--offset` for sessions/recordings. Verify incoming request details in PVWA before a decision; do not automatically approve lists. Suspend/resume/terminate operate only on the specified session; termination does not revoke independently issued Tencent credentials or already established cloud sessions.

`usernames.json` is an object mapping instance IDs to explicitly confirmed guest usernames. The CVM plan selects the first private IP and skips unknown OS, missing usernames and missing private IPs. It neither opens network paths nor guesses credentials. For each approved proposal, provide a valid `secret` through secure stdin to `onboard --safe CloudGuests --platform UnixSSH --apply`. `connection_component` is local planning metadata stripped before submission; configure connection component assignments in the native platform. Keep automatic management disabled until the native guest CPM platform has passed verification.

## Two-stage CAM key rotation

The old account must have `TencentSecretId` and `TencentRoleProfile` custom properties enabled in its native platform. Configure the target Safe/platform before running any write. A replacement is a separate Vault account, never an overwrite of the only working secret.

1. Run `prepare --old-account 1_2 --target-uin 123456789 --profile readonly --ticket rotation.json --apply`. The CLI reserves a journal before cloud writes, checks a conservative two-key capacity, verifies ownership, creates a replacement, verifies its identity, then stores the new pair in Vault. The old key stays active. Target must be a listed CAM sub-user; root keys are refused. Serialize operations per target UIN.
2. Add the replacement SecretId to the same bridge profile allowlist, keeping the old ID until cutover completes. Assign native permissions/connection settings to the replacement account. Validate an actual PSM console session, recording, approvals and role permissions with that account.
3. Run `finalize --ticket rotation.json --settings settings.json --confirm-psm-cutover --apply`. This requires your explicit confirmation of step 2, rechecks both Vault account scopes and key bindings, verifies the new identity and AssumeRole, then deactivates the old key. It does not prove browser login or recording itself.
4. If necessary run `restore-old --ticket rotation.json --apply`, restore bridge allowlist/PVWA access and retest the old account. Reactivation requires that the key still exists. Deletion is intentionally absent; remove the old key/account later under your retention/change policy.

Prefix commands with `python scripts/pamctl.py`. Successful tickets contain identifiers only. If prepare fails, its reserved journal remains and may contain only operation/UIN metadata. **Do not delete the journal and blindly rerun**: check the key description `psm-rotation:<operation>` and Vault replacement name `tc-rotation-<operation>`, reconcile uncertain cloud/Vault writes and record the outcome. A timed-out disable may already have succeeded; inspect the target key status. Do not dump raw API responses containing SecretKeys into logs. Python cannot guarantee secret memory zeroization.

## Validation and remaining acceptance

Offline tests cover write guards, HTTPS/no-redirect behavior, request shapes, target ownership, staged key retention, uncertain writes, scope changes, role verification failures, rollback and guest planning. CI exercises Python 3.11–3.13 on Windows/Ubuntu. SDK and REST calls are mocked in these tests; no live Tencent/PVWA mutations have been performed by this project validation.

Before production: test the actual PVWA endpoint/permissions and custom properties, install the chosen PSM connection framework, verify caller/role policy, and record SSH/RDP/console/approval/recording/rotation/rollback results. SDK-independent interfaces broaden portability; they do not establish compatibility with all CyberArk releases. A directly importable native platform/CPM package still needs target-version packaging and validation.

## Interface references

- [CyberArk official EPV API scripts](https://github.com/cyberark/epv-api-scripts), including [EPV-API-Common](https://github.com/cyberark/epv-api-scripts/tree/main/EPV-API-Common): request, session and recording endpoint references. Its distribution is labeled Alpha; target-version acceptance remains required. No upstream code is redistributed here.
- [Tencent CAM API overview](https://cloud.tencent.com/document/product/598/33155).
- [Tencent STS GetCallerIdentity](https://www.tencentcloud.com/document/product/1150/49453).
