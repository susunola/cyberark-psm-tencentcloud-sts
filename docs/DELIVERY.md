# Delivery ledger — 0.5.0

**English** | [简体中文](DELIVERY.zh-CN.md)

The repository implements a mainland Tencent console federation bridge and public-API administrative toolkit. It is not the CyberArk PAM product, a universally importable platform package or a certified AWS connector equivalent. This ledger separates implemented functions, existing native providers and external deliverables without treating mock tests as production evidence.

| Area | Implemented in this repository | Native/external boundary |
|---|---|---|
| Console | STS federation, caller/role allowlists, protected proxy, audit correlation | PSM browser isolation and actual login/recording acceptance |
| Key lifecycle | Verify, prepare, tested-cutover finalize, restoration, uncertain-write ticket recovery, scheduled verification/preparation | Native CPM engine package absent; no automatic finalize/delete |
| CAM/CVM | Scoped discovery, regional pagination, guest planning | Guest credentials/network/native SSH/RDP components |
| Onboarding | Single and batch PVWA onboarding, input/scope checks, durable attempt journal | Safe/platform/custom property provisioning and authorization in native PAM |
| Requests | Create, ticket/window fields, requester/incoming details, individual confirm/reject, explicit requester removal | Native approval/MFA/ticket policy and approver authority |
| Sessions | PSMConnect response, detail/activity/properties, suspend/resume/terminate | Native client/components and actual session execution |
| Recordings | Lists/details/activity/properties/validity/playback responses | PSM generates/retains/plays video; no custom video engine |
| Guest passwords | Native CPM Verify/Change/Reconcile submission and status | Verified native platform/reconciliation account; asynchronous completion |
| Exports | Bounded account/session/recording page traversal to private JSONL | API reads are not a transactionally consistent snapshot |
| Audit | UTC/schema fields, bounded deduplicated local aggregate report | Native threat analytics and organization-approved SIEM transport |
| Availability | TLS Redis shared tokens, fail-closed outages, atomic configuration replacement/backup | Redis primary fencing/TLS/ACLs and coordinated state-rollback response |
| Readiness | Local strict config validation, account binding and standard read-interface probes | Cannot prove write permissions, installed engines, real login or compatibility |
| Delivery | English-default bilingual documentation, CI, reproducible ZIP/SHA256 | Native package acceptance, certification and Marketplace submission |

## Remaining external deliverables

1. **Native CPM/PVWA import package.** Not supplied. Build from the licensed framework and exported platform/component schema matching the installed CyberArk environment. Public REST adapters and Python source cannot substitute for that engine/package. No proprietary SDK/binaries or fabricated process/INI package is included.
2. **Target-environment acceptance.** Not performed: live Tencent login/rotation and PVWA/PSM/CPM operations, approvals, recording, Windows service execution, production TLS/ACL/failover. A tested source package is not evidence for these.
3. **Supported-version certification and official contribution.** Not obtained/submitted. An all-version compatibility claim cannot be made without a defined supported matrix and real evidence. Marketplace contributor agreements and submission remain owner/customer actions.

Vault permissions, MFA, native recording, guest password protocols, Safe policy and PAM disaster recovery are provider capabilities to configure and validate, not separate copies of PAM to implement in this plugin. Mainland Tencent role federation is the current scope; international-site callbacks and legacy-only PVWA adapters are not supported/certified by this implementation.

## Completed administrative commands

All examples use `python scripts/pamctl.py`. Existing commands are documented in [capabilities](PAM-CAPABILITIES.md) and [operations](OPERATIONS.md).

```text
request --account 1_2 --component PSM-SSH --reason "Maintenance" --ticket-id CHG1 --ticket-system ServiceNow --from-date 1791331200 --to-date 1791334800
request-info --id request-123 --incoming
cancel-request --id request-123
session-info --id session-123 --section activities
export Accounts --out accounts-export.jsonl --limit 100 --max-pages 100
export LiveSessions --out sessions-export.jsonl
export Recordings --out recordings-export.jsonl
onboard-batch --safe CloudGuests --platform UnixSSH --journal batch-journal.jsonl
preflight --account 1_2 --safe TencentSafe --platform TencentSTS --component PSM-TencentCloud --settings settings.json
audit-report --input bridge.log --max-lines 100000
```

Request windows are explicit Unix seconds UTC; the numbers above demonstrate syntax, not a current approved window. Supply both window endpoints and both ticket fields. Native API policies remain authoritative. Request removal does not terminate active sessions or revoke cloud credentials. Creation/removal/batch mutations require `--apply`; dry guard mode performs no network requests. Inspect incoming details in PVWA before approving. Do not automate approvals.

Exports create exclusive protected JSONL files. A final `export-completed` record with `complete: true` confirms traversal completed under its bounds. Repeated pages, inconsistent empty pages or the page cap fail without that marker. Partial files are incomplete evidence. Server-provided next URLs are never followed; offsets are constructed against the configured PVWA host. Concurrent account/session changes can still alter pages, so this is not a point-in-time backup. Export rows are buffered for throughput; the completion marker is flushed/fsynced.

Batch onboarding consumes a complete account array through secure stdin (never secret argv/files in the repository). Validate all entries and case-insensitive names, probe existing Safe/name matches, then create sequentially. The exclusive journal stores fsynced attempt/confirmation records containing metadata and IDs only. There is no automatic retry/rollback after a failure. A final attempt without confirmation may already have created its account: search PVWA by Safe/name, reconcile and record the outcome before deciding the next action. Do not rerun the whole batch using another journal blindly. Native races between name lookup and account creation cannot be eliminated by this tool.

Preflight makes read requests only, prints limited binding/probe evidence, and exits 3 on a failed account scope/caller binding. An available platform/connector-list endpoint does not prove a component assignment or working engine. Guest accounts check scope; console accounts additionally check configured caller/profile binding. Refer to `not_verified` in the output for mandatory environment acceptance.

Audit reports deduplicate http/role events by request ID and emit status/profile counts only. They omit identities, URLs, arbitrary raw fields and credentials, and reject oversized inputs instead of claiming a complete report. They are local usage/error aggregates, not a threat-detection engine or a recording audit replacement. Keep inputs/outputs protected and select non-overlapping log sets appropriately.

## Upgrade note

From 0.5.0 the bridge imports `pam.audit`. In addition to root runtime files, deploy **`pam/__init__.py` and `pam/audit.py`** with the same protected ACLs. The installer includes only this minimal runtime subset, keeping management/rotation code outside the service installation. Existing installations follow the stopped-service staging/rollback process; do not overwrite service secrets. Installed-layout imports have an isolated subprocess test.
