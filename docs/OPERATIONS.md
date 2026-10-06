# Native operations, maintenance and shared tokens

**English** | [简体中文](OPERATIONS.zh-CN.md)

## Native guest CPM and PSM

These commands invoke installed CyberArk components rather than implementing guest password protocols. A target Windows/Linux guest account must already use a verified native platform and, for reconciliation, a configured reconciliation account. All writes default to `no-write`.

```text
python scripts/pamctl.py cpm --account 1_2 --action Verify --safe CloudGuests --platform UnixSSH
python scripts/pamctl.py cpm --account 1_2 --action Change --safe CloudGuests --platform UnixSSH
python scripts/pamctl.py cpm --account 1_2 --action Reconcile --safe CloudGuests --platform UnixSSH
python scripts/pamctl.py status --account 1_2
python scripts/pamctl.py connect --account 1_2 --component PSM-SSH --reason "Approved maintenance" --ticket-id CHG1 --ticket-system ServiceNow --out connection.json
python scripts/pamctl.py recording --id recording-123 --section activities
python scripts/pamctl.py recording --id recording-123 --section valid
python scripts/pamctl.py playback --id recording-123 --out playback.json
```

Add `--apply` only after reviewing the account/component and native policy. A CPM submission is asynchronous: `submitted-to-CPM` does **not** mean the guest password was changed. Check `status` and the native CPM logs. CAM key accounts are refused by guest CPM commands; they use staged key rotation.

Connect and playback capture JSON returned by the native endpoint into an exclusive output file, never stdout. Use the response with the configured native PSM client/player. Endpoint response formats vary; non-JSON launch responses are rejected rather than guessed. This tool does not automatically execute local RDP files, follow playback URLs, download recordings or bypass native approval/ticket policies. Generated responses may contain short-lived authentication material. On Unix outputs use mode 0600; on Windows use a directory whose ACL permits only the authorized operator/system. Remove launch files after use under your policy. If an API call or local save fails, an empty/partial reserved output may remain; inspect before retrying.

`capabilities` now makes GET probes for Accounts, LiveSessions, Recordings, IncomingRequests and MyRequests. It distinguishes authentication/permission errors, hidden or absent endpoints and other failures. A 404 is not proof that a feature is unsupported. Read capability does not establish write permission, installed components or compatibility with every version.

## Recover a preparation interrupted after a write

```text
python scripts/pamctl.py recover-ticket --journal rotation.json --ticket rotation-recovered.json
```

With `--apply`, this reads cloud/Vault inventory, requires exactly one active cloud key marked with the journal operation, exactly one matching saved replacement account, unchanged Safe/platform/user/address and a verified new credential identity. It writes identifiers only and never creates another key or deactivates anything. Continue with the normal tested-cutover/finalize flow using the recovered ticket. A missing/ambiguous Vault save cannot be recovered automatically: new SecretKeys cannot be read back from Tencent inventory. Retain the old working key and reconcile under your change procedure. Journals from 0.3.0 lacking account/profile scope require manual reconciliation.

## Scheduler-neutral maintenance

`deployment/maintenance.example.json` defines non-secret jobs. `verify-cam` retrieves the authorized Vault secret, verifies the target UIN and verifies AssumeRole for the configured bridge profile. `prepare-key` only prepares a replacement and requires a later tested cutover. Both pin Safe, platform, profile and caller allowlist. Unknown actions, including automatic finalize, are refused.

```text
python scripts/run_maintenance.py --jobs maintenance.json --settings settings.json --state-dir maintenance-state
```

Without `--apply` no jobs run. Provision a protected state directory, review the manifest, then add `--apply`. Execute from your organization's scheduler through a protected wrapper which obtains a **fresh** PVWA session and cloud credentials for each run. Do not put tokens or keys in Task Scheduler/cron arguments or job manifests. Native guest password rotation should use the installed native CPM platform's schedule.

Only one runner may use a state directory at a time. A crash lock is not stolen automatically: check the process/outcome before removing it. A prepare job retains its journal/ticket and refuses another run with the same ID; it cannot repeatedly mint replacements. Archive a completed ticket only after cutover and retention review. A failure stops later jobs; uncertain writes retain recovery journals. Use one scheduling authority per target UIN; the filesystem lock is not a distributed cloud lock. No scheduled job claims browser/recording acceptance or stops the old key automatically.

## Shared token deployment

Default mode remains a single process with bounded in-memory tokens. For multiple nodes use Redis 7+ with TLS and ACLs, identical session keys and a deployment-specific namespace. Node-local IIS authentication/proxy keys remain independently protected. All nodes must receive the same authenticated user identity format. Role configuration must be deployed consistently; STS admission remains two concurrent requests **per node**.

Set `PSM_TC_REDIS_URL` to a `rediss://` URL without query overrides, optional `PSM_TC_REDIS_CA_BUNDLE` to a readable trusted CA file, and `PSM_TC_REDIS_NAMESPACE` to a unique name. Or use `PSM_TC_SHARED_CONFIG` pointing to a protected JSON file based on `deployment/shared-secrets.example.json`; its `session_key` overrides the node's session key. The example is not usable without replacing credentials and generating an independent random cluster session key. Do not commit the resulting file.

Windows installations can use:

```powershell
.\scripts\Configure-SharedTokens.ps1 -InstallDir C:\PSM-TencentCloud -SharedSettingsFile C:\Protected\shared-secrets.json
```

Default invocation changes nothing. Drain connections, then use `-Apply -Restart` to validate Redis/TLS, copy the configuration with restricted ACLs and configure the installed WinSW service. CA files must be readable by LocalService. Service XML is preflighted with DTD disabled, then atomically replaced under an exclusive update lock. Existing shared-secret files and backups are never overwritten. A crash lock must be inspected before removal. The original service XML is backed up as `PSMTencentCloudSTS.xml.before-shared` inside the protected installation directory. A partial failure requires checking service/configuration state; restore that backup and the original token mode if needed. This script has been syntax-checked, not executed on a target PSM installation.

Lua scripts use Redis server time, enforce one shared outstanding-token capacity, and atomically check identity/expiry and consume the token on the primary. Stored token/identity values are hashed. Redis outages fail closed with 503; there is no fallback to node-local tokens and no automatic retry of uncertain consumes. Authenticated `/healthz` reports Redis availability. Changing session keys invalidates pending forms; start new PSM connections after changes.

**Failover boundary:** atomic primary execution is not an exactly-once guarantee across asynchronous replica failover or backup restoration. Redis state rollback can restore consumed tokens. Before resuming traffic after such an event, rotate the shared session key across all nodes and invalidate pending connections. Do not restore old token data into an active cluster. Load balancer health checks alone cannot fence stale Redis primaries; require a single writable primary and a coordinated failover procedure. Production TLS, ACLs, replication/fencing and load-balancer behavior still require target-environment acceptance.

The dedicated CI job runs real Redis 7.2.5 and verifies cross-node consumption, concurrent replay, server expiry, capacity, hashed records and a browser form POST routed to another app instance. TLS configuration and fail-closed outages have unit tests; real Redis transport in CI uses loopback plaintext and is not production TLS evidence.

Primary interface references: [CyberArk official EPV-API-Common](https://github.com/cyberark/epv-api-scripts/tree/main/EPV-API-Common), [Redis Lua scripting](https://redis.io/docs/latest/develop/programmability/eval-intro/) and [redis-py production usage](https://redis.io/docs/latest/develop/clients/redis-py/produsage/).

## Input and rotation checks (0.4.1)

All maintenance job identifiers/UINs and account/profile syntax are validated before any remote job runs; UIN aliases and case-insensitive filename collisions are rejected. Account Safe/platform/profile/allowlist checks remain per-job and are re-evaluated before use, not claimed as a transactional batch. Onboarding requires complete bounded string metadata and a string credential; CAM key accounts must explicitly disable native automatic management. Tickets validate identifiers and bind distinct old/new pairs. Rotation validates source metadata before key creation, rechecks key states after role verification and reads back retirement state before reporting success. Failed readback is an uncertain result (including possible consistency delay), requiring inventory reconciliation rather than automatic retry. API checks reduce races but cannot make separate cloud/Vault operations atomic; serialize target changes.
