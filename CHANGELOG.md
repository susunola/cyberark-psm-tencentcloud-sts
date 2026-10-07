# Changelog

## Unreleased

- Add a Windows CI job that runs the installer for real instead of reasoning about it: it fetches a pinned WinSW release and confirms the artifact hash, then runs `Install-Bridge.ps1` end to end on a Windows Server 2025 runner. It asserts the two behaviours that were previously only asserted as text - that `web.config.generated` grants no LocalService or broad principal access while the install directory still grants LocalService read so the service can start, and that a WinSW binary whose hash does not match is refused before the install directory is created. It then checks the authenticated readiness probe (and that the same probe without the proxy key returns 403), and that `Uninstall-Bridge.ps1` stops the service while preserving the files. Installer output and service logs are uploaded as diagnostics.
- Note what a Windows machine still cannot verify: IIS Windows Authentication and the PSM WebForm component need their own environment and, for PSM, a licensed CyberArk installation, so those remain acceptance items however the Windows host is obtained.
- Pin the security-relevant statements of the three deployment scripts that cannot be executed here. `Configure-SharedTokens.ps1` is asserted to remove inheritance, grant exactly SYSTEM/Administrators full plus LocalService read, have the protection follow the copy and precede the service-configuration write, and to refuse an existing configuration or a running service; `Uninstall-Bridge.ps1` is asserted to preserve the service configuration as audit evidence. The LocalService read grant in the shared-token script is deliberate and required, unlike the generated proxy configuration, and the assertions say so.
- Correct the assumption that the PowerShell suite is Windows-only: `tests/test_service_config.py` executes `Shared-ServiceConfig.ps1` through `pwsh` on any platform where it is on PATH, and it passes locally. The contributing guide now says which scripts can never be executed outside their target and that their behaviour is an acceptance item rather than a test.
- Verify the STS duration against the real international API. `AssumeRole` with `DurationSeconds=300` succeeds against a role whose own `SessionDuration` is 7200s, so that value is a ceiling rather than a floor and the project's 300-second credential policy is usable. This closes the open question about whether the configured duration was rejected by the API, and it is recorded in the acceptance ledger together with the role shape used (`ConsoleLogin=1`).
- Confirm the identity binding with real credentials: a CAM sub-user caller returns `UserId` equal to its UIN, so the comparison `pam/cloud.py verify()` performs is correct for the permanent caller keys it is used with. It would not hold for temporary credentials (`roleId:roleSessionName`), which is now stated where the check is documented.
- Record that Tencent's role-login callback cannot be validated without a browser: a server-side request returns the same 29 KB HTML shell with or without parameters and behaves identically for a correct and a tampered signature, so the endpoint does not check the signature for a plain GET. `scripts/acceptance_live.py` performs the checks that do not need one, can provision a throwaway probe role for them, and reports the trust scope it used.
- Document the international trust-policy detail found while provisioning: `qcs::cam::uin/<root>:uin/<sub-user>` is rejected as `InvalidParameter.PrincipalQcsError` in this account while `qcs::cam::uin/<root>:root` is accepted, so the probe tries the narrow form first and falls back, reporting which it used.
- Attribute refused requests in the audit log: every response with status 400 or above now carries a fixed `reason` code and, once the identity header has passed shape validation, the `proxy_identity` that presented it. A bare status code could not separate form tampering from an outage. Only fixed codes are logged - form values, credentials and vendor text still never are - and a shape-valid identity that failed the comma rule is recorded so header smuggling is visible, while a malformed one is not echoed. The aggregate report still drops identities and reasons.
- Make the CAM sub-user bound explicit and configurable as `PSM_TC_MAX_CAM_USERS`. CAM's `ListUsers` has no pagination fields in `v20190116` and returns every sub-user in one response, so the previous bound of 1000 was a limit on an unbounded reply rather than an artificial page size: it is now overridable and the error names the knob, instead of leaving a large organisation at a dead end.
- Serialise interactive preparations per target. `pamctl prepare` now takes a lock beside the ticket and refuses to start while another run holds it, with a message that says so. The spare-slot check is check-then-act and the maintenance runner's lock never covered the interactive path, so two runs could leave three keys behind; using the CLI to serialise was previously only a documented request.
- Bound admission waiting: a submission now waits up to `PSM_TC_ISSUANCE_WAIT_SECONDS` (default 5) for an STS slot and only then receives 503/Retry-After, instead of being refused the moment the slots are taken. Measured before the change: 10 concurrent logins against a 0.5-second STS produced 8 failures, which PSM's form submission cannot recover from.
- Make the admission and identity bounds configurable without a rebuild: `PSM_TC_ISSUANCE_SLOTS` (default 3, deliberately one fewer than the waitress thread count so health checks keep a worker) and `PSM_TC_IDENTITY_CAPACITY`. Each is validated at startup and a malformed value fails closed with the sanitized startup message.
- Document that one Windows identity per person is a deployment prerequisite rather than an acceptance item. The proxy prerequisites previously described the authenticated account as "usually a PSM session account", which is exactly the shared shape that lets concurrent users evict each other's pending token and makes audit attribution impossible; the new prerequisite states the requirement and names the knob for deployments that cannot meet it.
- Add regression tests for both: the burst test asserts two callers share one slot by queueing (and fails if the wait is removed), and the identity tests document the default bound's assumption while proving a raised bound supports a shared identity.
- Fix the integration test teardown so it tolerates an empty key set: Redis removes an emptied collection itself, so the cleanup pattern can match nothing and `DEL` without arguments is an error. This was introduced with the per-identity index and only surfaces against a real server, which is why the integration suite is now also run locally before committing.
- Verify the shared-token semantics against a real Redis server rather than only in CI: cross-node atomic consumption (exactly one consumer wins), capacity, server-side expiry, the per-identity bound, and the absence of raw tokens or identities in the stored records.
- Add property-based tests for the security-critical validators: no destination other than the console host is ever accepted, a normalized audit label is always log-safe and bounded, an accepted route cannot escape the API prefix, the JSON size bound is never exceeded, and a failure message never echoes the credential material it was given. The signed canonical string is asserted verbatim.
- Add a model-based test for the rotation state machine, driving random prepare/finalize/restore/recover sequences and asserting after every step that a reported cutover left exactly one live key, that a key is only retired after another key was verified as the target identity, and that rotation never ends with zero usable credentials.
- Add `scripts/check_guard_mutations.py`: it disables each security guard in turn and requires the suite to fail, reporting the guards that no test protects (12 of 12 enforced today). It refuses to run while a target file differs from HEAD, so it can never hide uncommitted work.
- Audit the pinned dependencies for published advisories with `pip-audit` in CI, and record the dependency-hash completeness check in the quality job.
- Add hypothesis and pip-audit to the pinned developer tooling. The property and invariant suites skip cleanly when only the runtime lock is installed, and the CI matrix now installs the test tooling so they execute rather than skip.
- Answer an oversized request body from the application instead of the transport, so the 413 now carries the same security headers as every other response. The transport ceiling was raised above the application's 8 KB contract for that purpose; requests with oversized headers are still refused by the transport and SECURITY.md records that boundary.
- Make the dependency-hash check meaningful: a recorded hash that the index no longer publishes fails the build, while an upstream artifact we have not recorded only asks for a regeneration. It runs in the CI quality job, so a stale or tampered lock is caught automatically.
- Assert the installer's security-relevant statements statically: hash-verified installation is preferred over the plain lock, the generated proxy configuration is re-protected to SYSTEM and administrators only after it is written, and the proxy template replaces the identity headers instead of appending to them.
- Bound pending form tokens per identity (evicting that identity's oldest), so one proxy-authenticated caller can no longer exhaust the shared pool and deny connections to everyone else. The global capacity still refuses rather than evicting other callers' tokens.
- Reserve the issuance slot before consuming the single-use token, and burn the session copy only at that point: a 503 "busy" no longer forces a form reload and re-entry of the SecretKey.
- Reject a comma-joined or space-padded `X-PSM-Authenticated-User`. The HTTP server joins repeated headers, so an appended value previously entered the audit identity and the token binding key together.
- Reject `?`/`#` in the PVWA API base URL and `.`/`..` route segments. An empty query or fragment parses as falsy but the raw delimiter survived into every later URL and silently retargeted the request to the API root.
- Bound and control-character-check the vendor strings and address lists copied into cloud inventory output.
- Re-protect the generated IIS proxy configuration so only SYSTEM and administrators can read it; the install directory grants LocalService read for the service XML, which previously made the proxy key readable to any LocalService process.
- Ship a hash-pinned `requirements.lock.hashes.txt` and install with `--require-hashes` on the deploy host, so a substituted dependency cannot execute with administrator rights. `scripts/pin_lock_hashes.py` regenerates it and can verify it is in sync.
- Document that requests rejected by the HTTP server itself (413/431) never reach the application and therefore carry none of its security headers.
- Refuse to retire a key unless the target holds exactly the rotation pair, so a second concurrent preparation can no longer leave an unverified key live under a "cutover complete" report.
- Validate and de-duplicate the CAM access-key inventory before any retirement decision; a malformed, repeated or unexpected record now fails loudly instead of collapsing into a wrong key state.
- Require the full Vault binding, account scope and bridge allowlist before `restore-old` reactivates a key, and read the state back afterwards. A hand-written ticket can no longer revive an unrelated or incident-disabled key.
- Align the accepted `duration_seconds` floor with the runtime credential margin (31..300): shorter values could never satisfy the margin, so they previously produced a permanently failing profile.
- Report the real cause when STS returns credentials that expire inside the margin; the diagnosis was previously swallowed by the sanitizing handler and surfaced as a generic STS failure.
- Adopt one quality toolchain for local use and CI: ruff for lint, mypy for typing and `coverage run -m unittest discover` for the suite. `requirements-dev.txt` pins the tooling and a pre-commit configuration mirrors it on upstream tags.
- Raise the enforced coverage gate from 80% to 95%; the measured total is 99.5% with 14 of 16 modules at 100%.
- Define the type-checked surface once in `pyproject.toml` and extend it to `scripts/`, so the CLI that drives real credentials is checked too.
- Fix the `mypy` step failing on `waitress`, which ships no type stubs; only that import code is suppressed, so every real type error still fails the build.
- Fix `pam.audit.event` so caller fields can no longer overwrite `schema_version` or `timestamp`, keeping emitted records unforgeable at the schema level.
- Fix non-string and malformed input handling: both token stores now validate capacity and TTL type (rejecting booleans and numeric strings) instead of raising `TypeError`, and `pam.vault` rejects non-string account IDs and non-object search results with `ValueError`/`VaultError` instead of `TypeError`/`AttributeError`.
- Expand the offline suite with additional adapter, boundary and failure-path tests covering request construction, error sanitization, pagination and totals, token backends, maintenance locking, staged-rotation refusals and startup failures.
- Do not enforce `ruff format`: the test and script suites keep intentional compact one-liners, so lint is enforced and formatting is not.
- Keep the stricter PVWA base-URL, token, route and inventory rules from 0.5.2 unchanged.

## 0.5.2 — 2026-10-07

- Bound CAM/CVM discovery to 20 unique prevalidated regions, 1,000 users, 100 pages per region and 10,000 instances overall; reject repeated IDs, invalid pages and changing totals rather than return partial inventory.
- Accept syntactically valid region suffixes while leaving availability to cloud validation; prevalidate key mutations and identity targets before remote calls.
- Reject malformed PVWA API bases, control-character tokens, false-equivalent TLS settings and invalid routes before transport.
- Add offline documentation/CLI validation and dependency consistency checks to all CI jobs.
- Include a deterministic CycloneDX dependency inventory beside source distributions; this is not a vulnerability scan or deployed-host inventory.
- Add inventory/transport failure regression tests without claiming live PAM acceptance.
- Raise code quality to a strict, CI-enforced baseline: add `pyproject.toml` with ruff, mypy (disallow untyped defs) and coverage configuration.
- Add complete type annotations across `app`, `configuration`, `federation`, `runtime`, `security`, `version` and all `pam` modules.
- Fix TokenStore clock binding so tests can patch `time.monotonic`; keep fail-closed secret-redaction behavior on every broad exception (documented `noqa: BLE001`).
- Replace `os.replace` with `Path.replace`, add explicit `check=` on `subprocess.run`, convert `dict()` calls to literals and sort imports.
- Add regression tests for configuration/federation/security/app failure paths; unit coverage for core modules 89–100% (overall 84%).
- CI now runs ruff + mypy + coverage (`--fail-under=80`) on every push in addition to the existing OS/Python matrix and Redis job.

## 0.5.1 — 2026-10-06

- Target Tencent Cloud international: sign the international role callback, allow only the international console destination and update CSP.
- Explicitly use international STS, CAM and CVM API endpoints; add endpoint and mainland-destination rejection regression checks.
- Add bilingual installation/use manuals and README links, login sequence and deployment architecture diagrams.
- Correct first-install directory and full-source management/test instructions; document migration and remaining live acceptance.

## 0.5.0 — 2026-10-06

- Complete public-interface request operations with ticket/time-window fields, request details and explicit request removal.
- Add live session details/activity/properties and bounded account/session/recording exports. Reject repeated/incomplete pages and never follow server-provided next URLs.
- Add fully validated batch onboarding with preexisting-name probes and fsynced, credential-free attempt/confirmation journals. Uncertain writes never auto-retry or roll back accounts.
- Add local audit aggregates with deduplication/size limits and timestamped bridge events; no identity/URL/raw-field export.
- Add read-only deployment preflight with scope/binding checks and interface probes; target acceptance is explicitly excluded.
- Include the minimal audit package in Windows runtime installs and document the upgrade requirement.
- Consolidate delivered capabilities and external packaging/acceptance/certification dependencies into one bilingual delivery ledger.

## 0.4.1 — 2026-10-06

- Validate every maintenance job before remote actions, canonicalize UINs and reject case-insensitive/Windows-reserved filename collisions.
- Validate source account scope before creating cloud keys; validate recovery tickets and replacement pairs.
- Recheck key states after role verification and confirm cloud retirement before reporting success; uncertain outcomes never retry automatically.
- Validate complete onboarding payloads, credential types, CAM bindings and management flags before writes.
- Preflight service XML with DTD disabled; replace it atomically under an exclusive lock, preserve the original backup and never overwrite existing shared secrets.
- Add lifecycle/input regression tests and real PowerShell file/XML integration tests; target service execution still requires environment acceptance.

## 0.4.0 — 2026-10-06

- Add scoped native guest CPM Verify/Change/Reconcile submission and sanitized account status.
- Capture native PSM connection and recording playback responses into exclusive private files; add recording detail/activity/validity queries.
- Probe standard PVWA read interfaces without inferring write permissions or universal version support.
- Recover verified replacement tickets after interrupted preparations; never recreate lost keys automatically.
- Add scheduler-neutral, scope-pinned verification/preparation jobs with crash journals and exclusive state locks.
- Add optional TLS Redis token storage, atomic cross-node consumption, fail-closed outages and protected Windows cluster configuration.
- Add a dedicated real Redis CI job and document failover/production acceptance boundaries.
- Native CPM binaries/platform import packages and target-environment acceptance remain dependent on the installed CyberArk framework.

## 0.3.0 — 2026-10-06

- Add administrative PVWA REST adapters for account onboarding, access requests, explicit approval decisions, session controls and recording metadata.
- Add CAM/CVM discovery and credential-free SSH/RDP onboarding proposals.
- Add sub-user key verification, staged key rotation, explicit role-tested cutover and old-key reactivation. Preserve both keys after uncertain writes.
- Keep mutations opt-in; require HTTPS, existing PVWA authorization and independent CAM management credentials.
- Include lifecycle modules and their mock tests in reproducible source distributions; document compatibility boundaries in English and Chinese.
- Native CPM packaging, target-version platform imports, real PSM recording and live cloud acceptance remain unverified.

## 0.2.2 — 2026-10-06

- Add real loopback HTTP tests against the shared Waitress runtime configuration.
- Reject duplicate JSON configuration keys and oversized files; support UTF-8 BOM from Windows editors.
- Fail startup with sanitized configuration diagnostics.
- Clean up partially installed services after installation failures.
- Include a CI workflow template in source distributions while workflow upload authorization is pending.

## 0.2.1 — 2026-10-06

- Bind single-use form tokens to authenticated proxy identities and use monotonic expiration.
- Add bounded STS issuance admission with 503/Retry-After, retaining capacity for health checks.
- Verify backend readiness during service installation and bound Waitress connections/body/header sizes.
- Add concurrent replay, identity, capacity/expiry and slow-STS tests.
- Use a shared version constant for health reporting and reproducible archives.

## 0.2.0 — 2026-10-06

- Add strict configuration validation and one-profile-per-caller binding.
- Reject duplicate/unknown form fields and redact unexpected connection failures.
- Permit the Tencent Cloud callback in form CSP, add health checks and safe correlation logging.
- Add Windows service install/uninstall scripts and an IIS rewrite template.
- Add Windows/Linux CI, reproducible source packaging, deployment/rollback guidance and acceptance records.
- Add MIT license, security policy and contribution guidance. Standardize author identity as susunola.

## 0.1.0 — 2026-10-06

- Initial Tencent Cloud STS console bridge, offline tests and bilingual documentation.

These are source milestones, not statements of production certification.
