# Changelog

## Unreleased

- Adopt one quality toolchain for local use and CI: ruff for lint, mypy for typing and `coverage run -m unittest discover` for the suite. `requirements-dev.txt` pins the tooling and a pre-commit configuration mirrors it on upstream tags.
- Raise the enforced coverage gate from 80% to 95%; the measured total is 99% with 13 of 16 modules at 100%.
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
