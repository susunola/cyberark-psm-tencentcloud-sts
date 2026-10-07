# Changelog

## Unreleased

- Add `pyproject.toml` with packaging metadata and enforced ruff, strict mypy, pytest and coverage configuration; add a pinned `requirements-dev.txt` for the quality gate.
- Add a CI quality job (ruff lint, ruff format check, strict mypy, pytest with coverage gate) and an optional `.pre-commit-config.yaml` pinned to upstream tags; sync the shipped workflow template.
- Add type annotations and `TokenStoreLike` structural typing across the bridge, federation, security and `pam/` modules; strict mypy now passes with no `Any` leaks.
- Replace inline magic numbers, duplicated probe-label maps and repeated parser construction with named constants, shared helpers and per-command CLI handlers; split `scripts/pamctl.py` and `scripts/build_release.py` into testable functions.
- Normalize formatting across source, scripts and tests; expand `.gitignore` to cover coverage/tooling caches and generated export artifacts.
- Document the quality gate, code conventions and sanitized-error policy in the contribution guide and both READMEs.
- Expand the offline suite to cover request construction, validation, sanitization, pagination, token backends, maintenance locking, staged-rotation refusals and both token stores; the enforced coverage gate is now 95%.
- Fix `pam.audit.event` so caller fields can no longer overwrite `schema_version` or `timestamp`, keeping emitted records unforgeable at the schema level.
- Fix non-string input handling: `pam.vault` account IDs, connect ticket fields and non-object search results now raise `ValueError`/`VaultError` instead of `TypeError`/`AttributeError`, and both token stores validate capacity and TTL type (rejecting booleans and numeric strings).
- Keep the stricter PVWA base-URL, token and route rules from 0.5.2 while adding the local quality gate around them.

## 0.5.2 — 2026-10-07

- Bound CAM/CVM discovery to 20 unique prevalidated regions, 1,000 users, 100 pages per region and 10,000 instances overall; reject repeated IDs, invalid pages and changing totals rather than return partial inventory.
- Accept syntactically valid region suffixes while leaving availability to cloud validation; prevalidate key mutations and identity targets before remote calls.
- Reject malformed PVWA API bases, control-character tokens, false-equivalent TLS settings and invalid routes before transport.
- Add offline documentation/CLI validation and dependency consistency checks to all CI jobs.
- Include a deterministic CycloneDX dependency inventory beside source distributions; this is not a vulnerability scan or deployed-host inventory.
- Add inventory/transport failure regression tests without claiming live PAM acceptance.

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
