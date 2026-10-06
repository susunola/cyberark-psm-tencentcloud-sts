# Changelog

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
