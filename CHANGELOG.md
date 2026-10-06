# Changelog

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
