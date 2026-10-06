# Security policy

Security maintenance currently targets the latest development branch. No production-certified release is available yet.

Report vulnerabilities privately to the repository owner, **susunola**, using GitHub private vulnerability reporting if enabled, or an established private support channel. Do not put credentials, exploit login URLs, or customer logs in public issues. There is no guaranteed response SLA.

## Trust boundaries

- PVWA and Vault authorize account use. The bridge cannot independently verify a human's PVWA approval.
- An authenticated HTTPS proxy authorizes Windows service identities and replaces identity/key headers.
- The backend accepts only loopback peers with the private proxy key. That key authenticates the proxy, not the human.
- Each caller SecretId is bound to exactly one role profile, preventing reuse across profiles through form tampering. Configure distinct dedicated caller accounts for distinct privilege tiers and constrain their CAM AssumeRole permissions.
- CAM role trust and permission policies define cloud access. A client-provided audit label is attribution metadata, not an authorization grant.

## Controls and residual risks

The bridge implements single-use expiring CSRF tokens, strict configuration validation, duplicate-field rejection, a bounded token store, an 8 KiB request limit, a fixed STS endpoint, an allowlisted console destination, and sensitive-error suppression. Successful issuance logs a correlation ID, proxy identity, profile and STS session name; it never logs request credentials or redirect URLs.

Local administrators, a compromised proxy, or processes able to read its secret are trusted and can bypass proxy isolation. PSM hardening must restrict access to service files, browser tools, network inspection and temporary credentials. Callback URLs contain temporary access credentials. Python cannot guarantee memory zeroization. The service does not revoke issued credentials on disconnect. Authentication proxy configuration and browser/PSM behavior require real Windows acceptance testing.

Use a single backend process until CSRF state is moved to shared storage. Restrict traffic and apply proxy rate limits to prevent token-store or STS-call exhaustion. Keep request-body tracing and response-header tracing disabled. Do not run Flask debug mode. Do not allow session users to replace profile IDs, caller credentials, proxy keys or service configuration through arbitrary PVWA overrides.

Rotate long-term CAM keys via an independently configured CPM workflow. During rotation, an old/new SecretId pair may share the same profile; remove the old ID after validation. Rotate proxy and session signing keys during a maintenance window; this invalidates in-flight forms.
