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

The bridge implements identity-bound single-use CSRF tokens with monotonic expiration in local mode or Redis server time in shared mode, strict configuration validation, duplicate-field rejection, a bounded token store, an 8 KiB request limit, a fixed STS endpoint, an allowlisted console destination, and sensitive-error suppression. Successful issuance logs a correlation ID, proxy identity, profile and STS session name; it never logs request credentials or redirect URLs.

Local administrators, a compromised proxy, or processes able to read its secret are trusted and can bypass proxy isolation. PSM hardening must restrict access to service files, browser tools, network inspection and temporary credentials. Callback URLs contain temporary access credentials. Python cannot guarantee memory zeroization. The service does not revoke issued credentials on disconnect. Authentication proxy configuration and browser/PSM behavior require real Windows acceptance testing.

Use a single backend process in local token mode. Multiple nodes require consistent role configuration, session signing keys, identity formatting and shared Redis storage. Redis must use TLS, restricted ACLs and a single writable primary. Outages fail closed, with no local fallback or consume retries. Atomic primary consumption does not prevent replay after asynchronous state rollback: rotate all node session keys before resuming traffic after failover/restore. See the operations guide for fencing and acceptance requirements. Restrict traffic and apply proxy rate limits to prevent token-store or STS-call exhaustion. Concurrent STS calls per node are bounded by `PSM_TC_ISSUANCE_SLOTS` (default 3, one worker thread reserved for health checks). A submission waits up to `PSM_TC_ISSUANCE_WAIT_SECONDS` for a slot and only then receives 503/Retry-After; because the slot is reserved before the single-use token is consumed, a queued or refused submission does not invalidate the form the user is looking at. Pending form tokens are bounded per authenticated identity (`PSM_TC_IDENTITY_CAPACITY`, default 3), so **every session must present its own identity** — a shared service account lets concurrent users evict each other and makes audit attribution impossible. Keep request-body tracing and response-header tracing disabled. Do not run Flask debug mode. Do not allow session users to replace profile IDs, caller credentials, proxy keys or service configuration through arbitrary PVWA overrides.

Rotate long-term CAM keys via the separate staged administrative workflow or a validated native CPM integration. During rotation, an old/new SecretId pair may share the same profile; remove the old ID after tested cutover. Keep reconciling CAM permissions out of the bridge service. Native guest CPM submissions are asynchronous and cannot substitute for verifying completion. Scheduled preparations retain the old key and never finalize automatically; uncertain writes require inventory reconciliation, not blind retries.

PVWA authentication and MFA are obtained through your approved flow. Administrative adapters require verified HTTPS, reject redirects and do not retry writes automatically. Protect state/output directories, especially on Windows where mode 0600 alone does not set a DACL. Native PSM connection and playback responses may contain authentication material; they are saved only in exclusive protected files. Do not commit inventories, actual shared settings, session tokens, output files or tickets. Rotate proxy and session signing keys during a maintenance window; this invalidates in-flight forms.

## Server-level rejections

The backend binds to loopback. Two limits apply:

- Request bodies over 8 KB are rejected by the application, which returns a 413
  carrying the same security headers as every other response. The transport's own
  body ceiling is deliberately set higher (32 KB) so that the application produces
  the response; a body beyond that ceiling is refused by the transport.
- Request *headers* over 16 KB are rejected by the transport before it reaches the
  application, because no application-level limit exists for them. Those responses
  (431) carry the transport's own body without the application's headers. The body
  is static and contains no request data. If your baseline requires uniform
  response headers on that path, terminate it at the authenticated proxy instead.
