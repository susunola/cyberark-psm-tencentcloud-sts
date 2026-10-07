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

Use a single backend process in local token mode. Multiple nodes require consistent role configuration, session signing keys, identity formatting and shared Redis storage. Redis must use TLS, restricted ACLs and a single writable primary. Outages fail closed, with no local fallback or consume retries. Atomic primary consumption does not prevent replay after asynchronous state rollback: rotate all node session keys before resuming traffic after failover/restore. See the operations guide for fencing and acceptance requirements. Restrict traffic and apply proxy rate limits to prevent token-store or STS-call exhaustion. Only two STS requests per node can execute concurrently; excess submissions receive 503/Retry-After and require a new form. This preserves worker capacity for health checks. Keep request-body tracing and response-header tracing disabled. Do not run Flask debug mode. Do not allow session users to replace profile IDs, caller credentials, proxy keys or service configuration through arbitrary PVWA overrides.

Rotate long-term CAM keys via the separate staged administrative workflow or a validated native CPM integration. During rotation, an old/new SecretId pair may share the same profile; remove the old ID after tested cutover. Keep reconciling CAM permissions out of the bridge service. Native guest CPM submissions are asynchronous and cannot substitute for verifying completion. Scheduled preparations retain the old key and never finalize automatically; uncertain writes require inventory reconciliation, not blind retries.

PVWA authentication and MFA are obtained through your approved flow. Administrative adapters require verified HTTPS, reject redirects and do not retry writes automatically. Protect state/output directories, especially on Windows where mode 0600 alone does not set a DACL. Native PSM connection and playback responses may contain authentication material; they are saved only in exclusive protected files. Do not commit inventories, actual shared settings, session tokens, output files or tickets. Rotate proxy and session signing keys during a maintenance window; this invalidates in-flight forms.

## Server-level rejections

The backend binds to loopback and is configured with an 8 KB request-body cap and
a 16 KB header cap. A request that exceeds either is rejected by the HTTP server
before it reaches the application, so those responses (413/431) carry the server's
own body without the application's `Content-Security-Policy`,
`Cache-Control: no-store`, `X-Content-Type-Options` or `X-Request-ID` headers. The
responses are static and contain no request data. If your baseline requires uniform
response headers on that path, terminate it at the authenticated proxy instead.
