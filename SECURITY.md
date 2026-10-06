# Security

This process holds long-term CAM SecretKeys in request memory and puts temporary credentials into a browser handoff. Treat the host as a privileged session component.

## Report

Use a private GitHub security advisory on this repository. Do not open a public issue with a key, token, login URL, or customer account id.

## Threat model

In scope:

- A PSM browser user trying to choose another role, destination, or SecretId.
- A client forging `X-PSM-Bridge-Key` or `X-PSM-Authenticated-User`.
- CSRF replay, open redirect, and credential leakage into the bridge log.
- A non-loopback client reaching the backend directly.

Out of scope, and not solved here:

- A compromised PSM host, proxy admin, or memory dump. Python cannot zero strings.
- Extraction of the temporary token from the PSM browser after a successful handoff. POST keeps it out of `Location` and the proxy access-log URL; it does not make the browser unable to see it.
- Revocation. Closing the PSM session does not call Tencent Cloud logout, and the temporary key remains valid until it expires.
- Live login compatibility. The signature matches the published callback string; the target account still has to accept it.

## Operator rules

- Broker keys are sub-user keys. Rotate them with CPM and update `allowed_secret_ids` in the same change.
- Set ExternalId on the role. The form cannot supply it.
- Keep duration at or below 300 seconds.
- One process. CSRF nonces are not shared across workers.
- Disable request-body tracing on the proxy.
