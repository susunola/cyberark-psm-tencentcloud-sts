# PSM-TencentCloud-STS

**English** | [简体中文](README.zh-CN.md)

A Tencent Cloud mainland console role login bridge for CyberArk PSM, using an architecture similar to AWS Console STS:

```text
PVWA authorization → PSM Web injects Vault credentials → STS AssumeRole
                   → signed Tencent Cloud role login URL → PSM browser console session
```

This package includes a runnable bridge and unit tests. It is not a platform ZIP that can be imported directly into PVWA. Windows deployment, PSM recording, and live Tencent Cloud login have not been validated against a target environment.

## Delivery status and operations

Version 0.2.2 includes strict configuration validation, dedicated caller-to-role binding, Windows install/uninstall scripts, an IIS proxy template, safe audit correlation, CI, a reproducible source archive and SHA256 manifest. Original code uses the MIT license; maintainer: **susunola**.

- [Deployment, upgrade, rollback and troubleshooting](docs/DEPLOYMENT.md)
- [Acceptance record and release gates](docs/ACCEPTANCE.md)
- [Marketplace submission draft](docs/MARKETPLACE-SUBMISSION.md)
- [Security policy](SECURITY.md) · [Contribution guide](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

Version 0.2.2 also binds form tokens to proxy identities, uses monotonic expiration and caps concurrent STS issuance at two requests. Overload returns 503/Retry-After; start a new connection after waiting. The installer verifies service readiness.

Run `python scripts/check_config.py settings.json` before deployment. Use the install script documented in the deployment guide; Windows runtime and real PSM/cloud acceptance remain pending. Each caller SecretId can belong to only one profile; use distinct callers for distinct privilege tiers.

Version 0.2.2 adds actual loopback HTTP integration tests against Waitress (cloud calls remain mocked), strict JSON loading including duplicate-key rejection, and sanitized startup failures. A CI template is available in `deployment/ci-workflow.yml.template`; enabling it requires GitHub workflow permission.

## Files

| File | Purpose |
|---|---|
| `federation.py` | Official SDK STS calls, HMAC-SHA256 signing, and role login URL construction |
| `app.py` | Bridge form, authenticated proxy checks, single-use CSRF, role/caller allowlists, and 303 redirect |
| `settings.example.json` | Server-side role configuration; users cannot submit arbitrary roles or destinations |
| `cam-assume-policy.example.json` | Caller sub-user permission example; replace the account and role |
| `WebFormFields.template.txt` | Credential injection mapping; verify against the installed PSM version |
| `requirements.in` / `requirements.lock.txt` | Dependency ranges and tested versions |
| `tests/test_bridge.py` | Offline tests using mock credentials and STS calls |

## Tencent Cloud configuration

1. Create a dedicated CAM caller sub-user with API keys. Store its SecretId in the CyberArk account property `TencentSecretId` and its SecretKey in the Vault password field. Do not use root account keys.
2. Create an account-trusted target role with console login enabled. Configure its trust relationship to permit the intended caller, and grant the caller `sts:AssumeRole` permission for that role. Both sides must permit the operation.
3. Attach the required business permissions to the role; start acceptance testing with a read-only role. The bridge does not provision users/roles or rotate keys. Configure CPM separately for long-term key rotation and update the caller allowlist when keys change.
4. Set the role ARN, allowed SecretIds, and destination in `settings.json`. The default duration is 300 seconds, following Tencent Cloud role login guidance. Verify that the current STS API accepts this duration in staging.

## Windows PSM deployment

Start on a test PSM server with a supported Python 3 installation:

```powershell
py -3 -m venv C:\PSM-TencentCloud\venv
C:\PSM-TencentCloud\venv\Scripts\python.exe -m pip install -r C:\PSM-TencentCloud\requirements.lock.txt
```

Copy `settings.example.json` to `settings.json` and enter your environment values. Give the service account read access to code and configuration. Ordinary PSM session accounts must not be able to modify code, role configuration, or service secrets.

The supplied installer uses an administrator-provided WinSW binary. If using other service tooling, manage this process:

```text
C:\PSM-TencentCloud\venv\Scripts\python.exe C:\PSM-TencentCloud\app.py
```

Set its working directory to `C:\PSM-TencentCloud` and configure:

| Service environment variable | Value |
|---|---|
| `PSM_TC_CONFIG` | Absolute path to `settings.json` |
| `PSM_TC_PROXY_KEY` | High-entropy random value of at least 32 characters shared with the trusted proxy |
| `PSM_TC_SESSION_KEY` | Independent high-entropy random value of at least 32 characters for session signing |

Keep secrets out of the repository, user-visible output, and WebFormFields. The backend listens on `127.0.0.1:8765`; do not expose it directly to browsers. Use a single service process with concurrent threads. Single-use CSRF state is stored in process memory; multiple processes require a shared store first.

## Authenticated HTTPS proxy prerequisite

Configure IIS or an enterprise-controlled reverse proxy on PSM with a dedicated HTTPS site, such as `https://psm-tc-bridge.internal/`, and a trusted certificate.

The proxy must meet all these requirements:

1. Disable anonymous access, enable Windows Authentication, and restrict access to approved PSM session service identities. Confirm the actual account in your environment; the browser must complete integrated authentication.
2. **Remove browser-supplied** `X-PSM-Bridge-Key` and `X-PSM-Authenticated-User` headers. Set the first to the private bridge proxy key and the second to the actual Windows identity authenticated by the proxy. Never forward client-asserted identity values.
3. Forward paths and POST forms to the fixed backend `http://127.0.0.1:8765` while preserving browser-side HTTPS. The bridge validates the actual TCP peer as loopback; do not substitute the remote client address.
4. Restrict proxy key configuration access to administrators and the proxy service, and restrict site access to controlled hosts. Disable tracing of request bodies, cookies, response Location headers, and complete login URLs. Do not retain sensitive material in logs.
5. Reject direct backend requests, missing proxy keys, unauthenticated requests, and forged identity headers. Correct proxy configuration is the authentication boundary; localhost alone is insufficient.

The package provides a Windows service installer and an IIS rewrite template. IIS authentication, ARR/URL Rewrite installation and certificates still require environment-specific configuration. Complete them before production use. Do not enable Flask debug mode.

## PVWA platform and connection component

1. Duplicate the Web application sample component shipped with your PSM version and name it `PSM-TencentCloud-STS`. Retain the supported browser, driver, launcher, PID management, and exit handling.
2. Set `LogonURL` to the authenticated HTTPS bridge root URL.
3. Apply `WebFormFields.template.txt` in the stated order and verify custom property expansion syntax for your PSM version. Form element IDs belong to this bridge and do not depend on Tencent Cloud's page DOM.
4. Create or duplicate an appropriate API credential platform and associate this component. Add account properties `TencentSecretId` and `TencentRoleProfile`; the latter selects a server-side profile such as `tc-readonly`. The password field must contain the CAM SecretKey.
5. Do not let session users arbitrarily override profiles, SecretIds, or destinations. Use controlled account/platform authorization and Vault Safe permissions to govern connections.
6. `ClientUserName` is an STS audit label, not an authentication source or independent proof of human identity. Input labels accept 2–256 characters without control characters. Domain names, Chinese characters and long labels are normalized to an ASCII label with a stable hash suffix. Use the request ID and role session name to correlate PSM records; the form label is still client-provided metadata.
7. Submission redirects to Tencent Cloud's role callback and then to the console. Configure successful-login validation for your version; a loaded bridge page does not prove successful cloud login.
8. The PSM Web framework provides browser isolation, PID reporting, recording, and cleanup. The bridge does not implement these functions. Verify them before exporting a formal component package from PVWA.

## Signing and limitations

Tencent Cloud uses `roleAccessCallback`, rather than AWS's `getSigninToken`. The signing string contains action, nonce, secretId, and timestamp. It is signed with the temporary SecretKey using HMAC-SHA256 and Base64 encoding. The temporary token, signature, and destination are URL-encoded.

The long-term SecretKey is used in the HTTPS form submission and server memory, not files, logs, or command-line arguments. Python cannot guarantee memory zeroization. The callback URL **contains temporary credentials** and may be readable by browsers, administrators, or diagnostic tools. Apply your PSM Web baseline to debugging tools and logs, and test user-accessible extraction paths. This implementation does not guarantee that credentials are impossible to extract.

The requested STS duration is 300 seconds. Console cookie lifetime and PSM timeouts must be validated separately. Closing a PSM session does not revoke issued credentials. The package does not implement cloud session revocation or forced global logout.

Only mainland endpoints and ordinary CAM roles are implemented; international endpoints and service roles need adaptation. Keep cloud-side login policies, network restrictions, and MFA conditions effective. Requests that fail policy requirements must fail rather than bypassing those requirements.

## Validation

Run offline tests:

```powershell
C:\PSM-TencentCloud\venv\Scripts\python.exe -m unittest discover -s tests -v
```

Tests cover signing and encoding, destination restrictions, proxy authentication, CSRF replay, role/caller allowlists, SDK request construction, expiring credentials, and redacted errors. Mock STS calls do not establish live login compatibility.

For environment acceptance, verify role identity after login and failures for invalid keys or unauthorized roles. Reject altered profiles, replayed forms, and proxy bypasses. Check cookie isolation across users, STS audit label correlation, recording playback, browser cleanup after timeout/exit, and actual console session lifetime. Inspect browser, proxy, and service diagnostics for long-term key or temporary URL exposure. Mark the integration production-ready only after acceptance passes.

## Official references

- [Tencent Cloud role console login](https://cloud.tencent.com/document/product/598/45529)
- [Using Tencent Cloud roles](https://cloud.tencent.com/document/product/598/19419)
- [Tencent Cloud Python SDK](https://github.com/TencentCloud/tencentcloud-sdk-python)
- [CyberArk Web applications for PSM](https://docs.cyberark.com/pam-self-hosted/latest/en/Content/PASIMP/psm_WebApplication.htm) — select your installed version.

This is an independent implementation. It contains no proprietary CyberArk SDK and is not a CyberArk Marketplace-certified product.
