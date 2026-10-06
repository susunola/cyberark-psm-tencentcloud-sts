# PSM-TencentCloud-STS

**English** | [简体中文](README.zh-CN.md)

**Start here: [Detailed installation and usage manual](docs/INSTALLATION-AND-USAGE.md)** — prerequisites, Windows/IIS setup, PVWA/PSM, commands, rotation, recovery and troubleshooting.

A Tencent Cloud international console role login bridge for CyberArk PSM, using an architecture similar to AWS Console STS:

## Login flow

The PSM browser submits the Vault credential to an authenticated local bridge; the bridge exchanges it for temporary role credentials. The browser then uses Tencent Cloud's international callback to establish the console session.

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant PVWA
    participant Vault
    participant PSM as PSM Web browser
    participant IIS as IIS HTTPS proxy
    participant Bridge as Local STS bridge
    participant STS as sts.intl.tencentcloudapi.com
    participant Login as www.tencentcloud.com
    participant Console as console.tencentcloud.com
    User->>PVWA: Select account, reason and ticket
    PVWA->>PVWA: Safe authorization, MFA and approval policy
    PVWA->>PSM: Start authorized native PSM session
    Vault-->>PSM: Controlled account credential retrieval
    PSM->>IIS: GET form with Windows Authentication
    IIS->>Bridge: Loopback request with trusted identity/key
    Bridge-->>PSM: Form and identity-bound single-use CSRF
    PSM->>IIS: POST injected SecretId, SecretKey, profile and CSRF
    IIS->>Bridge: Overwrite client headers; forward authenticated POST
    Bridge->>Bridge: Validate identity, CSRF and caller/profile binding
    Bridge->>STS: AssumeRole using dedicated caller credentials
    STS-->>Bridge: Temporary role credentials
    Bridge->>Bridge: HMAC-SHA256 sign international callback
    Bridge-->>PSM: 303 to signed roleAccessCallback
    PSM->>Login: Submit signed temporary login URL
    Login-->>PSM: Establish cloud session and redirect
    PSM->>Console: Access console with role permissions
    Note over PSM,Console: Native PSM records session; closing PSM does not revoke cloud tokens
```

## Deployment architecture

Solid lines show requests or managed dependencies; dotted lines show the returned redirect and optional shared-token state. Guest SSH/RDP is a separate native PSM path.

```mermaid
flowchart TB
    U[Authorized operator] --> PVWA
    subgraph PAM[CyberArk PAM environment]
        PVWA[PVWA: authorization / MFA / approval / tickets]
        V[Vault: CAM and guest credentials]
        CPM[Native CPM: verified guest password platforms]
        REC[Native PSM recordings and audit]
        subgraph HOST[Windows PSM host]
            B[Native PSM Web browser]
            I[IIS: HTTPS / Windows Authentication]
            S[Bridge service: LocalService / 127.0.0.1:8765]
            CFG[Protected role allowlist / service secrets]
        end
        PVWA --> B
        V -->|controlled retrieval| B
        B -->|HTTPS form| I
        I -->|overwrite identity and key / loopback| S
        CFG --> S
        B --> REC
        CPM --> V
    end
    subgraph TC[Tencent Cloud international]
        STS[sts.intl.tencentcloudapi.com]
        LOGIN[www.tencentcloud.com role callback]
        CONSOLE[console.tencentcloud.com]
        CAM[cam.intl.tencentcloudapi.com]
        CVM[cvm.intl.tencentcloudapi.com]
        G[Private Windows / Linux CVM guests]
    end
    S -->|AssumeRole HTTPS| STS
    S -.->|303 returned through proxy to browser| B
    B -->|signed temporary URL| LOGIN
    LOGIN -->|cloud session redirect| CONSOLE
    B -->|native PSM-SSH / PSM-RDP separately| G
    CPM -->|native guest password management| G
    A[Protected admin workstation: pamctl / maintenance] -->|authorized API session| PVWA
    A -->|scoped key management| CAM
    A -->|inventory discovery| CVM
    R[Optional shared Redis: TLS / ACL / single writable primary]
    S -.->|multi-node single-use form state| R
```

This package includes a runnable bridge and unit tests. It is not a platform ZIP that can be imported directly into PVWA. Windows deployment, PSM recording, and live Tencent Cloud login have not been validated against a target environment.

## Delivery status and operations

Version 0.5.1 includes strict configuration validation, dedicated caller-to-role binding, Windows install/uninstall scripts, an IIS proxy template, safe audit correlation, CI, a reproducible source archive and SHA256 manifest. Original code uses the MIT license; maintainer: **susunola**.

- [Complete delivery ledger and remaining external dependencies](docs/DELIVERY.md)
- [Native CPM/PSM operations, recovery, maintenance and shared tokens](docs/OPERATIONS.md)
- [PAM capabilities, lifecycle CLI and compatibility boundaries](docs/PAM-CAPABILITIES.md)
- [Deployment, upgrade, rollback and troubleshooting](docs/DEPLOYMENT.md)
- [Acceptance record and release gates](docs/ACCEPTANCE.md)
- [Marketplace submission draft](docs/MARKETPLACE-SUBMISSION.md)
- [Security policy](SECURITY.md) · [Contribution guide](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

Version 0.2.2 also binds form tokens to proxy identities, uses monotonic expiration and caps concurrent STS issuance at two requests. Overload returns 503/Retry-After; start a new connection after waiting. The installer verifies service readiness.

Run `python scripts/check_config.py settings.json` before deployment. Use the install script documented in the deployment guide; Windows runtime and real PSM/cloud acceptance remain pending. Each caller SecretId can belong to only one profile; use distinct callers for distinct privilege tiers.

Version 0.2.2 adds actual loopback HTTP integration tests against Waitress (cloud calls remain mocked), strict JSON loading including duplicate-key rejection, and sanitized startup failures. GitHub Actions CI is enabled for Windows Server 2025 and Ubuntu 24.04 with Python 3.11–3.13. The workflow pins Actions to specific commits. A matching template is included in `deployment/ci-workflow.yml.template`.

Version 0.3.0 adds `scripts/pamctl.py`: CAM/CVM discovery, guest onboarding proposals, PVWA onboarding and approval/session interfaces, and staged sub-user key rotation. These are administrative workflows, not a certified native CPM package. See the capability guide for prerequisites and commands.

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
3. Attach the required business permissions to the role; start acceptance testing with a read-only role. The bridge does not provision users/roles. The separate administrative toolkit supports staged key rotation; configure native CPM separately if required, and update caller allowlists during cutover.
4. Set the role ARN, allowed SecretIds, and destination in `settings.json`. The default duration is 300 seconds, as this project’s short-lived credential policy. Verify that the current STS API accepts this duration in staging.

## Windows PSM deployment

Follow the [step-by-step manual](docs/INSTALLATION-AND-USAGE.md#install). Run `scripts/Install-Bridge.ps1` from full source in administrator PowerShell, supplying a machine-wide Python executable, reviewed WinSW binary, trusted SHA256 and validated settings file. **Do not pre-create the installation directory**; the installer creates it with restricted ACLs.

The installer registers `PSMTencentCloudSTS` as LocalService, installs locked dependencies, generates independent proxy/session keys and checks readiness. The backend listens on `127.0.0.1:8765`; configure the authenticated HTTPS proxy before PSM connections. Service XML and generated IIS configuration contain secrets and must stay protected.

The installed service contains minimal runtime files. Run administrative scripts and tests from a separate full-source environment. Single-node mode uses in-memory form tokens; [multiple-node deployment](docs/INSTALLATION-AND-USAGE.md#advanced) uses shared Redis tokens and a common session key.

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

International endpoints and ordinary CAM roles are implemented; mainland console callbacks and service roles are outside the configured scope. Keep cloud-side login policies, network restrictions, and MFA conditions effective. Requests that fail policy requirements must fail rather than bypassing those requirements.

## Validation

Run offline tests from the full-source directory after creating the management `.venv` described in the manual:

```powershell
& .\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Tests cover signing and encoding, destination restrictions, proxy authentication, CSRF replay, role/caller allowlists, SDK request construction, expiring credentials, and redacted errors. Mock STS calls do not establish live login compatibility.

For environment acceptance, verify role identity after login and failures for invalid keys or unauthorized roles. Reject altered profiles, replayed forms, and proxy bypasses. Check cookie isolation across users, STS audit label correlation, recording playback, browser cleanup after timeout/exit, and actual console session lifetime. Inspect browser, proxy, and service diagnostics for long-term key or temporary URL exposure. Mark the integration production-ready only after acceptance passes.

## Official references

- [Tencent Cloud role console login](https://www.tencentcloud.com/document/product/614/36997)
- [Using Tencent Cloud roles](https://www.tencentcloud.com/document/product/598/19419)
- [Tencent Cloud Python SDK](https://github.com/TencentCloud/tencentcloud-sdk-python)
- [CyberArk Web applications for PSM](https://docs.cyberark.com/pam-self-hosted/latest/en/Content/PASIMP/psm_WebApplication.htm) — select your installed version.

This is an independent implementation. It contains no proprietary CyberArk SDK and is not a CyberArk Marketplace-certified product.

International endpoint references: [AssumeRole](https://www.tencentcloud.com/document/product/1150/49456), [GetCallerIdentity](https://www.tencentcloud.com/document/product/1150/49453), [CAM ListAccessKeys](https://www.tencentcloud.com/zh/document/api/598/37088), [CVM DescribeInstances](https://www.tencentcloud.com/document/product/213/33258). The role callback specification is published in the official **Embedding CLS Console (old scheme)** page; live login to the configured console destination still requires acceptance.
