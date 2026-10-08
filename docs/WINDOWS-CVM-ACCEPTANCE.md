# Windows CVM deployment acceptance — 2026-10-08

[中文](WINDOWS-CVM-ACCEPTANCE.zh-CN.md) · [Deployment matrix](DEPLOYMENT.md) · [Machine-readable evidence](evidence/windows-cvm-2026-10-08.json)

Four real Tencent Cloud international CVMs were created in `ap-singapore-2`, tested using TAT, and terminated afterwards. These are **bridge installation/service acceptance results**, not CyberArk/Idira certification or end-to-end PSM acceptance.

| Windows Server edition | OS build | Windows PowerShell | Official public image | Bridge result |
|---|---|---|---|---|
| 2022 Datacenter English x64 | 20348 | 5.1.20348.4294 | `img-9tzezztj` | Passed |
| 2019 Datacenter English x64 | 17763 | 5.1.17763.8755 | `img-bhvhr6pr` | Passed |
| 2016 Datacenter English x64 | 14393 | 5.1.14393.9140 | `img-1eckhm4t` | Passed |
| 2012 R2 Datacenter English x64 | 9600 | 5.1.14409.2001 | `img-2tddq003` | Passed |

Each host used `SA9.MEDIUM4` (2 vCPU, 4 GiB), a 50 GiB system disk, machine-wide **Python 3.13.7**, and **WinSW 2.12.0** verified against the repository SHA256 pin. The Python installer Authenticode signature was checked as valid and issued to the Python Software Foundation. The 2022/2019/2016 tests used commit `401ad3c`, plus the native-stderr fix described below. The later 2012 R2 test used commit `3e78aec`, which already includes that fix. Python 3.11/3.12/3.14 were not tested on these CVMs; their existing Windows 2025 CI evidence is separate.

## Checks performed

All four hosts passed the existing `scripts/ci/` checks: WinSW hash verification, synthetic configuration creation, tampered WinSW refusal, hash-locked dependency installation, service registration/start under `NT SERVICE\PSMTencentCloudSTS`, ACL review, authenticated readiness, anonymous health/readiness refusal (HTTP 403), anonymous liveness (HTTP 200), unexpected form-field refusal (HTTP 400) with an attributable audit reason, service restart and repeated readiness, and uninstall with configuration/runtime files preserved.

The synthetic profile contained no usable cloud credentials. The caller AK/SK remained on the orchestration host and was not placed on any guest. A pre-existing security group without public TCP ingress was borrowed without modifying its rules. Tests ran through TAT rather than RDP/WinRM. All four test instances were terminated and their termination was confirmed through CVM API; no new security group was created.

## Issue discovered and retested

The initial 2022 and 2019 runs stopped during dependency installation, before service registration. The CI wrapper redirected native stderr with `2>&1` while using `$ErrorActionPreference='Stop'`. Windows PowerShell 5.1 can promote pip notices into terminating native-command errors in that combination. `scripts/ci/install-service.ps1` now keeps stderr separate and retains the installer's native exit-code checks. Both hosts passed after that patch; 2016 passed with the same patch. Only the passing reruns establish the matrix status.

## Reproduce

Create an isolated official English x64 CVM for the selected image, enable TAT, install machine-wide Python 3.13.7, and download WinSW with the pinned checksum. Set `RUNNER_TEMP`, `GITHUB_WORKSPACE`, `INSTALL_DIR`, `WINSW_URL`, `WINSW_SHA256` and the Python `PATH`, then run the checked-in scripts in this order:

1. `fetch-winsw.ps1`, `write-acceptance-settings.ps1`, `assert-tampered-winsw-refused.ps1`.
2. `install-service.ps1`, `assert-installer-acls.ps1`, `assert-readiness-probe.ps1`, `assert-tampered-form-refused.ps1`.
3. Restart `PSMTencentCloudSTS`, wait for it to become ready, then repeat `assert-readiness-probe.ps1`.
4. `assert-uninstall-preserves-files.ps1`.
5. Retain sanitized evidence, terminate the temporary CVM, and verify termination.

## Remaining acceptance

IIS/ARR, Windows authentication, TLS, actual PSM component launch, console browser login, session isolation, recording/playback and PSM browser cleanup remain untested. Production deployment must still match the selected PSM/Connector vendor OS support matrix. Original Windows Server 2012 and older, desktop Windows, Server Core and ARM64 were not covered.

## Windows Server 2012 R2 and original 2012 follow-up

2012 R2 passed all bridge checks. TAT initially returned `START_FAILED` because its default working directory did not exist on this image; the retry explicitly set `WorkingDirectory` to `C:\` and passed. The harness extracted the source archive using .NET `ZipFile`. The guest itself had Windows PowerShell 5.1; older PowerShell versions were not tested. The temporary R2 instance was terminated and a separate CVM query returned no remaining instance.

Original Windows Server 2012 (non-R2) could not be tested. Complete public-image pagination in `ap-singapore`, `ap-hongkong` and `ap-tokyo`, plus account-visible image pagination in `ap-singapore`, found only 2012 R2 images. This is a scoped image-availability finding, not proof of worldwide unavailability or plugin incompatibility. An authorized custom/shared original-2012 image and its region are required to continue. R2 evidence must not be applied to original 2012.
