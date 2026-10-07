# Contributing

Maintainer: **susunola**. English is the default documentation language; update `README.zh-CN.md` when changing setup or behavior.

Create a branch, explain the concrete problem, and run the full quality gate:

```text
python -m pip install -r requirements.lock.txt -r requirements-dev.txt
python -m ruff check .
python -m mypy
python -m coverage run -m unittest discover -s tests
python -m coverage report
python scripts/check_docs.py
python scripts/pin_lock_hashes.py --check
python -m pip_audit -r requirements.lock.txt
python scripts/build_release.py --out dist
```

Two checks go further than the gate above and run as their own CI jobs:

- `python scripts/check_guard_mutations.py` disables one security guard at a time and requires the suite to fail, so a control that no test protects is reported (about a minute). It refuses to run when a target file differs from HEAD, so it cannot hide uncommitted work.
- `python -m pip_audit -r requirements.lock.txt` fails when a published advisory covers a pinned dependency. A new advisory is a real finding rather than a flake, so it is expected to break the build until the pin moves.

The gate scripts are themselves under test in `tests/test_gate_tooling.py`: each one is fed a deliberately broken input and required to refuse it, because a check that quietly stops detecting a problem leaves the build green and is worse than no check at all.

`.github/workflows/security.yml` carries the analysis that does not belong in the per-push gate: CodeQL with the `security-and-quality` query pack, on pushes to `main`, on pull requests and weekly, because a new query pack finds new problems in code that has not changed. The release artifacts are attested from the same run, by a job that holds the elevated permissions alone. `deployment/` publishes a byte-identical template for each workflow, which `tests/test_hardening.py` asserts, so a deployment can follow the gate the repository actually runs.

### What can and cannot be checked off Windows

`tests/test_service_config.py` executes `scripts/Shared-ServiceConfig.ps1` through
`pwsh` whenever it is on PATH - on Linux and macOS too, not only on Windows CI.
`tests/test_powershell_syntax.py` parses every `.ps1` file under `scripts/` with the
real PowerShell parser, which reaches the statements only a Windows host can execute:
a syntax error there would otherwise surface for the first time on a runner that
nobody can reproduce locally. If `pwsh` is missing, both modules skip, so install
PowerShell locally rather than assuming Windows is required:

```text
brew install powershell            # macOS
python -m unittest tests.test_service_config tests.test_powershell_syntax -v
```

That parser is what makes the next convention load-bearing: a workflow step must
invoke a file under `scripts/ci/` rather than inline PowerShell in YAML, and
`tests/test_hardening.py` enforces that shape, because a parser can only see files.

`Install-Bridge.ps1` is executed by the `windows-installer` CI job on a Windows
Server 2025 runner: it installs the service, asserts the ACLs by reading them, and
uninstalls again. Run that job's steps in a local Windows VM when iterating on the
installer; they are not reproducible on macOS or Linux. What even a Windows host
cannot cover is IIS Windows Authentication and the PSM WebForm component - the
latter needs a licensed CyberArk installation.

Three deployment scripts cannot be executed anywhere but their target:
`Install-Bridge.ps1` needs administrator rights, `icacls.exe`, WinSW and a
machine-wide Python; `Configure-SharedTokens.ps1` needs `icacls.exe` and the
service; `Uninstall-Bridge.ps1` needs the service. CI parses all of them and this
repository also pins their security-relevant statements by assertion in
`tests/test_hardening.py`, so a property cannot be dropped silently - but that is
text, not execution. Their runtime behaviour is an acceptance item, not a test.
`scripts/ci/` holds the statements the `windows-installer` job runs, one file per
step, so those are parsed even though only a Windows host can execute them.

### Measure the admission queue

`python scripts/load_check.py` starts the real WSGI runtime with a slow STS and fires concurrent logins over loopback sockets, so a change to the admission queue can be checked against a number instead of an argument. It needs no credentials and no Redis, and takes about five seconds. Give each caller its own identity - `--callers` does that - because the per-identity pending-token bound, not the queue, is what refuses a shared one. Use `--wait 0` for the pre-queue comparison.

### Run the Redis integration suite locally

The shared-token backend runs a Lua script, and the entire integration suite is
skipped when no server is configured — which is how a breakage in the cleanup
path reached review once already. Before committing a change to `security.py`,
`security.py`'s key layout, or an integration test, run it against a real server:

```text
docker run --rm -d --name psm-redis -p 127.0.0.1:6399:6379 redis:7.0-alpine
PSM_TEST_REDIS_URL=redis://127.0.0.1:6399/15 python -m unittest discover -s tests
docker rm -f psm-redis
```

When you add a security guard, add it to the mutation table in `scripts/check_guard_mutations.py` and to the property or invariant suite where one applies. When you change the dependency lock, regenerate the hash file (`python scripts/pin_lock_hashes.py`) and re-run the audit.

`requirements-dev.txt` is required to run the suite: the property and invariant suites need hypothesis and skip cleanly without it. `mypy` takes its target list from `pyproject.toml`, and `coverage report` enforces the coverage threshold declared there (98%; currently measured at 100%). Raise the gate only together with real tests. `python -m unittest discover -s tests -v` is the single runner used locally and by CI, including the Windows/Ubuntu and Python 3.11-3.14 matrix.

Lint is enforced but formatting is not: the test and script suites keep intentional compact one-liners, so `ruff format` must not be run over them.

Optional: install the git hooks once per clone with `pre-commit install`. `.pre-commit-config.yaml` pins every hook to an immutable upstream tag and runs the same lint and type checks as CI.

Add meaningful tests for authorization boundaries, signing, deployment changes and failures. Never commit secrets, live login URLs or customer data. Contributions use the repository's MIT license. Dependencies keep their respective licenses; do not copy proprietary CyberArk SDK files into this repository.

## Code conventions

- Target Python 3.11+ syntax; `pyproject.toml` declares 3.11 as the floor and CI tests 3.11-3.14.
- Add type annotations to new functions. Everything outside `tests/` is type-checked, including `scripts/`; keep it free of `Any` leaks and blind re-`raise`s.
- Broad `except Exception` is only acceptable at third-party boundaries (cloud SDK, `requests`, Redis, WSGI startup) where the whole point is to stop vendor text or credentials from reaching logs. Annotate those with `# noqa: BLE001` and a one-line reason, and re-raise a sanitized error with `from None`.
- Never log, return or embed credentials, temporary tokens, login URLs or raw API error text. Sanitize at the boundary and correlate with the request ID instead.
- Keep expected failures fail-closed: a validation or backend ambiguity must deny the operation (no credentials issued, no key retired) rather than proceed.

Windows and live-cloud test evidence must distinguish tests actually run from planned tests. Do not describe mock tests as real PSM certification. The project is independent and must not be described as officially supported or certified without written confirmation.
