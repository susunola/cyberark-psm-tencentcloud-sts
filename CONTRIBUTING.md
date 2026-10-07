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
python scripts/build_release.py --out dist
```

`mypy` takes its target list from `pyproject.toml`, and `coverage report` enforces the coverage threshold declared there (95%; currently measured at 99%). Raise the gate only together with real tests. `python -m unittest discover -s tests -v` is the single runner used locally and by CI, including the Windows/Ubuntu and Python 3.11-3.13 matrix.

Lint is enforced but formatting is not: the test and script suites keep intentional compact one-liners, so `ruff format` must not be run over them.

Optional: install the git hooks once per clone with `pre-commit install`. `.pre-commit-config.yaml` pins every hook to an immutable upstream tag and runs the same lint and type checks as CI.

Add meaningful tests for authorization boundaries, signing, deployment changes and failures. Never commit secrets, live login URLs or customer data. Contributions use the repository's MIT license. Dependencies keep their respective licenses; do not copy proprietary CyberArk SDK files into this repository.

## Code conventions

- Target Python 3.11+ syntax; `pyproject.toml` declares 3.11 as the floor and CI tests 3.11-3.13.
- Add type annotations to new functions. Everything outside `tests/` is type-checked, including `scripts/`; keep it free of `Any` leaks and blind re-`raise`s.
- Broad `except Exception` is only acceptable at third-party boundaries (cloud SDK, `requests`, Redis, WSGI startup) where the whole point is to stop vendor text or credentials from reaching logs. Annotate those with `# noqa: BLE001` and a one-line reason, and re-raise a sanitized error with `from None`.
- Never log, return or embed credentials, temporary tokens, login URLs or raw API error text. Sanitize at the boundary and correlate with the request ID instead.
- Keep expected failures fail-closed: a validation or backend ambiguity must deny the operation (no credentials issued, no key retired) rather than proceed.

Windows and live-cloud test evidence must distinguish tests actually run from planned tests. Do not describe mock tests as real PSM certification. The project is independent and must not be described as officially supported or certified without written confirmation.
