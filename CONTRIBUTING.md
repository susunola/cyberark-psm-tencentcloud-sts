# Contributing

Maintainer: **susunola**. English is the default documentation language; update `README.zh-CN.md` when changing setup or behavior.

Create a branch, explain the concrete problem, and run the full quality gate:

```text
python -m pip install -r requirements.lock.txt -r requirements-dev.txt
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m pytest -q
python scripts/build_release.py --out dist
```

`pytest` runs the coverage gate declared in `pyproject.toml` and fails below the threshold; use `python -m pytest -q --no-cov` while iterating. `python -m unittest discover -s tests -v` remains supported and is what CI's matrix jobs run.

Optional: install the git hooks once per clone with `pre-commit install`. `.pre-commit-config.yaml` pins every hook to an immutable upstream tag and runs the same lint/format/type checks as CI.

Add meaningful tests for authorization boundaries, signing, deployment changes and failures. Never commit secrets, live login URLs or customer data. Contributions use the repository's MIT license. Dependencies keep their respective licenses; do not copy proprietary CyberArk SDK files into this repository.

## Code conventions

- Target Python 3.10+ syntax; the runtime floor is Python 3.10 even though CI tests 3.11–3.13.
- Add type annotations to new functions. All modules outside `tests/` are checked with strict mypy; keep them free of `Any` leaks and blind re-`raise`s.
- Broad `except Exception` is only acceptable at third-party boundaries (cloud SDK, `requests`, Redis, WSGI startup) where the whole point is to stop vendor text or credentials from reaching logs. Annotate those with `# noqa: BLE001` and a one-line reason, and re-raise a sanitized error with `from None`.
- Never log, return or embed credentials, temporary tokens, login URLs or raw API error text. Sanitize at the boundary and correlate with the request ID instead.
- Prefer module-level named constants over inline magic numbers and strings.

Windows and live-cloud test evidence must distinguish tests actually run from planned tests. Do not describe mock tests as real PSM certification. The project is independent and must not be described as officially supported or certified without written confirmation.
