# Contributing

Maintainer: **susunola**. English is the default documentation language; update `README.zh-CN.md` when changing setup or behavior.

Create a branch, explain the concrete problem, and run:

```text
python -m pip install -r requirements.lock.txt
python -m unittest discover -s tests -v
python scripts/build_release.py --out dist
```

Add meaningful tests for authorization boundaries, signing, deployment changes and failures. Never commit secrets, live login URLs or customer data. Contributions use the repository's MIT license. Dependencies keep their respective licenses; do not copy proprietary CyberArk SDK files into this repository.

Windows and live-cloud test evidence must distinguish tests actually run from planned tests. Do not describe mock tests as real PSM certification. The project is independent and must not be described as officially supported or certified without written confirmation.
