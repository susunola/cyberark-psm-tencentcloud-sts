"""Create a reproducible source distribution and SHA256 manifest, excluding secrets."""

import argparse
import hashlib
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]

TOP_LEVEL_FILES = (
    "app.py",
    "configuration.py",
    "federation.py",
    "security.py",
    "runtime.py",
    "version.py",
    "README.md",
    "README.zh-CN.md",
    "requirements.in",
    "requirements.lock.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    ".pre-commit-config.yaml",
    "WebFormFields.template.txt",
    "settings.example.json",
    "cam-assume-policy.example.json",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "NOTICE.md",
    "LICENSE",
)
PACKAGED_DIRECTORIES = ("scripts", "deployment", "docs", "tests", "pam")
PACKAGED_SUFFIXES = (".py", ".ps1", ".md", ".template")
# Fixed timestamp keeps the archive byte-for-byte reproducible.
FIXED_TIMESTAMP = (2026, 1, 1, 0, 0, 0)
ARCHIVE_ROOT = "psm-tencentcloud-sts/"


def collected_files() -> list[Path]:
    files = [ROOT / name for name in TOP_LEVEL_FILES]
    for folder in PACKAGED_DIRECTORIES:
        files.extend(
            path
            for path in (ROOT / folder).rglob("*")
            if path.is_file() and (path.suffix in PACKAGED_SUFFIXES or path.name.endswith(".example.json"))
        )
    return sorted(files)


def build(out: Path) -> Path:
    sys.path.insert(0, str(ROOT))
    from version import VERSION

    out.mkdir(parents=True, exist_ok=True)
    archive = out / f"psm-tencentcloud-sts-{VERSION}-source.zip"
    with ZipFile(archive, "w", compression=ZIP_DEFLATED) as output:
        for path in collected_files():
            info = ZipInfo(ARCHIVE_ROOT + path.relative_to(ROOT).as_posix(), date_time=FIXED_TIMESTAMP)
            info.compress_type = ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            output.writestr(info, path.read_bytes())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (out / "SHA256SUMS").write_text(f"{digest}  {archive.name}\n")
    return archive


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    print(build(args.out).name)


if __name__ == "__main__":
    main()
