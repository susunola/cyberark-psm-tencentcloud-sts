"""Offline checks for local documentation links and supported CLI examples."""

import argparse
import re
import shlex
import sys
from pathlib import Path
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.pamctl import build_parser

ROOT = Path(__file__).resolve().parents[1]
DOCUMENTED_MANUALS = "INSTALLATION-AND-USAGE"
LINK_PATTERN = re.compile(r"\]\(([^\s)]+)\)")
HEADING_PATTERN = re.compile(r"^#+\s+(.+)$", re.M)
CLI_EXAMPLE_PATTERN = re.compile(r"python scripts/pamctl\.py ([^`\n]+)")
SLUG_UNSAFE_PATTERN = re.compile(r"[^\w\s-]")
EXIT_INVALID_DOCS = 2


def documented_paths() -> list[Path]:
    return sorted(ROOT.glob("*.md")) + sorted((ROOT / "docs").glob("*.md"))


def anchor_exists(content: str, anchor: str) -> bool:
    if f'id="{anchor}"' in content:
        return True
    headings = HEADING_PATTERN.findall(content)
    slugs = [SLUG_UNSAFE_PATTERN.sub("", heading.lower()).replace(" ", "-") for heading in headings]
    return anchor in slugs


def check_links(path: Path, text: str) -> int:
    """Return the number of valid local links in one document."""
    links = 0
    for destination in LINK_PATTERN.findall(text):
        if "://" in destination:
            continue
        filename, _, anchor = unquote(destination).partition("#")
        target = (path.parent / filename).resolve() if filename else path
        if not target.is_file() or not target.is_relative_to(ROOT):
            raise ValueError("Broken local documentation link: " + path.name)
        if anchor and not anchor_exists(target.read_text(encoding="utf-8"), anchor):
            raise ValueError("Broken local documentation anchor: " + path.name)
        links += 1
    return links


def check_cli_examples(parser: argparse.ArgumentParser, text: str) -> int:
    """Validate documented pamctl invocations without executing any operation."""
    commands = 0
    for example in CLI_EXAMPLE_PATTERN.findall(text):
        args = shlex.split(example.split("|")[0].strip(), posix=False)
        args = [a[1:-1] if a.startswith('"') and a.endswith('"') else a for a in args]
        parser.parse_args(args)
        commands += 1
    return commands


def check() -> None:
    links = 0
    commands = 0
    parser = build_parser()
    for path in documented_paths():
        text = path.read_text(encoding="utf-8")
        if text.count("```") % 2:
            raise ValueError("Unbalanced code fence: " + path.name)
        links += check_links(path, text)
        if path.name.startswith(DOCUMENTED_MANUALS):
            commands += check_cli_examples(parser, text)
    print(f"Documentation validated: {links} local links and {commands} CLI examples")


def main() -> None:
    try:
        check()
    except ValueError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(EXIT_INVALID_DOCS) from None


if __name__ == "__main__":
    main()
