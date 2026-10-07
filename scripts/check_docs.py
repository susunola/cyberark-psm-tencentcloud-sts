"""Offline checks for local documentation links and supported CLI examples."""
import re
import shlex
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.pamctl import build_parser  # noqa: E402


def check():
    links = commands = 0
    parser = build_parser()
    paths = sorted(ROOT.glob('*.md')) + sorted((ROOT / 'docs').glob('*.md'))
    for path in paths:
        text = path.read_text(encoding='utf-8')
        if text.count('```') % 2:
            raise ValueError('Unbalanced code fence: ' + path.name)
        for destination in re.findall(r'\]\(([^\s)]+)\)', text):
            if '://' in destination:
                continue
            filename, _, anchor = unquote(destination).partition('#')
            target = (path.parent / filename).resolve() if filename else path
            if not target.is_file() or not target.is_relative_to(ROOT):
                raise ValueError('Broken local documentation link: ' + path.name)
            if anchor:
                content = target.read_text(encoding='utf-8')
                headings = re.findall(r'^#+\s+(.+)$', content, re.M)
                slugs = [re.sub(r'[^\w\s-]', '', h.lower()).replace(' ', '-') for h in headings]
                if f'id="{anchor}"' not in content and anchor not in slugs:
                    raise ValueError('Broken local documentation anchor: ' + path.name)
            links += 1
        # Full CLI examples in the installation manuals; no API or secret input is executed.
        if path.name.startswith('INSTALLATION-AND-USAGE'):
            for example in re.findall(r'python scripts/pamctl\.py ([^`\n]+)', text):
                args = shlex.split(example.split('|')[0].strip(), posix=False)
                args = [a[1:-1] if a.startswith('"') and a.endswith('"') else a for a in args]
                parser.parse_args(args)
                commands += 1
    print(f'Documentation validated: {links} local links and {commands} CLI examples')


if __name__ == '__main__':
    try:
        check()
    except ValueError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2) from error
