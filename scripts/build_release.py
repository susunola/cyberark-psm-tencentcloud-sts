"""Create a reproducible source distribution and SHA256 manifest, excluding secrets."""
import argparse
import hashlib
from pathlib import Path
import sys
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from version import VERSION

FILES = ['app.py', 'configuration.py', 'federation.py', 'security.py', 'runtime.py', 'version.py', 'README.md', 'README.zh-CN.md',
         'requirements.in', 'requirements.lock.txt', 'WebFormFields.template.txt',
         'settings.example.json', 'cam-assume-policy.example.json', 'SECURITY.md',
         'CONTRIBUTING.md', 'CHANGELOG.md', 'NOTICE.md', 'LICENSE']
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--out', type=Path, required=True)
args = parser.parse_args()
files = [ROOT / name for name in FILES]
for folder in ('scripts', 'deployment', 'docs', 'tests', 'pam'):
    files.extend(p for p in (ROOT / folder).rglob('*') if p.is_file() and (p.suffix in ('.py', '.ps1', '.md', '.template') or p.name.endswith('.example.json')))
args.out.mkdir(parents=True, exist_ok=True)
archive = args.out / f'psm-tencentcloud-sts-{VERSION}-source.zip'
with ZipFile(archive, 'w', compression=ZIP_DEFLATED) as output:
    for path in sorted(files):
        data = path.read_bytes()
        info = ZipInfo('psm-tencentcloud-sts/' + path.relative_to(ROOT).as_posix(), date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type = ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        output.writestr(info, data)
(args.out / 'SHA256SUMS').write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name + '\n')
print(archive.name)
