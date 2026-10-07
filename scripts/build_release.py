"""Create a reproducible source distribution and SHA256 manifest, excluding secrets."""
import argparse
import hashlib
import json
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from version import VERSION  # noqa: E402

FILES = ['app.py', 'configuration.py', 'federation.py', 'security.py', 'runtime.py', 'validate.py', 'version.py', 'README.md', 'README.zh-CN.md',
         'requirements.in', 'requirements.lock.txt', 'requirements.lock.hashes.txt',
         'requirements-dev.txt', 'pyproject.toml',
         '.pre-commit-config.yaml', 'WebFormFields.template.txt',
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
        if path.is_symlink() or not path.resolve().is_relative_to(ROOT):
            raise ValueError('Source archive refuses symlinks or external paths')
        data = path.read_bytes()
        info = ZipInfo('psm-tencentcloud-sts/' + path.relative_to(ROOT).as_posix(), date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type = ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        output.writestr(info, data)
# Inventory describes the locked source dependencies, not installed production hosts.
components = []
for raw in (ROOT / 'requirements.lock.txt').read_text().splitlines():
    # Tolerate a hash-pinned lock: 'name==version \' followed by '--hash=sha256:...' lines.
    line = raw.split('\\')[0].split('--hash')[0].strip()
    if not line or line.startswith('#'):
        continue
    name, version = line.split('==')
    components.append({'type': 'library', 'name': name, 'version': version,
                       'purl': f'pkg:pypi/{name.lower()}/{version}'})
bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
       'metadata': {'component': {'type': 'application', 'name': 'psm-tencentcloud-sts', 'version': VERSION}},
       'components': sorted(components, key=lambda c: c['name'].lower())}
(args.out / 'dependency-sbom.cdx.json').write_text(json.dumps(bom, indent=2) + '\n')
(args.out / 'SHA256SUMS').write_text(''.join(
    hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n'
    for path in (archive, args.out / 'dependency-sbom.cdx.json')))
print(archive.name)
