import copy
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree

from app import create_app, normalize_audit_label
from configuration import validate_settings
from federation import FederationError, login_url, validate_destination
from version import VERSION

ROOT = Path(__file__).resolve().parents[1]


def workflow_sources():
    """Every workflow file plus the template published for it."""
    return sorted((ROOT / '.github/workflows').glob('*.yml')) + sorted((ROOT / 'deployment').glob('*-workflow.yml.template'))


def powershell_steps(text):
    """The line number and command of every step that runs under `shell: pwsh`."""
    steps = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r'^\s*run:\s*(.*)$', line)
        if match is None:
            continue
        shell = ''
        for previous in reversed(lines[:index]):
            stripped = previous.strip()
            starts_step = stripped.startswith('- ')
            candidate = stripped[2:] if starts_step else stripped
            if candidate.startswith('shell:'):
                shell = candidate.partition(':')[2].strip()
            if starts_step:
                break
        if shell == 'pwsh':
            steps.append((index + 1, match.group(1).strip()))
    return steps


class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.settings = {'profiles': {'readonly': {'role_arn': 'qcs::cam::uin/123:roleName/ReadOnly',
            'allowed_secret_ids': ['broker-id'], 'destination': 'https://console.tencentcloud.com/',
            'duration_seconds': 300, 'region': 'ap-guangzhou'}}}
        self.calls = []
        def sts(*args):
            self.calls.append(args)
            return {'TmpSecretId': 'AKID-TEST', 'TmpSecretKey': 'fake-temp-key', 'Token': 'fake-token'}
        self.app = create_app(self.settings, proxy_key='p'*32, session_key='s'*32, sts=sts)
        self.client = self.app.test_client()
        self.headers = {'X-PSM-Bridge-Key': 'p'*32, 'X-PSM-Authenticated-User': 'PSMConnect'}

    def form(self):
        response = self.client.get('/', headers=self.headers, base_url='https://bridge.local')
        token = re.search(r'name="csrf" value="([^"]+)"', response.text).group(1)
        return {'csrf': token, 'secret_id': 'broker-id', 'secret_key': 'fake-broker-key', 'profile': 'readonly', 'audit_label': 'alice'}

    def post(self, data):
        return self.client.post('/connect', data=data, headers=self.headers, base_url='https://bridge.local')

    def test_bad_configurations(self):
        for field, value in [('duration_seconds', True), ('duration_seconds', 301), ('duration_seconds', 0),
            ('allowed_secret_ids', 'broker-id'), ('allowed_secret_ids', []), ('allowed_secret_ids', ['REPLACE_ME']),
            ('role_arn', '*'), ('region', None), ('destination', 123)]:
            with self.subTest(field=field, value=value):
                settings = copy.deepcopy(self.settings); settings['profiles']['readonly'][field] = value
                with self.assertRaises((ValueError, FederationError)):
                    validate_settings(settings)

    def test_unknown_settings_rejected(self):
        with self.assertRaises(ValueError):
            validate_settings({**self.settings, 'secret_key': 'fake-secret'})

    def test_caller_cannot_bind_to_two_profiles(self):
        self.settings['profiles']['admin'] = copy.deepcopy(self.settings['profiles']['readonly'])
        with self.assertRaises(ValueError):
            validate_settings(self.settings)

    def test_independent_service_keys(self):
        with self.assertRaises(ValueError):
            create_app(self.settings, proxy_key='x'*32, session_key='x'*32)

    def test_health_is_authenticated(self):
        self.assertEqual(self.client.get('/healthz').status_code, 403)
        r = self.client.get('/healthz', headers=self.headers)
        self.assertEqual(r.json['status'], 'ok')

    def test_security_headers_and_cookie(self):
        r = self.client.get('/', headers=self.headers, base_url='https://bridge.local')
        for flag in ('Secure', 'HttpOnly', 'SameSite=Strict'):
            self.assertIn(flag, r.headers['Set-Cookie'])
        self.assertIn('form-action \'self\' https://www.tencentcloud.com', r.headers['Content-Security-Policy'])
        self.assertEqual(r.headers['Referrer-Policy'], 'no-referrer')
        self.assertRegex(r.headers['X-Request-ID'], r'^[0-9a-f]{32}$')

    def test_duplicate_and_unknown_fields(self):
        from werkzeug.datastructures import MultiDict
        data = MultiDict(self.form()); data.add('profile', 'admin')
        self.assertEqual(self.post(data).status_code, 400)
        data = self.form(); data['role_arn'] = 'admin'
        self.assertEqual(self.post(data).status_code, 400)
        self.assertFalse(self.calls)

    def test_expired_csrf(self):
        data = self.form()
        with patch('security.time.monotonic', return_value=time.monotonic() + 121):
            self.assertEqual(self.post(data).status_code, 403)
        self.assertFalse(self.calls)

    def test_request_size_limit(self):
        data = self.form(); data['secret_key'] = 'x'*9000
        self.assertEqual(self.post(data).status_code, 413)

    def test_unexpected_exception_redacted(self):
        def failure(*args):
            raise RuntimeError('FAKE-SECRET-EXCEPTION')
        self.app = create_app(self.settings, proxy_key='p'*32, session_key='s'*32, sts=failure)
        self.client = self.app.test_client()
        r = self.post(self.form())
        self.assertEqual(r.status_code, 502)
        self.assertNotIn('FAKE-SECRET-EXCEPTION', r.text)

    def test_safe_audit_correlation(self):
        with self.assertLogs('psm_tencent.audit', level='INFO') as captured:
            data = self.form(); response = self.post(data)
        output = '\n'.join(captured.output)
        self.assertIn(response.headers['X-Request-ID'], output)
        self.assertIn(self.calls[0][3], output)
        for secret in ('fake-broker-key', 'fake-temp-key', 'fake-token', 'roleAccessCallback'):
            self.assertNotIn(secret, output)

    def test_invalid_url_types(self):
        for value in (None, 42, [], '', 'https://console.tencentcloud.com/\n', 'https://console.tencentcloud.com/\\evil'):
            with self.assertRaises(FederationError):
                validate_destination(value)

    def test_invalid_temporary_credentials(self):
        for creds in ({}, {'TmpSecretId': 'bad&id', 'TmpSecretKey': 'key', 'Token': 'token'}):
            with self.assertRaises(FederationError):
                login_url(creds, 'https://console.tencentcloud.com/')

    def test_shared_token_config_grants_only_the_service_account_read(self):
        """The shared Redis/session configuration is readable by LocalService on purpose.

        Unlike the generated proxy configuration, WinSW must read this file at start-up,
        so LocalService read is required here. Pin the exact principal set so a future
        reader does not remove the necessary grant, and pin the absence of a broad one.
        """
        script = (ROOT / "scripts/Configure-SharedTokens.ps1").read_text(encoding="utf-8")
        self.assertIn("'/inheritance:r'", script)
        self.assertIn("'*S-1-5-18:F'", script)  # SYSTEM
        self.assertIn("'*S-1-5-32-544:F'", script)  # Administrators
        self.assertIn("'*S-1-5-19:R'", script)  # LocalService, read only
        for broad in ("*S-1-1-0", "*S-1-5-32-545", "*S-1-5-11", "*S-1-5-32-546"):
            self.assertNotIn(broad, script, f"{broad} must never be granted")
        # The copy happens first, so the protection immediately follows it.
        self.assertLess(script.index("[System.IO.File]::Copy"), script.index("& icacls.exe"))
        # A failed protection must abort before the service configuration is touched.
        self.assertLess(script.index("& icacls.exe"), script.index("Save-SharedServiceConfig -Document"))

    def test_shared_token_config_validates_and_refuses_before_it_mutates(self):
        script = (ROOT / "scripts/Configure-SharedTokens.ps1").read_text(encoding="utf-8")
        # Stops or asks for -Restart, refuses an existing configuration or backup, and
        # proves the configuration works through the real Python loader, silently.
        self.assertIn("Stop the service or explicitly supply -Restart", script)
        self.assertIn("Existing shared configuration or backup found", script)
        self.assertIn("configured_token_store(shared_environment(os.environ))", script)
        self.assertIn("no details are printed", script)
        # Validation precedes the file copy that makes the configuration live.
        self.assertLess(script.index("configured_token_store"), script.index("[System.IO.File]::Copy"))

    def test_uninstall_preserves_evidence_and_is_guarded(self):
        script = (ROOT / "scripts" / "Uninstall-Bridge.ps1").read_text(encoding="utf-8")
        self.assertIn("#Requires -RunAsAdministrator", script)
        # An uninstall must not destroy the service configuration or its secrets: they are
        # audit and rollback evidence, and the operator is told what remains.
        self.assertNotIn("Remove-Item", script)
        self.assertIn("Files preserved for audit/rollback", script)
        self.assertIn("Remove the dedicated IIS site", script)

    def test_ci_powershell_steps_invoke_a_script_instead_of_inlining_it(self):
        # tests/test_powershell_syntax.py parses every file under scripts/, which is exactly
        # what inline PowerShell in a workflow escapes: its syntax errors would surface for
        # the first time on the runner that executes the step, and only there.
        for path in workflow_sources():
            steps = powershell_steps(path.read_text(encoding='utf-8'))
            for line, command in steps:
                with self.subTest(workflow=path.name, line=line):
                    self.assertRegex(command, r'^\./scripts/[\w./-]+\.ps1$')
        # The scan itself must be reaching the workflows, and the Windows job in
        # particular, or this test would pass by finding nothing at all.
        names = {path.name for path in workflow_sources()}
        self.assertIn('ci.yml', names)
        self.assertTrue(any(powershell_steps(path.read_text(encoding='utf-8')) for path in workflow_sources()))

    def test_every_workflow_template_matches_its_workflow(self):
        # README advertises the templates as matching; keep them byte-identical so a
        # deployment cannot follow a gate the repository does not run.
        templates = sorted((ROOT / 'deployment').glob('*-workflow.yml.template'))
        self.assertTrue(templates, 'no workflow templates were found')
        for template in templates:
            workflow = ROOT / '.github/workflows' / template.name.replace('-workflow.yml.template', '.yml')
            with self.subTest(template=template.name):
                self.assertTrue(workflow.is_file(), f'{template.name} has no {workflow.name}')
                self.assertEqual(template.read_bytes(), workflow.read_bytes())

    def test_proxy_template_overwrites_headers(self):
        root = ElementTree.parse(ROOT / 'deployment/web.config.template').getroot()
        variables = {v.attrib['name']: v.attrib['value'] for v in root.findall('.//serverVariables/set')}
        self.assertEqual(variables['HTTP_X_PSM_AUTHENTICATED_USER'], '{REMOTE_USER}')
        self.assertEqual(variables['HTTP_X_PSM_BRIDGE_KEY'], 'REPLACE_WITH_PRIVATE_PROXY_KEY')

    def test_enterprise_audit_labels(self):
        for label in ('DOMAIN\\alice', '张三', 'alice'*40):
            value = normalize_audit_label(label)
            self.assertRegex(value, r'^[A-Za-z0-9_.@=-]{2,64}$')
            self.assertEqual(value, normalize_audit_label(label))
        self.assertNotEqual(normalize_audit_label('DOMAIN\\alice'), normalize_audit_label('DOMAIN/alice'))
        data = self.form(); data['audit_label'] = 'DOMAIN\\alice'
        self.assertEqual(self.post(data).status_code, 303)
        self.assertLessEqual(len(self.calls[0][3]), 128)

    def test_installer_verifies_dependency_hashes(self):
        # Static assertion: the installer must prefer the hash-pinned lock, because
        # this pip install runs elevated. Windows behaviour is verified on CI.
        installer = (ROOT / "scripts/Install-Bridge.ps1").read_text(encoding="utf-8")
        self.assertIn("requirements.lock.hashes.txt", installer)
        self.assertIn("'--require-hashes'", installer)
        verified = installer.index("'--require-hashes'")
        fallback = installer.index("without hash verification")
        self.assertLess(verified, fallback)
        self.assertEqual(installer.count("'pip','install'"), 2)

    def test_installer_reprotects_the_generated_proxy_config(self):
        # The install directory grants LocalService read for the service XML, so the
        # generated file holding the proxy key must be re-protected after it is written.
        installer = (ROOT / "scripts/Install-Bridge.ps1").read_text(encoding="utf-8")
        written = installer.index("web.config.generated'")
        protection = installer.index("/inheritance:r', '/grant:r', '*S-1-5-18:F', '*S-1-5-32-544:R'")
        self.assertLess(written, protection)
        # Only SYSTEM and administrators, and no LocalService read on that path.
        self.assertNotIn("*S-1-5-19:F", installer)

    def test_proxy_template_replaces_rather_than_appends_identity_headers(self):
        template = (ROOT / "deployment" / "web.config.template").read_text(encoding="utf-8")
        # <set> replaces the server variable; <add> would append, letting a client
        # supply part of the identity the bridge trusts.
        self.assertEqual(template.count("<set name="), 2)
        self.assertNotIn("<add name=", template)

    def test_release_is_reproducible_and_excludes_secrets(self):
        from zipfile import ZipFile
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for folder in (first, second):
                subprocess.run([sys.executable, str(ROOT/'scripts/build_release.py'), '--out', folder], check=True, capture_output=True)
            a = Path(first)/f'psm-tencentcloud-sts-{VERSION}-source.zip'
            b = Path(second)/a.name
            self.assertEqual(a.read_bytes(), b.read_bytes())
            import hashlib
            import json
            bom = Path(first) / 'dependency-sbom.cdx.json'
            self.assertEqual(bom.read_bytes(), (Path(second) / bom.name).read_bytes())
            inventory = json.loads(bom.read_text())
            self.assertEqual(inventory['bomFormat'], 'CycloneDX')
            self.assertEqual(inventory['metadata']['component']['version'], VERSION)
            with ZipFile(a) as archive:
                names = archive.namelist()
                # The public source archive must carry the local quality gate too.
                for required in ('psm-tencentcloud-sts/pyproject.toml',
                                 'psm-tencentcloud-sts/requirements-dev.txt',
                                 'psm-tencentcloud-sts/requirements.lock.hashes.txt',
                                 'psm-tencentcloud-sts/.pre-commit-config.yaml'):
                    self.assertIn(required, names)
                self.assertFalse(any(n.endswith('/settings.json') or '.git/' in n or '__pycache__' in n for n in names))
            locked = {}
            for raw in (ROOT / 'requirements.lock.txt').read_text().splitlines():
                entry = raw.split('\\')[0].split('--hash')[0].strip()
                if '==' in entry:
                    name, _, pinned = entry.partition('==')
                    locked[name.lower()] = pinned
            self.assertEqual({c['name'].lower(): c['version'] for c in inventory['components']}, locked)
            for line in (Path(first) / 'SHA256SUMS').read_text().splitlines():
                digest, name = line.split('  ')
                self.assertEqual(digest, hashlib.sha256((Path(first) / name).read_bytes()).hexdigest())
            with ZipFile(a) as archive:
                names = archive.namelist()
                self.assertIn('psm-tencentcloud-sts/LICENSE', names)
                self.assertFalse(any(n.endswith('/settings.json') or '.git/' in n or '__pycache__' in n for n in names))


if __name__ == '__main__':
    unittest.main()
