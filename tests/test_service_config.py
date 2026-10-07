import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(shutil.which('pwsh'), 'PowerShell integration runs on Windows CI')
class ServiceConfigTests(unittest.TestCase):
    def invoke(self, directory, script):
        helper=Path(__file__).resolve().parents[1]/'scripts/Shared-ServiceConfig.ps1'
        runner=directory/'run.ps1'
        runner.write_text("$ErrorActionPreference = 'Stop'\n. $args[0]\n"+script,encoding='utf-8')
        return subprocess.run(['pwsh','-NoProfile','-File',str(runner),str(helper)],cwd=directory,capture_output=True,text=True,check=False)

    def test_atomic_replace_and_exact_original_backup(self):
        with tempfile.TemporaryDirectory() as folder:
            directory=Path(folder);original='<service><env name="PSM_TC_PROXY_KEY" value="FAKE-KEY" /></service>'
            (directory/'service.xml').write_text(original)
            result=self.invoke(directory,"$d = New-SharedServiceConfig 'service.xml' 'shared-secrets.json'\nSave-SharedServiceConfig $d 'service.xml' 'backup.xml'\n")
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual((directory/'backup.xml').read_text(),original)
            self.assertIn('PSM_TC_SHARED_CONFIG',(directory/'service.xml').read_text())
            self.assertFalse((directory/'service.xml.shared.tmp').exists())

    def test_duplicate_entry_and_dtd_fail_without_modifying_original(self):
        with tempfile.TemporaryDirectory() as folder:
            directory=Path(folder)
            for original in ['<service><env name="PSM_TC_SHARED_CONFIG" value="FAKE-SECRET" /></service>',
                             '<!DOCTYPE service [<!ENTITY value "FAKE-SECRET">]><service>&value;</service>']:
                (directory/'service.xml').write_text(original)
                result=self.invoke(directory,"New-SharedServiceConfig 'service.xml' 'shared-secrets.json'\n")
                self.assertNotEqual(result.returncode,0)
                self.assertNotIn('FAKE-SECRET',result.stderr)
                self.assertEqual((directory/'service.xml').read_text(),original)

    def test_existing_backup_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            directory=Path(folder);(directory/'service.xml').write_text('<service/>');(directory/'backup.xml').write_text('prior')
            result=self.invoke(directory,"$d=New-SharedServiceConfig 'service.xml' 'shared-secrets.json'\nSave-SharedServiceConfig $d 'service.xml' 'backup.xml'\n")
            self.assertNotEqual(result.returncode,0)
            self.assertEqual((directory/'service.xml').read_text(),'<service/>')
            self.assertEqual((directory/'backup.xml').read_text(),'prior')

    def test_existing_update_lock_preserves_service_and_lock(self):
        with tempfile.TemporaryDirectory() as folder:
            directory=Path(folder);(directory/'service.xml').write_text('<service/>');(directory/'service.xml.shared.lock').write_text('active')
            result=self.invoke(directory,"$d=New-SharedServiceConfig 'service.xml' 'shared-secrets.json'\nSave-SharedServiceConfig $d 'service.xml' 'backup.xml'\n")
            self.assertNotEqual(result.returncode,0)
            self.assertEqual((directory/'service.xml').read_text(),'<service/>')
            self.assertEqual((directory/'service.xml.shared.lock').read_text(),'active')
            self.assertFalse((directory/'backup.xml').exists())


if __name__=='__main__':unittest.main()
