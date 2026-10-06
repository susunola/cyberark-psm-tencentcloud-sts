import copy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock
from pam.files import read_json, private_output
from pam.lifecycle import recover_ticket, LifecycleError
from pam.maintenance import run, validate_jobs


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.cloud, self.vault = MagicMock(), MagicMock()
        self.op = 'a'*32
        self.journal = {'operation':self.op, 'status':'preparing', 'old_account':'old-account', 'target_uin':'123', 'profile':'readonly'}
        self.old = {'id':'old-account','address':'cloud.tencent.com','safeName':'CloudSafe','platformId':'TencentSTS', 'userName':'broker',
                    'platformAccountProperties':{'TencentSecretId':'old-id','TencentRoleProfile':'readonly'}}
        self.new = copy.deepcopy(self.old); self.new['id']='new-account'; self.new['platformAccountProperties']['TencentSecretId']='new-id'
        self.vault.account.side_effect=lambda value:self.old if value=='old-account' else self.new
        self.vault.find_rotation_accounts.return_value=[{'id':'new-account'}]
        self.vault.secret.return_value='FAKE-SECRET'
        self.cloud.keys.return_value=[{'id':'old-id','status':'Active','description':''},
                                     {'id':'new-id','status':'Active','description':'psm-rotation:'+self.op}]

    def test_recovery_verifies_without_creating_or_retiring(self):
        ticket=recover_ticket(self.cloud,self.vault,self.journal)
        self.assertEqual(ticket.new_account,'new-account')
        self.assertNotIn('FAKE-SECRET',repr(ticket))
        self.cloud.verify.assert_called_once_with('new-id','FAKE-SECRET','123')
        self.cloud.create_key.assert_not_called(); self.cloud.set_key_status.assert_not_called(); self.vault.create.assert_not_called()

    def test_uncertain_missing_or_ambiguous_vault_save_cannot_recover(self):
        for matches in ([],[{'id':'new-account'},{'id':'duplicate'}]):
            self.vault.find_rotation_accounts.return_value=matches
            with self.assertRaises(LifecycleError):recover_ticket(self.cloud,self.vault,self.journal)
        self.cloud.create_key.assert_not_called()

    def test_recovery_scope_changed_or_identity_invalid(self):
        self.new['safeName']='DifferentSafe'
        with self.assertRaises(LifecycleError):recover_ticket(self.cloud,self.vault,self.journal)
        self.new['safeName']='CloudSafe'; self.cloud.verify.side_effect=ValueError('mismatch')
        with self.assertRaises(ValueError):recover_ticket(self.cloud,self.vault,self.journal)
        self.cloud.set_key_status.assert_not_called()

    def test_bounded_duplicate_free_json_and_exclusive_output(self):
        with self.assertRaises(ValueError):read_json(stream=io.StringIO('{"x":1,"x":2}'))
        with self.assertRaises(ValueError):read_json(stream=io.StringIO(' '*20),limit=10)
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'ticket.json'
            with private_output(path) as sink:sink.write('original')
            with self.assertRaises(FileExistsError):private_output(path)
            self.assertEqual(path.read_text(),'original')


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        RecoveryTests.setUp(self)
        self.jobs={'jobs':[{'id':'caller','action':'verify-cam','account':'old-account','target_uin':'123',
                           'profile':'readonly','safe':'CloudSafe','platform':'TencentSTS'}]}
        self.settings={'profiles':{'readonly':{'allowed_secret_ids':['old-id'], 'role_arn':'qcs::cam::uin/123:roleName/ReadOnly',
                    'duration_seconds':300,'region':'ap-guangzhou'}}}

    def test_verification_never_rotates(self):
        role=MagicMock()
        with tempfile.TemporaryDirectory() as folder:
            result=run(self.jobs,self.settings,folder,self.cloud,self.vault,role)
            self.assertEqual(result[0]['status'],'identity-and-role-verified')
            self.assertFalse((Path(folder)/'.maintenance.lock').exists())
        role.assert_called_once();self.cloud.create_key.assert_not_called()

    def test_schedule_cannot_auto_finalize_and_scope_is_pinned(self):
        self.jobs['jobs'][0]['action']='finalize'
        with self.assertRaises(ValueError):validate_jobs(self.jobs)
        self.jobs['jobs'][0]['action']='verify-cam';self.jobs['jobs'][0]['safe']='OtherSafe'
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):run(self.jobs,self.settings,folder,self.cloud,self.vault,MagicMock())
        self.vault.secret.assert_not_called()

    def test_existing_lock_stops_api_calls(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder)/'.maintenance.lock').write_text('existing')
            with self.assertRaises(FileExistsError):run(self.jobs,self.settings,folder,self.cloud,self.vault,MagicMock())
        self.vault.account.assert_not_called()

    def test_existing_preparation_ticket_prevents_new_cloud_write(self):
        self.jobs['jobs'][0]['action']='prepare-key'
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder)/'caller.json').write_text('reserved')
            with self.assertRaises(FileExistsError):run(self.jobs,self.settings,folder,self.cloud,self.vault,MagicMock())
            self.assertEqual((Path(folder)/'caller.json').read_text(),'reserved')
        self.cloud.create_key.assert_not_called()

    def test_uncertain_preparation_leaves_recoverable_journal(self):
        self.jobs['jobs'][0]['action']='prepare-key'
        self.cloud.keys.return_value=self.cloud.keys.return_value[:1]
        self.cloud.create_key.return_value=('new-id','FAKE-SECRET')
        self.vault.create.side_effect=TimeoutError('uncertain-save')
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(LifecycleError):run(self.jobs,self.settings,folder,self.cloud,self.vault,MagicMock())
            journal=read_json(Path(folder)/'caller.json')
            self.assertEqual(journal['old_account'],'old-account')
            self.assertNotIn('FAKE-SECRET',repr(journal))
            self.assertFalse((Path(folder)/'.maintenance.lock').exists())
        self.cloud.set_key_status.assert_not_called()


if __name__=='__main__':unittest.main()
