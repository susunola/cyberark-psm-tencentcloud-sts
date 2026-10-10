import copy
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from pam.cloud import Cloud
from pam.lifecycle import LifecycleError, finalize, prepare, restore_old
from pam.planning import cvm_plan
from pam.vault import Vault, VaultError


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.cloud, self.vault = MagicMock(), MagicMock()
        self.cloud.keys.return_value = [{'id':'old-id','status':'Active','description':''}]
        self.cloud.create_key.return_value = ('new-id', 'FAKE-SECRET')
        self.cloud.verify.return_value = True
        self.old = {'id':'old-account', 'address':'www.tencentcloud.com','userName':'broker',
            'safeName':'CloudSafe','platformId':'TencentSTS',
            'platformAccountProperties':{'TencentSecretId':'old-id','TencentRoleProfile':'readonly'}}
        self.vault.account.return_value = self.old
        self.vault.create.return_value = 'new-account'
        self.operation = 'a'*32
        def update_status(target, secret_id, status):
            for key in self.cloud.keys.return_value:
                if key['id'] == secret_id:
                    key['status'] = status
        self.cloud.set_key_status.side_effect = update_status

    def prepared(self):
        ticket = prepare(self.cloud,self.vault,'old-account','123','readonly',self.operation)
        self.new = copy.deepcopy(self.old)
        self.new['id'] = 'new-account';self.new['platformAccountProperties']['TencentSecretId']='new-id'
        self.vault.account.side_effect = lambda value: self.old if value=='old-account' else self.new
        self.vault.secret.return_value = 'FAKE-SECRET'
        self.cloud.keys.return_value += [{'id':'new-id','status':'Active','description':'psm-rotation:'+self.operation}]
        self.settings = {'profiles':{'readonly':{'allowed_secret_ids':['old-id','new-id'],
            'role_arn':'qcs::cam::uin/123:roleName/ReadOnly','duration_seconds':300,'region':'ap-guangzhou'}}}
        return ticket

    def test_prepare_stores_pair_without_retiring_old(self):
        ticket = self.prepared()
        payload = self.vault.create.call_args.args[0]
        self.assertEqual(payload['secret'],'FAKE-SECRET')
        self.assertEqual(payload['platformAccountProperties']['TencentSecretId'],'new-id')
        self.assertNotIn('FAKE-SECRET',repr(ticket))
        self.cloud.set_key_status.assert_not_called()

    def test_inactive_old_key_requires_reconciliation(self):
        self.cloud.keys.return_value[0]['status'] = 'Inactive'
        with self.assertRaises(LifecycleError):
            prepare(self.cloud, self.vault, 'old-account', '123', 'readonly', self.operation)
        self.cloud.create_key.assert_not_called()

    def test_incomplete_old_account_never_creates_replacement(self):
        del self.old['address']
        with self.assertRaises(LifecycleError):
            prepare(self.cloud, self.vault, 'old-account', '123', 'readonly', self.operation)
        self.cloud.create_key.assert_not_called()

    def test_invalid_replacement_pair_is_not_saved(self):
        self.cloud.create_key.return_value = ('old-id', 'FAKE-SECRET')
        with self.assertRaises(LifecycleError):
            prepare(self.cloud, self.vault, 'old-account', '123', 'readonly', self.operation)
        self.vault.create.assert_not_called(); self.cloud.set_key_status.assert_not_called()

    def test_new_key_disabled_during_role_verification_keeps_old(self):
        ticket = self.prepared()
        def concurrent_change(*args):
            self.cloud.keys.return_value[1]['status'] = 'Inactive'
        with self.assertRaises(LifecycleError):
            finalize(self.cloud, self.vault, ticket, self.settings, confirmed_cutover=True, role_verifier=concurrent_change)
        self.cloud.set_key_status.assert_not_called()

    def test_disable_ack_without_readback_is_not_success(self):
        ticket = self.prepared()
        self.cloud.set_key_status.side_effect = None
        with self.assertRaises(LifecycleError):
            finalize(self.cloud, self.vault, ticket, self.settings, confirmed_cutover=True, role_verifier=MagicMock())
        self.cloud.set_key_status.assert_called_once()

    def test_unknown_old_key_state_never_reports_cutover(self):
        ticket = self.prepared()
        self.cloud.keys.return_value[0]['status'] = 'Unknown'
        with self.assertRaises(LifecycleError):
            finalize(self.cloud, self.vault, ticket, self.settings, confirmed_cutover=True)
        self.cloud.set_key_status.assert_not_called()

    def test_no_spare_slot_never_creates(self):
        self.cloud.keys.return_value.append({'id':'other-id','status':'Active','description':''})
        with self.assertRaises(LifecycleError):prepare(self.cloud,self.vault,'old-account','123','readonly',self.operation)
        self.cloud.create_key.assert_not_called()

    def test_repeated_operation_requires_reconciliation(self):
        self.cloud.keys.return_value[0]['description']='psm-rotation:'+self.operation
        with self.assertRaises(LifecycleError):prepare(self.cloud,self.vault,'old-account','123','readonly',self.operation)
        self.cloud.create_key.assert_not_called()

    def test_uncertain_vault_write_keeps_old_key(self):
        self.vault.create.side_effect=RuntimeError('FAKE-SECRET')
        with self.assertRaises(LifecycleError) as error:prepare(self.cloud,self.vault,'old-account','123','readonly',self.operation)
        self.assertNotIn('FAKE-SECRET',str(error.exception))
        self.cloud.set_key_status.assert_not_called()

    def test_failed_verification_keeps_old_key_and_secret_stays_in_vault(self):
        # SecretKey cannot be read back after CreateAccessKey, so the Vault write
        # must happen before verify; a failed verify leaves the secret recoverable.
        self.cloud.verify.side_effect=RuntimeError('verification failed')
        with self.assertRaises(LifecycleError):prepare(self.cloud,self.vault,'old-account','123','readonly',self.operation)
        self.vault.create.assert_called_once();self.cloud.set_key_status.assert_not_called()

    def test_finalize_requires_operator_confirmation(self):
        ticket=self.prepared()
        with self.assertRaises(LifecycleError):finalize(self.cloud,self.vault,ticket,self.settings)
        self.cloud.set_key_status.assert_not_called()

    def test_finalize_requires_bridge_allowlist_update(self):
        ticket=self.prepared();self.settings['profiles']['readonly']['allowed_secret_ids']=['old-id']
        with self.assertRaises(LifecycleError):finalize(self.cloud,self.vault,ticket,self.settings,confirmed_cutover=True)
        self.cloud.set_key_status.assert_not_called()

    def test_success_disables_only_old_key(self):
        ticket=self.prepared();role=MagicMock()
        result=finalize(self.cloud,self.vault,ticket,self.settings,confirmed_cutover=True,role_verifier=role)
        role.assert_called_once();self.cloud.set_key_status.assert_called_once_with('123','old-id','Inactive')
        self.assertEqual(result['status'],'old-key-inactive')

    def test_failed_role_permission_keeps_old(self):
        ticket=self.prepared()
        with self.assertRaises(RuntimeError):finalize(self.cloud,self.vault,ticket,self.settings,confirmed_cutover=True,role_verifier=MagicMock(side_effect=RuntimeError()))
        self.cloud.set_key_status.assert_not_called()

    def test_scope_change_rejected(self):
        ticket=self.prepared();self.new['safeName']='OtherSafe'
        with self.assertRaises(LifecycleError):finalize(self.cloud,self.vault,ticket,self.settings,confirmed_cutover=True)
        self.cloud.set_key_status.assert_not_called()

    def test_restore_old_is_reversible(self):
        ticket = self.prepared()
        self.cloud.keys.return_value[0]['status'] = 'Inactive'   # as if finalize already retired it
        self.cloud.set_key_status.reset_mock()
        self.assertEqual(restore_old(self.cloud, self.vault, ticket, self.settings),
                         {'status': 'old-key-reactivated'})
        self.cloud.set_key_status.assert_called_once_with('123', 'old-id', 'Active')

    def test_restore_old_is_a_no_op_when_the_old_key_is_still_active(self):
        ticket = self.prepared()
        self.cloud.set_key_status.reset_mock()
        self.assertEqual(restore_old(self.cloud, self.vault, ticket, self.settings),
                         {'status': 'old-key-already-active'})
        self.cloud.set_key_status.assert_not_called()

    def test_restore_old_refuses_a_ticket_the_vault_does_not_bind(self):
        ticket = self.prepared()
        self.old['platformAccountProperties']['TencentSecretId'] = 'other-id'
        self.cloud.set_key_status.reset_mock()
        with self.assertRaises(LifecycleError):
            restore_old(self.cloud, self.vault, ticket, self.settings)
        self.cloud.set_key_status.assert_not_called()

    def test_restore_old_refuses_when_the_bridge_does_not_allow_the_old_key(self):
        ticket = self.prepared()
        self.cloud.keys.return_value[0]['status'] = 'Inactive'
        self.settings['profiles']['readonly']['allowed_secret_ids'] = ['new-id']
        self.cloud.set_key_status.reset_mock()
        with self.assertRaises(LifecycleError):
            restore_old(self.cloud, self.vault, ticket, self.settings)
        self.cloud.set_key_status.assert_not_called()

    def test_cli_prepare_refuses_a_target_that_another_run_holds(self):
        """Two preparations for one target must not interleave.

        The spare-slot check in prepare is check-then-act, so a second run that reads
        the inventory before the first creates a key leaves three keys behind.
        """
        root = Path(__file__).resolve().parents[1]
        script = str(root / 'scripts/pamctl.py')
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as lock_root:
            ticket = Path(folder) / 'rotation.json'
            # Locks are named by target UIN in a shared directory, not beside the ticket.
            lock = Path(lock_root) / '123.lock'
            lock.write_text('{}')
            environment = {
                **os.environ,
                'PSM_TC_PREPARE_LOCK_DIR': lock_root,
                'PVWA_API_URL': 'https://pvwa.invalid/PasswordVault/API',
                'PVWA_TOKEN': 'fake-token',
                'TENCENTCLOUD_SECRET_ID': 'fake-id',
                'TENCENTCLOUD_SECRET_KEY': 'fake-key',
            }
            result = subprocess.run(
                [sys.executable, script, 'prepare', '--old-account', 'old-account', '--target-uin', '123',
                 '--profile', 'readonly', '--ticket', str(ticket), '--apply'],
                capture_output=True, text=True, env=environment, check=False, timeout=60,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('serialised', result.stderr)
            # The holder's lock and the journal reservation must both be untouched.
            self.assertTrue(lock.exists())
            self.assertFalse(ticket.exists())

    def test_cli_write_defaults_to_no_write(self):
        root=Path(__file__).resolve().parents[1]
        result=subprocess.run([sys.executable,str(root/'scripts/pamctl.py'),'prepare','--old-account','old-account',
            '--target-uin','123','--profile','readonly','--ticket','unused.json'],capture_output=True,text=True,check=False)
        self.assertEqual(result.returncode,0);self.assertIn('no-write',result.stdout)


class AdapterTests(unittest.TestCase):
    def test_vault_redirect_is_rejected_without_secret_leak(self):
        transport=MagicMock();transport.request.return_value.status_code=302
        vault=Vault('https://pvwa.test/PasswordVault/api','FAKE-TOKEN',session=transport)
        with self.assertRaises(VaultError) as error:vault.secret('12_34','test')
        self.assertNotIn('FAKE-TOKEN',str(error.exception))
        self.assertFalse(transport.request.call_args.kwargs['allow_redirects'])
        self.assertTrue(transport.request.call_args.kwargs['verify'])

    def test_vault_tls_cannot_be_disabled(self):
        with self.assertRaises(ValueError):Vault('https://pvwa.test/api','token',ca=False)
        with self.assertRaises(ValueError):Vault('http://pvwa.test/api','token')

    def test_cvm_plan_uses_private_ip_and_explicit_guest(self):
        inventory={'instances':[{'id':'ins-1','region':'ap-guangzhou','os':'Ubuntu Linux','private_ips':['10.0.0.1'],'public_ips':['192.0.2.1']}]}
        plan=cvm_plan(inventory,'Safe','UnixPlatform','WindowsPlatform',{'ins-1':'admin'})
        self.assertEqual(plan['accounts'][0]['address'],'10.0.0.1')
        self.assertEqual(plan['accounts'][0]['connection_component'],'PSM-SSH')
        self.assertNotIn('secret',plan['accounts'][0])
        self.assertEqual(len(cvm_plan(inventory,'Safe','Unix','Windows',{})['skipped']),1)

    def test_root_keys_cannot_be_changed(self):
        cloud=Cloud('fake-id','fake-key');cloud.cam=MagicMock();cloud.cam.ListUsers.return_value.Data=[]
        from federation import FederationError
        with self.assertRaises(FederationError):cloud.create_key('123','a'*32)
        cloud.cam.CreateAccessKey.assert_not_called()

    def test_sdk_key_request_is_scoped_to_target(self):
        cloud=Cloud('fake-id','fake-key');cloud.cam=MagicMock()
        user=MagicMock();user.Uin=123;cloud.cam.ListUsers.return_value.Data=[user]
        key=MagicMock();key.AccessKeyId='new-id';key.SecretAccessKey='fake-secret'
        cloud.cam.CreateAccessKey.return_value.AccessKey=key
        self.assertEqual(cloud.create_key('123','a'*32),('new-id','fake-secret'))
        request=cloud.cam.CreateAccessKey.call_args.args[0]
        self.assertEqual(request.TargetUin,123)


if __name__=='__main__':unittest.main()
