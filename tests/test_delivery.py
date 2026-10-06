import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock
from pam.audit import summarize, event
from pam.delivery import export_records, onboard_batch, preflight
from pam.vault import Vault


class DeliveryTests(unittest.TestCase):
    def account(self, name):
        return {'name':name,'address':'10.0.0.1','userName':'admin','platformId':'UnixSSH','safeName':'Guests','secretType':'password','secret':'FAKE-SECRET'}

    def test_export_follows_native_offsets_and_never_server_urls(self):
        vault=MagicMock();vault.list_operations.side_effect=[{'value':[{'id':'1'},{'id':'2'}],'nextLink':'https://untrusted.invalid/'}, {'value':[{'id':'3'}]}]
        self.assertEqual(len(list(export_records(vault,'Accounts',limit=2))),3)
        self.assertEqual(vault.list_operations.call_args_list[1].args,('Accounts',2,2))

    def test_repeated_pages_do_not_claim_complete_export(self):
        vault=MagicMock();vault.list_operations.return_value={'Recordings':[{'id':'1'}],'Total':2}
        with self.assertRaises(ValueError):list(export_records(vault,'Recordings',limit=1))

    def test_page_cap_and_incomplete_empty_page_are_errors(self):
        vault=MagicMock();vault.list_operations.return_value={'LiveSessions':[{'id':'1'}],'Total':2}
        with self.assertRaises(ValueError):list(export_records(vault,'LiveSessions',limit=1,max_pages=1))
        vault.list_operations.return_value={'LiveSessions':[],'Total':2}
        with self.assertRaises(ValueError):list(export_records(vault,'LiveSessions'))

    def test_batch_validates_every_account_before_any_lookup_or_write(self):
        vault=MagicMock();bad=self.account('second');bad['secret']={'invalid':'type'}
        with tempfile.TemporaryFile(mode='w+',encoding='utf-8') as journal:
            with self.assertRaises(ValueError):onboard_batch([self.account('first'),bad],'Guests','UnixSSH',vault,journal)
        vault.create.assert_not_called();vault.find_accounts_by_name.assert_not_called()

    def test_preexisting_batch_account_stops_all_creations(self):
        vault=MagicMock();vault.find_accounts_by_name.side_effect=[[],[{'id':'existing'}]]
        with tempfile.TemporaryFile(mode='w+',encoding='utf-8') as journal:
            with self.assertRaises(ValueError):onboard_batch([self.account('first'),self.account('second')],'Guests','UnixSSH',vault,journal)
        vault.create.assert_not_called()

    def test_uncertain_batch_write_retains_attempt_without_credentials(self):
        vault=MagicMock();vault.find_accounts_by_name.return_value=[];vault.create.side_effect=['1_2',TimeoutError('FAKE-SECRET')]
        with tempfile.TemporaryFile(mode='w+',encoding='utf-8') as journal:
            with self.assertRaises(TimeoutError):onboard_batch([self.account('first'),self.account('second')],'Guests','UnixSSH',vault,journal)
            journal.seek(0);raw=journal.read();records=[json.loads(line) for line in raw.splitlines()]
        self.assertNotIn('FAKE-SECRET',raw)
        self.assertEqual(records[-1]['event'],'create_attempt')
        self.assertEqual(records[-1]['index'],1)
        self.assertFalse(any(r['event']=='batch_completed' for r in records))
        self.assertEqual(vault.create.call_count,2)

    def test_successful_batch_has_completion_marker(self):
        vault=MagicMock();vault.find_accounts_by_name.return_value=[];vault.create.return_value='1_2'
        with tempfile.TemporaryFile(mode='w+',encoding='utf-8') as journal:
            result=onboard_batch([self.account('first')],'Guests','UnixSSH',vault,journal)
            journal.seek(0);rows=[json.loads(line) for line in journal]
        self.assertEqual(result['account_ids'],['1_2']);self.assertEqual(rows[-1]['event'],'batch_completed')

    def test_preflight_does_not_retrieve_secrets_or_assert_native_acceptance(self):
        vault=MagicMock();vault.account.return_value=self.account('first');vault.request.return_value={}
        result=preflight(vault,{'profiles':{}},'1_2','Guests','UnixSSH','PSM-SSH')
        self.assertTrue(result['scope_binding_ready'])
        self.assertIn('approval/recording',result['not_verified'])
        vault.secret.assert_not_called();self.assertTrue(all(c.args[0]=='GET' for c in vault.request.call_args_list))

    def test_audit_aggregates_deduplicate_and_drop_sensitive_fields(self):
        request_id='a'*32
        record={'event':'http_result','request_id':request_id,'status':200,'secret':'FAKE-SECRET','url':'https://private.invalid'}
        rows=[record,record,{'event':'role_session_issued','request_id':request_id,'profile':'readonly','proxy_identity':'private-user'}, {'unexpected':'FAKE-SECRET'}]
        result=summarize(io.StringIO('\n'.join(json.dumps(r) for r in rows)))
        self.assertEqual(result['unique_http_events'],1);self.assertEqual(result['unique_role_events'],1)
        self.assertNotIn('FAKE-SECRET',str(result));self.assertNotIn('private-user',str(result));self.assertNotIn('private.invalid',str(result))

    def test_audit_bounds_do_not_return_incomplete_success(self):
        with self.assertRaises(ValueError):summarize(io.StringIO('x'*8193))
        with self.assertRaises(ValueError):summarize(io.StringIO('{}\n{}\n'),max_lines=1)
        self.assertIn('timestamp',json.loads(event({'event':'http_result'})))

    def test_request_window_and_ticket_schema(self):
        vault=Vault('https://pvwa.invalid/API','FAKE-TOKEN');vault.request=MagicMock()
        vault.access_request('1_2','Maintenance','PSM-SSH',ticket_id='CHG1',ticket_system='ServiceNow',from_date=100,to_date=200)
        payload=vault.request.call_args.args[2]
        self.assertEqual(payload['TicketID'],'CHG1');self.assertEqual(payload['FromDate'],100)
        vault.request.reset_mock()
        for options in ({'from_date':200,'to_date':100},{'from_date':True,'to_date':200},{'ticket_id':'CHG1'}):
            with self.assertRaises(ValueError):vault.access_request('1_2','Maintenance','PSM-SSH',**options)
        vault.request.assert_not_called()

    def test_request_and_session_detail_endpoints(self):
        vault=Vault('https://pvwa.invalid/API','FAKE-TOKEN');vault.request=MagicMock()
        vault.session_details('session-123','activities');vault.request.assert_called_with('GET','/LiveSessions/session-123/activities')
        vault.request_details('request-123',True);vault.request.assert_called_with('GET','/IncomingRequests/request-123')
        vault.cancel_request('request-123');vault.request.assert_called_with('DELETE','/MyRequests/request-123')

    def test_installed_runtime_layout_imports_without_administrative_modules(self):
        root=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as folder:
            destination=Path(folder);(destination/'pam').mkdir()
            for name in ('app.py','federation.py','configuration.py','security.py','runtime.py','version.py'):
                shutil.copyfile(root/name,destination/name)
            for name in ('__init__.py','audit.py'):shutil.copyfile(root/'pam'/name,destination/'pam'/name)
            result=subprocess.run([sys.executable,'-c','import app; import runtime'],cwd=destination,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_new_mutations_default_no_write(self):
        script=Path(__file__).resolve().parents[1]/'scripts/pamctl.py'
        for args in [['cancel-request','--id','request-123'],['onboard-batch','--safe','Guests','--platform','UnixSSH','--journal','absent.jsonl']]:
            result=subprocess.run([sys.executable,str(script),*args],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr);self.assertIn('no-write',result.stdout)


if __name__=='__main__':unittest.main()
