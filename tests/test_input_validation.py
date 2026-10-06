import copy
import tempfile
import unittest
from unittest.mock import MagicMock
from pam.lifecycle import Ticket
from pam.maintenance import validate_jobs, run
from pam.onboarding import validate_account


class InputValidationTests(unittest.TestCase):
    def account(self):
        return {'name':'guest','address':'10.0.0.1','userName':'admin','platformId':'UnixSSH',
                'safeName':'Guests','secretType':'password','secret':'FAKE-SECRET','connection_component':'PSM-SSH'}

    def job(self):
        return {'id':'caller','action':'prepare-key','account':'1_2','target_uin':'123','profile':'readonly','safe':'Cloud','platform':'TencentSTS'}

    def test_account_validation_preserves_input_and_strips_proposal_metadata(self):
        payload=self.account()
        validated=validate_account(payload,'Guests','UnixSSH')
        self.assertNotIn('connection_component',validated)
        self.assertIn('connection_component',payload)

    def test_invalid_metadata_secret_scope_or_flags_rejected(self):
        for field,value in [('address',''),('secret',{'nested':'FAKE-SECRET'}),('safeName','OtherSafe'),
                            ('secretManagement',None),('secretManagement',{'automaticManagementEnabled':'false'})]:
            payload=self.account();payload[field]=value
            with self.assertRaises(ValueError):validate_account(payload,'Guests','UnixSSH')

    def test_cam_binding_requires_explicit_staged_management(self):
        payload=self.account();payload['platformAccountProperties']={'TencentSecretId':'caller-id','TencentRoleProfile':'readonly'}
        with self.assertRaises(ValueError):validate_account(payload,'Guests','UnixSSH')
        payload['secretManagement']={'automaticManagementEnabled':False}
        self.assertEqual(validate_account(payload,'Guests','UnixSSH')['platformAccountProperties']['TencentSecretId'],'caller-id')
        del payload['platformAccountProperties']['TencentRoleProfile']
        with self.assertRaises(ValueError):validate_account(payload,'Guests','UnixSSH')

    def test_numeric_target_aliases_and_case_insensitive_job_ids_rejected(self):
        first=self.job();second=copy.deepcopy(first);second.update(id='other',target_uin='00123')
        with self.assertRaises(ValueError):validate_jobs({'jobs':[first,second]})
        second.update(id='CALLER',target_uin='456')
        with self.assertRaises(ValueError):validate_jobs({'jobs':[first,second]})
        first['id']='CON'
        with self.assertRaises(ValueError):validate_jobs({'jobs':[first]})

    def test_all_jobs_validated_before_any_remote_operation(self):
        first=self.job();second=copy.deepcopy(first);second.update(id='other',target_uin='invalid')
        cloud,vault=MagicMock(),MagicMock()
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):run({'jobs':[first,second]}, {'profiles':{}}, folder, cloud, vault)
        vault.account.assert_not_called();cloud.create_key.assert_not_called()

    def test_ticket_validated_and_uin_canonicalized(self):
        args={'operation':'a'*32,'target_uin':'00123','old_account':'1_2','new_account':'1_3',
              'old_secret_id':'old-id','new_secret_id':'new-id','profile':'readonly'}
        self.assertEqual(Ticket(**args).target_uin,'123')
        for field,value in [('operation','bad'),('old_account','../Accounts'),('new_secret_id','old-id'),('profile','bad profile')]:
            changed={**args,field:value}
            with self.assertRaises(ValueError):Ticket(**changed)


if __name__=='__main__':unittest.main()
