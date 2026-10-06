import unittest

from psm_tc_bridge.config import ConfigError, validate_settings


class ConfigTests(unittest.TestCase):
    def profile(self, **overrides):
        raw = dict(
            role_arn='qcs::cam::uin/123:roleName/ReadOnly',
            allowed_secret_ids=['broker-id'],
            destination='https://console.cloud.tencent.com/',
            duration_seconds=300,
            region='ap-guangzhou',
        )
        raw.update(overrides)
        return raw

    def test_accepts_locked_profile(self):
        settings = validate_settings({'profiles': {'readonly': self.profile(
            external_id='psm-bridge',
            session_policy={'version': '2.0', 'statement': [{'effect': 'allow', 'action': ['cvm:Describe*'], 'resource': ['*']}]},
        )}})
        self.assertEqual(settings['submit_method'], 'post')
        self.assertEqual(settings['profiles']['readonly']['external_id'], 'psm-bridge')
        self.assertNotIn('principal', settings['profiles']['readonly']['session_policy'])

    def test_rejects_placeholders_unknown_keys_and_open_roles(self):
        with self.assertRaises(ConfigError):
            validate_settings({'profiles': {'readonly': self.profile(allowed_secret_ids=['REPLACE_WITH_BROKER_CAM_SECRET_ID'])}})
        with self.assertRaises(ConfigError):
            validate_settings({'profiles': {'readonly': self.profile()}, 'bind': '0.0.0.0'})
        with self.assertRaises(ConfigError):
            validate_settings({'profiles': {'readonly': self.profile(role_arn='qcs::cam::uin/123:role/tencentcloudServiceRoleName/x')}})
        with self.assertRaises(ConfigError):
            validate_settings({'profiles': {'readonly': self.profile(destination='https://evil.test/')}})
        with self.assertRaises(ConfigError):
            validate_settings({'profiles': {'readonly': self.profile(duration_seconds=301)}})
        with self.assertRaises(ConfigError):
            validate_settings({'profiles': {'readonly': self.profile(session_policy={'principal': {'qcs': '*'}}})})
        with self.assertRaises(ConfigError):
            validate_settings({'profiles': {'readonly': self.profile(sts_endpoint='169.254.169.254')}})


if __name__ == '__main__':
    unittest.main()
