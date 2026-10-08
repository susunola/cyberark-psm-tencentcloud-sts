"""International and China console sites must switch as a matching set."""
import unittest
from unittest.mock import MagicMock, patch

from configuration import validate_settings
from federation import (
    SITES,
    FederationError,
    assume_role,
    login_url,
    validate_destination,
    validate_site,
)

CREDS = {'TmpSecretId': 'AKID-TEST', 'TmpSecretKey': 'fake-temp-key', 'Token': 'fake-token'}
INTL_DEST = 'https://console.tencentcloud.com/'
CHINA_DEST = 'https://console.cloud.tencent.com/'


def profile(site=None, destination=INTL_DEST):
    p = {
        'role_arn': 'qcs::cam::uin/123:roleName/ReadOnly',
        'allowed_secret_ids': ['broker-id'],
        'destination': destination,
        'duration_seconds': 300,
        'region': 'ap-guangzhou',
    }
    if site is not None:
        p['site'] = site
    return {'profiles': {'readonly': p}}


class SiteTableTests(unittest.TestCase):
    def test_sites_are_complete_sets(self):
        self.assertEqual(set(SITES), {'intl', 'china'})
        for name, site in SITES.items():
            self.assertEqual(site.name, name)
            for field in ('console_host', 'login_host', 'sts_endpoint', 'cam_endpoint', 'cvm_endpoint'):
                self.assertTrue(getattr(site, field))

    def test_unknown_site_rejected(self):
        for value in ('', 'CN', 'China', None, 1):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_site(value)

    def test_destination_is_bound_to_site_console_host(self):
        self.assertEqual(validate_destination(INTL_DEST, 'intl'), INTL_DEST)
        self.assertEqual(validate_destination(CHINA_DEST, 'china'), CHINA_DEST)
        with self.assertRaises(FederationError):
            validate_destination(CHINA_DEST, 'intl')
        with self.assertRaises(FederationError):
            validate_destination(INTL_DEST, 'china')


class ConfigurationSiteTests(unittest.TestCase):
    def test_omitted_site_defaults_to_international(self):
        validated = validate_settings(profile())
        self.assertNotIn('site', validated['profiles']['readonly'])

    def test_china_site_and_destination_accepted(self):
        validated = validate_settings(profile('china', CHINA_DEST))
        self.assertEqual(validated['profiles']['readonly']['site'], 'china')

    def test_cross_site_destination_rejected(self):
        with self.assertRaises(FederationError):
            validate_settings(profile('china', INTL_DEST))
        with self.assertRaises(FederationError):
            validate_settings(profile('intl', CHINA_DEST))


class LoginUrlSiteTests(unittest.TestCase):
    def test_international_callback_and_canonical_host(self):
        url = login_url(CREDS, INTL_DEST, site='intl', now=1700000000, nonce=67439)
        self.assertTrue(url.startswith('https://www.tencentcloud.com/login/roleAccessCallback?'))
        self.assertIn('s_url=https%3A%2F%2Fconsole.tencentcloud.com%2F', url)

    def test_china_callback_uses_china_hosts(self):
        url = login_url(CREDS, CHINA_DEST, site='china', now=1700000000, nonce=67439)
        self.assertTrue(url.startswith('https://cloud.tencent.com/login/roleAccessCallback?'))
        self.assertIn('s_url=https%3A%2F%2Fconsole.cloud.tencent.com%2F', url)

    def test_china_signature_canonical_uses_china_login_host(self):
        import base64
        import hashlib
        import hmac as hmac_mod
        from urllib.parse import parse_qs, urlsplit

        url = login_url(CREDS, CHINA_DEST, site='china', now=1700000000, nonce=67439)
        canonical = (
            'GETcloud.tencent.com/login/roleAccessCallback?action=roleLogin'
            '&nonce=67439&secretId=AKID-TEST&timestamp=1700000000'
        )
        expected = base64.b64encode(
            hmac_mod.new(b'fake-temp-key', canonical.encode(), hashlib.sha256).digest()
        ).decode()
        self.assertEqual(parse_qs(urlsplit(url).query)['signature'], [expected])


class AssumeRoleSiteTests(unittest.TestCase):
    def test_international_sts_endpoint(self):
        self._assert_endpoint('intl', 'sts.intl.tencentcloudapi.com')

    def test_china_sts_endpoint(self):
        self._assert_endpoint('china', 'sts.tencentcloudapi.com')

    def _assert_endpoint(self, site, expected):
        with patch('tencentcloud.sts.v20180813.sts_client.StsClient') as client:
            instance = client.return_value
            response = MagicMock()
            response.ExpiredTime = 2**40
            response.Credentials.TmpSecretId = 'AKID-T'
            response.Credentials.TmpSecretKey = 'k'
            response.Credentials.Token = 't'
            instance.AssumeRole.return_value = response
            assume_role('id', 'key', 'qcs::cam::uin/1:roleName/R', 'sess', 60, 'ap-guangzhou', site=site)
            self.assertEqual(client.call_args.args[2].httpProfile.endpoint, expected)


if __name__ == '__main__':
    unittest.main()


class RoleVerifierSiteTests(unittest.TestCase):
    def test_finalize_forwards_profile_site_to_role_verifier(self):
        from unittest.mock import MagicMock

        from pam.lifecycle import Ticket, finalize

        ticket = Ticket(
            operation='a' * 32,
            target_uin='123',
            old_account='old-account',
            new_account='new-account',
            old_secret_id='old-id',
            new_secret_id='new-id',
            profile='readonly',
        )
        cloud = MagicMock()
        active_pair = [
            {'id': 'old-id', 'status': 'Active', 'description': ''},
            {'id': 'new-id', 'status': 'Active', 'description': ''},
        ]
        retired_pair = [
            {'id': 'old-id', 'status': 'Inactive', 'description': ''},
            {'id': 'new-id', 'status': 'Active', 'description': ''},
        ]
        cloud.keys.side_effect = [active_pair, active_pair, retired_pair]
        vault = MagicMock()
        vault.account.side_effect = [
            {
                'id': 'old-account',
                'safeName': 'S', 'platformId': 'P', 'userName': 'u', 'address': 'a',
                'platformAccountProperties': {'TencentSecretId': 'old-id', 'TencentRoleProfile': 'readonly'},
            },
            {
                'id': 'new-account',
                'safeName': 'S', 'platformId': 'P', 'userName': 'u', 'address': 'a',
                'platformAccountProperties': {'TencentSecretId': 'new-id', 'TencentRoleProfile': 'readonly'},
            },
        ]
        vault.secret.return_value = 'FAKE-SECRET'
        verifier = MagicMock()
        settings = {
            'profiles': {
                'readonly': {
                    'allowed_secret_ids': ['old-id', 'new-id'],
                    'role_arn': 'qcs::cam::uin/1:roleName/R',
                    'duration_seconds': 60,
                    'region': 'ap-beijing',
                    'site': 'china',
                }
            }
        }
        finalize(cloud, vault, ticket, settings, confirmed_cutover=True, role_verifier=verifier)
        self.assertEqual(verifier.call_args.args[-1], 'china')
