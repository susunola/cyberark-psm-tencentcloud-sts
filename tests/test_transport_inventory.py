"""Reject partial/ambiguous inventory and invalid transport configuration before use."""

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from federation import FederationError, validate_region
from pam.cloud import Cloud
from pam.vault import Vault


def record(**fields: object) -> SimpleNamespace:
    """Build a fake SDK response record."""
    return SimpleNamespace(**fields)


def instance(identifier):
    return record(
        InstanceId=identifier,
        InstanceName="guest",
        OsName="Linux",
        PrivateIpAddresses=["10.0.0.1"],
        PublicIpAddresses=[],
        InstanceState="RUNNING",
    )


class InventoryTests(unittest.TestCase):
    def run_pages(self, pages, regions=None):
        with (
            patch("tencentcloud.cam.v20190116.cam_client.CamClient") as cam,
            patch("tencentcloud.cvm.v20170312.cvm_client.CvmClient") as cvm,
        ):
            cam.return_value.ListUsers.return_value.Data = []
            cvm.return_value.DescribeInstances.side_effect = pages
            result = Cloud("fake-id", "fake-key").discover(regions or ["ap-singapore"])
            return result, cvm.return_value.DescribeInstances.call_args_list

    def test_distinct_pages_advance_offset(self):
        result, calls = self.run_pages(
            [
                record(TotalCount=2, InstanceSet=[instance("ins-a")]),
                record(TotalCount=2, InstanceSet=[instance("ins-b")]),
            ]
        )
        self.assertEqual([i["id"] for i in result["instances"]], ["ins-a", "ins-b"])
        self.assertEqual([c.args[0].Offset for c in calls], [0, 1])

    def test_repeated_page_never_returns_duplicate_inventory(self):
        with self.assertRaises(FederationError):
            self.run_pages([record(TotalCount=2, InstanceSet=[instance("ins-a")])] * 2)

    def test_incomplete_changing_and_malformed_pages_fail(self):
        samples = [
            [record(TotalCount=1, InstanceSet=[])],
            [record(TotalCount=True, InstanceSet=[])],
            [record(TotalCount=10001, InstanceSet=[])],
            [record(TotalCount=0, InstanceSet=[instance("ins-a")])],
            [
                record(TotalCount=2, InstanceSet=[instance("ins-a")]),
                record(TotalCount=3, InstanceSet=[instance("ins-b")]),
            ],
        ]
        for pages in samples:
            with self.subTest(pages=pages), self.assertRaises(FederationError):
                self.run_pages(pages)

    def test_all_regions_checked_before_any_remote_call(self):
        with patch("tencentcloud.cam.v20190116.cam_client.CamClient") as cam:
            cloud = Cloud("fake-id", "fake-key")
            for regions in ([], ["ap-singapore", "bad"], ["ap-singapore"] * 2, ["ap-singapore"] * 21):
                with self.subTest(regions=regions), self.assertRaises(ValueError):
                    cloud.discover(regions)
            cam.return_value.ListUsers.assert_not_called()

    def test_invalid_mutations_and_identity_targets_make_no_remote_calls(self):
        with (
            patch("tencentcloud.cam.v20190116.cam_client.CamClient") as cam,
            patch("tencentcloud.sts.v20180813.sts_client.StsClient") as sts,
        ):
            cloud = Cloud("fake-id", "fake-key")
            for action in (
                lambda: cloud.create_key("123", "invalid"),
                lambda: cloud.create_key("bad", "a" * 32),
                lambda: cloud.set_key_status("123", "bad/id", "Active"),
                lambda: cloud.verify("fake-id", "fake-key", "bad"),
            ):
                with self.assertRaises(ValueError):
                    action()
            cam.return_value.ListUsers.assert_not_called()
            cam.return_value.CreateAccessKey.assert_not_called()
            cam.return_value.UpdateAccessKey.assert_not_called()
            sts.assert_not_called()

    def test_region_suffix_syntax_is_supported_without_claiming_availability(self):
        self.assertEqual(validate_region("ap-shanghai-fsi"), "ap-shanghai-fsi")
        for value in (None, "ap-singapore/evil", "ap-Singapore", "ap-singapore\n"):
            with self.assertRaises(ValueError):
                validate_region(value)

    def test_duplicate_subuser_inventory_blocks_mutation(self):
        with patch("tencentcloud.cam.v20190116.cam_client.CamClient") as cam:
            cam.return_value.ListUsers.return_value.Data = [record(Uin=123), record(Uin=123)]
            cloud = Cloud("fake-id", "fake-key")
            with self.assertRaises(FederationError):
                cloud.create_key("123", "a" * 32)
            cam.return_value.CreateAccessKey.assert_not_called()


class TransportTests(unittest.TestCase):
    def test_tls_cannot_be_disabled_by_false_equivalent_values(self):
        for ca in (False, None, 0, 1, "", [], {}):
            with self.subTest(ca=ca), self.assertRaises(ValueError):
                Vault("https://pvwa.test/PasswordVault/API", "fake-token", ca=ca)

    def test_invalid_url_and_header_rejected_without_secret_in_error(self):
        for url in (
            "https://pvwa.test:bad/PasswordVault/API",
            "https://pvwa.test/API",
            "https://pvwa.test/PasswordVault/API\n",
            "https://user:secret@pvwa.test/PasswordVault/API",
            "https://pvwa.test/PasswordVault/API?token=secret",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError) as caught:
                Vault(url, "fake-token")
            self.assertNotIn("secret", str(caught.exception))
        for token in (None, 42, "secret\r\nX-Test: value", "secret\x7f"):
            with self.assertRaises(ValueError):
                Vault("https://pvwa.test/PasswordVault/API", token)

    def test_invalid_routes_do_not_call_transport(self):
        session = MagicMock()
        vault = Vault("https://pvwa.test/PasswordVault/API", "fake-token", session=session)
        for path in ("//evil.test", "https://evil.test", "/Accounts#fragment", "/Accounts\n", "/\\evil"):
            with self.assertRaises(ValueError):
                vault.request("GET", path)
        session.request.assert_not_called()
