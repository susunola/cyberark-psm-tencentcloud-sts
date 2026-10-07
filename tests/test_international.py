"""International routing must never silently use SDK mainland defaults."""

import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit

from federation import FederationError, assume_role, login_url, validate_destination
from pam.cloud import Cloud


class InternationalRoutingTests(unittest.TestCase):
    def test_callback_and_destination_are_international_only(self):
        url = login_url(
            {"TmpSecretId": "AKID-TEST", "TmpSecretKey": "fake-key", "Token": "fake-token"},
            "https://console.tencentcloud.com/",
            now=1700000000,
            nonce=67439,
        )
        self.assertEqual(urlsplit(url).netloc, "www.tencentcloud.com")
        self.assertEqual(urlsplit(url).path, "/login/roleAccessCallback")
        for destination in (
            "https://console.cloud.tencent.com/",
            "https://console.tencentcloud.com.evil.test/",
            "https://console.tencentcloud.com@evil.test/",
        ):
            with self.subTest(destination=destination), self.assertRaises(FederationError):
                validate_destination(destination)

    def test_assume_role_explicit_international_endpoint(self):
        with patch("tencentcloud.sts.v20180813.sts_client.StsClient") as client:
            client.return_value.AssumeRole.return_value = SimpleNamespace(
                ExpiredTime=int(time.time()) + 300,
                Credentials=SimpleNamespace(
                    TmpSecretId="AKID-TEST", TmpSecretKey="fake-key", Token="fake-token"
                ),
            )
            assume_role(
                "test-id", "fake-key", "qcs::cam::uin/123:roleName/ReadOnly", "psm-test", 300, "ap-singapore"
            )
            self.assertEqual(client.call_args.args[2].httpProfile.endpoint, "sts.intl.tencentcloudapi.com")

    def test_credentials_expiring_inside_the_margin_are_refused_with_the_real_cause(self):
        # The margin lives outside the sanitizing handler, so the diagnosis survives.
        with patch("tencentcloud.sts.v20180813.sts_client.StsClient") as client:
            client.return_value.AssumeRole.return_value = SimpleNamespace(
                ExpiredTime=int(time.time()) + 5,
                Credentials=SimpleNamespace(TmpSecretId="AKID-TEST", TmpSecretKey="fake-key", Token="fake-token"),
            )
            with self.assertRaises(FederationError) as error:
                assume_role(
                    "test-id", "fake-key", "qcs::cam::uin/123:roleName/ReadOnly", "psm-test", 300, "ap-singapore"
                )
        self.assertEqual(str(error.exception), "Temporary credentials expire too soon")

    def test_a_non_integer_expiry_is_refused(self):
        with patch("tencentcloud.sts.v20180813.sts_client.StsClient") as client:
            client.return_value.AssumeRole.return_value = SimpleNamespace(
                ExpiredTime=None,
                Credentials=SimpleNamespace(TmpSecretId="AKID-TEST", TmpSecretKey="fake-key", Token="fake-token"),
            )
            with self.assertRaises(FederationError):
                assume_role(
                    "test-id", "fake-key", "qcs::cam::uin/123:roleName/ReadOnly", "psm-test", 300, "ap-singapore"
                )

    def test_management_cam_and_identity_endpoints(self):
        with (
            patch("tencentcloud.cam.v20190116.cam_client.CamClient") as cam,
            patch("tencentcloud.sts.v20180813.sts_client.StsClient") as sts,
        ):
            sts.return_value.GetCallerIdentity.return_value.UserId = "123"
            cloud = Cloud("test-id", "fake-key")
            self.assertTrue(cloud.verify("test-id", "fake-key", "123"))
            self.assertEqual(cam.call_args.args[2].httpProfile.endpoint, "cam.intl.tencentcloudapi.com")
            self.assertEqual(sts.call_args.args[2].httpProfile.endpoint, "sts.intl.tencentcloudapi.com")

    def test_discovery_explicit_international_endpoint(self):
        with (
            patch("tencentcloud.cam.v20190116.cam_client.CamClient") as cam,
            patch("tencentcloud.cvm.v20170312.cvm_client.CvmClient") as cvm,
        ):
            cam.return_value.ListUsers.return_value.Data = []
            cvm.return_value.DescribeInstances.return_value = SimpleNamespace(InstanceSet=[], TotalCount=0)
            self.assertEqual(
                Cloud("test-id", "fake-key").discover(["ap-singapore"]), {"users": [], "instances": []}
            )
            self.assertEqual(cvm.call_args.args[2].httpProfile.endpoint, "cvm.intl.tencentcloudapi.com")
