"""Adapter-level tests for pam.cloud: target validation, sanitization and exact SDK requests.

Every test fakes the Tencent Cloud SDK through the same patch targets the runtime uses,
so no credentials and no network access are required.
"""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from federation import FederationError
from pam.cloud import Cloud, uin

CAM_CLIENT = "tencentcloud.cam.v20190116.cam_client.CamClient"
CVM_CLIENT = "tencentcloud.cvm.v20170312.cvm_client.CvmClient"
STS_CLIENT = "tencentcloud.sts.v20180813.sts_client.StsClient"
CREDENTIAL = "tencentcloud.common.credential.Credential"


def _cam_cloud(cam, subusers=(123,), region="ap-singapore"):
    """Build a Cloud whose fake CAM client lists exactly the given sub-user UINs."""
    cloud = Cloud("AKID-FAKE-ID", "fake-secret-key", region)
    cam.return_value.ListUsers.return_value.Data = [SimpleNamespace(Uin=value) for value in subusers]
    return cloud


def _instance(instance_id, private_ips=None, public_ips=None, **overrides):
    fields = {
        "InstanceId": instance_id,
        "InstanceName": "web-1",
        "OsName": "Ubuntu Linux",
        "PrivateIpAddresses": private_ips,
        "PublicIpAddresses": public_ips,
        "InstanceState": "RUNNING",
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


class UinTests(unittest.TestCase):
    def test_accepts_int_and_str_within_twenty_digits(self):
        self.assertEqual(uin(123), 123)
        self.assertEqual(uin("123"), 123)
        self.assertEqual(uin("12345678901234567890"), 12345678901234567890)

    def test_rejects_non_numeric_zero_negative_empty_and_overlong_values(self):
        for value in (
            "",
            "0",
            0,
            "-5",
            "-123",
            "abc",
            "12a",
            "123 ",
            " 123",
            "1.5",
            1.5,
            123456789012345678901,
            "123456789012345678901",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                uin(value)


class CloudConstructionTests(unittest.TestCase):
    def test_cam_client_is_bound_to_international_endpoint_and_explicit_region(self):
        with patch(CAM_CLIENT) as cam:
            cloud = Cloud("AKID-FAKE-ID", "fake-secret-key", "ap-guangzhou")
        self.assertEqual(cloud.region, "ap-guangzhou")
        self.assertEqual(cam.call_args.args[1], "ap-guangzhou")
        self.assertIs(cam.call_args.args[0], cloud.credential)
        profile = cam.call_args.args[2]
        self.assertEqual(profile.httpProfile.endpoint, "cam.intl.tencentcloudapi.com")
        self.assertEqual(profile.httpProfile.reqTimeout, 15)

    def test_default_region_is_singapore(self):
        with patch(CAM_CLIENT):
            self.assertEqual(Cloud("AKID-FAKE-ID", "fake-secret-key").region, "ap-singapore")

    def test_credential_is_built_from_the_explicit_pair_only(self):
        with patch(CAM_CLIENT) as cam, patch(CREDENTIAL) as credential:
            cloud = Cloud("AKID-FAKE-ID", "fake-secret-key", "ap-singapore")
            self.assertEqual(credential.call_args.args, ("AKID-FAKE-ID", "fake-secret-key"))
            self.assertIs(cloud.credential, credential.return_value)
            self.assertIs(cam.call_args.args[0], credential.return_value)

    def test_real_credential_keeps_the_explicit_pair_without_a_token(self):
        with patch(CAM_CLIENT):
            credential = Cloud("AKID-FAKE-ID", "fake-secret-key").credential
        self.assertEqual(credential.secret_id, "AKID-FAKE-ID")
        self.assertEqual(credential.secret_key, "fake-secret-key")
        self.assertIsNone(credential.token)


class CloudCallSanitizationTests(unittest.TestCase):
    def test_call_returns_the_wrapped_result(self):
        request = SimpleNamespace(Offset=0)
        self.assertIs(Cloud.call(lambda value: value, request), request)

    def test_call_replaces_every_sdk_failure_without_echoing_details(self):
        def explode(request):
            raise RuntimeError("AuthFailure: secret id AKID-FAKE-ID / fake-secret-key rejected")

        with self.assertRaises(FederationError) as error:
            Cloud.call(explode, SimpleNamespace())
        message = str(error.exception)
        self.assertNotIn("AKID-FAKE-ID", message)
        self.assertNotIn("fake-secret-key", message)
        self.assertNotIn("AuthFailure", message)
        self.assertIn("Cloud operation failed", message)
        self.assertIsNone(error.exception.__cause__)

    def test_call_sanitizes_real_sdk_exceptions(self):
        from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException

        def explode(request):
            raise TencentCloudSDKException(
                "AuthFailure.SecretIdNotFound", "secret id AKID-FAKE-ID is not found"
            )

        with self.assertRaises(FederationError) as error:
            Cloud.call(explode, SimpleNamespace())
        self.assertNotIn("AKID-FAKE-ID", str(error.exception))
        self.assertIsNone(error.exception.__cause__)

    def test_call_does_not_swallow_base_exceptions(self):
        def explode(request):
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            Cloud.call(explode, SimpleNamespace())

    def test_accessor_failures_surface_as_sanitized_federation_errors(self):
        with patch(CAM_CLIENT) as cam:
            cloud = _cam_cloud(cam)
            cam.return_value.ListAccessKeys.side_effect = RuntimeError("AKID-FAKE-ID rejected")
            with self.assertRaises(FederationError) as error:
                cloud.keys(123)
        self.assertNotIn("AKID-FAKE-ID", str(error.exception))


class AccessKeyListTests(unittest.TestCase):
    def test_keys_map_fields_scope_request_and_normalize_description(self):
        operation = "a" * 32
        with patch(CAM_CLIENT) as cam:
            cloud = _cam_cloud(cam)
            cam.return_value.ListAccessKeys.return_value = SimpleNamespace(
                AccessKeys=[
                    SimpleNamespace(
                        AccessKeyId="AKID-OLD", Status="Active", Description="psm-rotation:" + operation
                    ),
                    SimpleNamespace(AccessKeyId="AKID-NEW", Status="Inactive", Description=None),
                ]
            )
            keys = cloud.keys("123")
        self.assertEqual(
            keys,
            [
                {"id": "AKID-OLD", "status": "Active", "description": "psm-rotation:" + operation},
                {"id": "AKID-NEW", "status": "Inactive", "description": ""},
            ],
        )
        request = cam.return_value.ListAccessKeys.call_args.args[0]
        self.assertEqual(type(request).__name__, "ListAccessKeysRequest")
        self.assertEqual(request.TargetUin, 123)

    def test_malformed_or_repeated_key_records_are_refused(self):
        cases = {
            "repeated id": [
                SimpleNamespace(AccessKeyId="AKID-A", Status="Active", Description=None),
                SimpleNamespace(AccessKeyId="AKID-A", Status="Inactive", Description=None),
            ],
            "unknown status": [SimpleNamespace(AccessKeyId="AKID-A", Status="Deleted", Description=None)],
            "missing id": [SimpleNamespace(AccessKeyId=None, Status="Active", Description=None)],
            "non-string id": [SimpleNamespace(AccessKeyId=123, Status="Active", Description=None)],
            "id with illegal characters": [SimpleNamespace(AccessKeyId="AKID/A", Status="Active", Description=None)],
            "non-string description": [SimpleNamespace(AccessKeyId="AKID-A", Status="Active", Description=5)],
            "oversized inventory": [
                SimpleNamespace(AccessKeyId=f"AKID-{index}", Status="Active", Description=None)
                for index in range(11)
            ],
        }
        for name, records in cases.items():
            with patch(CAM_CLIENT) as cam:
                cloud = _cam_cloud(cam)
                cam.return_value.ListAccessKeys.return_value = SimpleNamespace(AccessKeys=records)
                with self.subTest(record=name), self.assertRaises(FederationError):
                    cloud.keys(123)

    def test_missing_access_keys_become_an_empty_list(self):
        with patch(CAM_CLIENT) as cam:
            cloud = _cam_cloud(cam)
            cam.return_value.ListAccessKeys.return_value = SimpleNamespace(AccessKeys=None)
            self.assertEqual(cloud.keys(123), [])

    def test_invalid_target_never_reaches_the_sdk(self):
        with patch(CAM_CLIENT) as cam:
            cloud = _cam_cloud(cam)
            with self.assertRaises(ValueError):
                cloud.keys("0")
            cam.return_value.ListAccessKeys.assert_not_called()


class CreateKeyTests(unittest.TestCase):
    def test_returns_pair_scopes_request_and_asserts_subuser_first(self):
        operation = "b" * 32
        with patch(CAM_CLIENT) as cam:
            cloud = _cam_cloud(cam)
            cam.return_value.CreateAccessKey.return_value.AccessKey = SimpleNamespace(
                AccessKeyId="AKID-NEW", SecretAccessKey="fake-rotated-secret"
            )
            self.assertEqual(cloud.create_key("123", operation), ("AKID-NEW", "fake-rotated-secret"))
        self.assertEqual([call[0] for call in cam.return_value.mock_calls], ["ListUsers", "CreateAccessKey"])
        request = cam.return_value.CreateAccessKey.call_args.args[0]
        self.assertEqual(request.TargetUin, 123)
        self.assertEqual(request.Description, "psm-rotation:" + operation)

    def test_unlisted_target_is_rejected_before_creation(self):
        with patch(CAM_CLIENT) as cam:
            cloud = _cam_cloud(cam, subusers=())
            with self.assertRaises(FederationError):
                cloud.create_key("123", "c" * 32)
            cam.return_value.CreateAccessKey.assert_not_called()

    def test_partial_or_empty_key_pair_is_never_returned(self):
        cases = (
            SimpleNamespace(AccessKey=None),
            SimpleNamespace(AccessKey=SimpleNamespace(AccessKeyId="", SecretAccessKey="fake-secret")),
            SimpleNamespace(AccessKey=SimpleNamespace(AccessKeyId="AKID-NEW", SecretAccessKey="")),
            SimpleNamespace(AccessKey=SimpleNamespace(AccessKeyId="AKID-NEW", SecretAccessKey=None)),
        )
        for response in cases:
            with self.subTest(response=response), patch(CAM_CLIENT) as cam:
                cloud = _cam_cloud(cam)
                cam.return_value.CreateAccessKey.return_value = response
                with self.assertRaises(FederationError) as error:
                    cloud.create_key("123", "d" * 32)
                self.assertIn("reconcile cloud inventory", str(error.exception))


class SetKeyStatusTests(unittest.TestCase):
    def test_valid_transition_sets_every_request_field(self):
        with patch(CAM_CLIENT) as cam:
            cloud = _cam_cloud(cam)
            cloud.set_key_status("123", "AKID-OLD", "Inactive")
        self.assertEqual([call[0] for call in cam.return_value.mock_calls], ["ListUsers", "UpdateAccessKey"])
        request = cam.return_value.UpdateAccessKey.call_args.args[0]
        self.assertEqual(
            (request.TargetUin, request.AccessKeyId, request.Status), (123, "AKID-OLD", "Inactive")
        )

    def test_active_transition_is_accepted(self):
        with patch(CAM_CLIENT) as cam:
            cloud = _cam_cloud(cam)
            cloud.set_key_status(123, "AKID-NEW", "Active")
        self.assertEqual(cam.return_value.UpdateAccessKey.call_args.args[0].Status, "Active")

    def test_invalid_status_or_empty_secret_id_aborts_before_update(self):
        for status, secret_id in (
            ("Deleted", "AKID-OLD"),
            ("active", "AKID-OLD"),
            ("", "AKID-OLD"),
            ("None", "AKID-OLD"),
            ("Inactive", ""),
            ("Inactive", None),
        ):
            with self.subTest(status=status, secret_id=secret_id), patch(CAM_CLIENT) as cam:
                cloud = _cam_cloud(cam)
                with self.assertRaises(ValueError):
                    cloud.set_key_status("123", secret_id, status)
                cam.return_value.UpdateAccessKey.assert_not_called()

    def test_invalid_input_never_reaches_the_cloud(self):
        with patch(CAM_CLIENT) as cam:
            cloud = _cam_cloud(cam, subusers=())
            with self.assertRaises(ValueError):
                cloud.set_key_status("123", "", "Deleted")
            cam.return_value.ListUsers.assert_not_called()
            cam.return_value.UpdateAccessKey.assert_not_called()


class AssertSubuserTests(unittest.TestCase):
    def test_listed_uin_passes_regardless_of_int_or_str(self):
        with patch(CAM_CLIENT) as cam:
            cloud = _cam_cloud(cam, subusers=("123",))
            self.assertIsNone(cloud.assert_subuser(123))
            self.assertIsNone(cloud.assert_subuser("123"))

    def test_unlisted_and_prefix_uin_are_rejected(self):
        with patch(CAM_CLIENT) as cam:
            cloud = _cam_cloud(cam, subusers=(1234, "123456", 999))
            with self.assertRaises(FederationError) as error:
                cloud.assert_subuser(123)
        self.assertIn("sub-user", str(error.exception))

    def test_missing_user_list_is_refused(self):
        with patch(CAM_CLIENT) as cam:
            cloud = _cam_cloud(cam)
            cam.return_value.ListUsers.return_value = SimpleNamespace(Data=None)
            with self.assertRaises(FederationError):
                cloud.assert_subuser(123)


class VerifyIdentityTests(unittest.TestCase):
    def test_matching_identity_uses_international_sts_endpoint(self):
        with (
            patch(CAM_CLIENT),
            patch(STS_CLIENT) as sts,
            patch(CREDENTIAL) as credential,
        ):
            sts.return_value.GetCallerIdentity.return_value.UserId = "123"
            cloud = Cloud("AKID-FAKE-ID", "fake-secret-key", "ap-singapore")
            self.assertTrue(cloud.verify("AKID-ROTATED-ID", "rotated-fake-key", 123))
        self.assertEqual(
            [call.args for call in credential.call_args_list],
            [("AKID-FAKE-ID", "fake-secret-key"), ("AKID-ROTATED-ID", "rotated-fake-key")],
        )
        self.assertEqual(sts.call_args.args[1], "ap-singapore")
        self.assertEqual(sts.call_args.args[2].httpProfile.endpoint, "sts.intl.tencentcloudapi.com")
        self.assertEqual(sts.call_args.args[2].httpProfile.reqTimeout, 15)

    def test_identity_mismatch_is_rejected_without_echoing_the_secret(self):
        with patch(CAM_CLIENT), patch(STS_CLIENT) as sts:
            sts.return_value.GetCallerIdentity.return_value.UserId = "999"
            cloud = Cloud("AKID-FAKE-ID", "fake-secret-key")
            with self.assertRaises(FederationError) as error:
                cloud.verify("AKID-ROTATED-ID", "rotated-fake-key", 123)
        self.assertIn("different identity", str(error.exception))
        self.assertNotIn("rotated-fake-key", str(error.exception))

    def test_sdk_identity_failure_is_sanitized(self):
        with patch(CAM_CLIENT), patch(STS_CLIENT) as sts:
            sts.return_value.GetCallerIdentity.side_effect = RuntimeError("AKID-ROTATED-ID rejected")
            cloud = Cloud("AKID-FAKE-ID", "fake-secret-key")
            with self.assertRaises(FederationError) as error:
                cloud.verify("AKID-ROTATED-ID", "rotated-fake-key", 123)
        self.assertNotIn("AKID-ROTATED-ID", str(error.exception))


class DiscoverTests(unittest.TestCase):
    def test_users_and_instances_are_mapped_exactly(self):
        with patch(CAM_CLIENT) as cam, patch(CVM_CLIENT) as cvm:
            cam.return_value.ListUsers.return_value.Data = [
                SimpleNamespace(Uin=123, Name="broker", ConsoleLogin=0)
            ]
            cam.return_value.ListAccessKeys.return_value = SimpleNamespace(
                AccessKeys=[SimpleNamespace(AccessKeyId="AKID-OLD", Status="Active", Description="")]
            )
            cvm.return_value.DescribeInstances.return_value = SimpleNamespace(
                InstanceSet=[_instance("ins-1", ["10.0.0.1"], ["192.0.2.1"])], TotalCount=1
            )
            inventory = Cloud("AKID-FAKE-ID", "fake-secret-key").discover(["ap-singapore"])
        self.assertEqual(
            inventory,
            {
                "users": [
                    {
                        "uin": "123",
                        "name": "broker",
                        "console_login": 0,
                        "keys": [{"id": "AKID-OLD", "status": "Active", "description": ""}],
                    }
                ],
                "instances": [
                    {
                        "id": "ins-1",
                        "region": "ap-singapore",
                        "name": "web-1",
                        "os": "Ubuntu Linux",
                        "private_ips": ["10.0.0.1"],
                        "public_ips": ["192.0.2.1"],
                        "state": "RUNNING",
                    }
                ],
            },
        )
        self.assertEqual(cvm.call_args.args[1], "ap-singapore")
        self.assertEqual(cvm.call_args.args[2].httpProfile.endpoint, "cvm.intl.tencentcloudapi.com")
        keys_request = cam.return_value.ListAccessKeys.call_args.args[0]
        self.assertEqual(keys_request.TargetUin, 123)

    def test_none_ip_lists_become_empty_lists(self):
        with patch(CAM_CLIENT) as cam, patch(CVM_CLIENT) as cvm:
            cam.return_value.ListUsers.return_value.Data = []
            cvm.return_value.DescribeInstances.return_value = SimpleNamespace(
                InstanceSet=[_instance("ins-2")], TotalCount=1
            )
            instance = Cloud("AKID-FAKE-ID", "fake-secret-key").discover(["ap-singapore"])["instances"][0]
        self.assertEqual(instance["private_ips"], [])
        self.assertEqual(instance["public_ips"], [])

    def test_vendor_text_cannot_smuggle_control_characters_into_the_inventory(self):
        cases = {
            "control character in a user name": SimpleNamespace(Uin=123, Name="broker\u001b[31m", ConsoleLogin=0),
            "oversized instance name": SimpleNamespace(Uin=123, Name="x" * 1025, ConsoleLogin=0),
            "non-numeric console flag": SimpleNamespace(Uin=123, Name="broker", ConsoleLogin="true"),
        }
        for name, user in cases.items():
            with patch(CAM_CLIENT) as cam, patch(CVM_CLIENT) as cvm:
                cam.return_value.ListUsers.return_value.Data = [user]
                cam.return_value.ListAccessKeys.return_value = SimpleNamespace(AccessKeys=None)
                cvm.return_value.DescribeInstances.return_value = SimpleNamespace(InstanceSet=[], TotalCount=0)
                with self.subTest(record=name), self.assertRaises(FederationError):
                    Cloud("AKID-FAKE-ID", "fake-secret-key").discover(["ap-singapore"])

    def test_an_address_that_is_not_an_address_literal_is_rejected(self):
        for addresses in ([None, "10.0.0.1"], ["10.0.0.1\u001b[0m"], ["10.0.0.1; rm -rf /"]):
            with patch(CAM_CLIENT) as cam, patch(CVM_CLIENT) as cvm:
                cam.return_value.ListUsers.return_value.Data = []
                instance = _instance("ins-1", addresses, [])
                cvm.return_value.DescribeInstances.return_value = SimpleNamespace(
                    InstanceSet=[instance], TotalCount=1
                )
                with self.subTest(addresses=addresses), self.assertRaises(FederationError):
                    Cloud("AKID-FAKE-ID", "fake-secret-key").discover(["ap-singapore"])

    def test_invalid_region_is_rejected_without_building_a_cvm_client(self):
        # Suffix forms such as ap-singapore-1 are valid syntax and covered separately.
        for region in ("ap_singapore", "AP-Singapore", "", "ap", "a-guangzhou"):
            with self.subTest(region=region), patch(CAM_CLIENT) as cam, patch(CVM_CLIENT) as cvm:
                cam.return_value.ListUsers.return_value.Data = []
                with self.assertRaises(ValueError):
                    Cloud("AKID-FAKE-ID", "fake-secret-key").discover([region])
                cvm.assert_not_called()

    def test_pagination_requests_successive_offsets_until_a_page_is_short(self):
        pages = [
            SimpleNamespace(InstanceSet=[_instance("ins-1"), _instance("ins-2")], TotalCount=3),
            SimpleNamespace(InstanceSet=[_instance("ins-3")], TotalCount=3),
        ]
        with patch(CAM_CLIENT) as cam, patch(CVM_CLIENT) as cvm:
            cam.return_value.ListUsers.return_value.Data = []
            cvm.return_value.DescribeInstances.side_effect = pages
            inventory = Cloud("AKID-FAKE-ID", "fake-secret-key").discover(["ap-singapore"])
        calls = cvm.return_value.DescribeInstances.call_args_list
        self.assertEqual(len(calls), 2)
        self.assertEqual([call.args[0].Offset for call in calls], [0, 2])
        self.assertEqual({call.args[0].Limit for call in calls}, {100})
        self.assertEqual([item["id"] for item in inventory["instances"]], ["ins-1", "ins-2", "ins-3"])

    def test_empty_page_before_total_count_is_incomplete_inventory(self):
        with patch(CAM_CLIENT) as cam, patch(CVM_CLIENT) as cvm:
            cam.return_value.ListUsers.return_value.Data = []
            cvm.return_value.DescribeInstances.return_value = SimpleNamespace(InstanceSet=[], TotalCount=5)
            with self.assertRaises(FederationError) as error:
                Cloud("AKID-FAKE-ID", "fake-secret-key").discover(["ap-singapore"])
        self.assertIn("Incomplete inventory page", str(error.exception))

    def test_each_region_is_queried_separately_and_tagged(self):
        with patch(CAM_CLIENT) as cam, patch(CVM_CLIENT) as cvm:
            cam.return_value.ListUsers.return_value.Data = []
            cvm.return_value.DescribeInstances.return_value = SimpleNamespace(
                InstanceSet=[_instance("ins-1")], TotalCount=1
            )
            inventory = Cloud("AKID-FAKE-ID", "fake-secret-key").discover(["ap-singapore", "ap-guangzhou"])
        self.assertEqual([call.args[1] for call in cvm.call_args_list], ["ap-singapore", "ap-guangzhou"])
        self.assertEqual(
            [item["region"] for item in inventory["instances"]], ["ap-singapore", "ap-guangzhou"]
        )


if __name__ == "__main__":
    unittest.main()
