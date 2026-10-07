"""Refusal paths that the other suites do not drive, one branch each.

The tests here reach the vendor-text and inventory-bound branches of pam.cloud, the
source-binding re-check in pam.lifecycle.prepare and the per-identity token bound of
both token stores. The Tencent Cloud SDK is faked through the same patch targets the
runtime uses, so no credentials and no network access are required, and every
assertion pins the operator-visible refusal text rather than only that something raised.
"""

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from federation import FederationError
from pam.cloud import MAX_VENDOR_TEXT, Cloud, display_hosts, display_text
from pam.lifecycle import LifecycleError, prepare
from security import RedisTokenStore, TokenStore

CAM_CLIENT = 'tencentcloud.cam.v20190116.cam_client.CamClient'
CVM_CLIENT = 'tencentcloud.cvm.v20170312.cvm_client.CvmClient'
VENDOR_TEXT_REFUSAL = 'Unexpected vendor text in inventory'
VENDOR_LIST_REFUSAL = 'Unexpected vendor address list in inventory'
PAGE_BOUND_REFUSAL = 'Inventory exceeds page bound'
RECORD_BOUND_REFUSAL = 'Inventory exceeds total record bound'
BINDING_REFUSAL = 'Account/profile binding mismatch'
IDENTITY_CAPACITY_REFUSAL = 'Invalid per-identity token capacity'


def instance(identifier):
    """Build a fake CVM instance record, as tests/test_cloud_adapter.py does."""
    return SimpleNamespace(InstanceId=identifier, InstanceName='guest', OsName='Linux',
        PrivateIpAddresses=['10.0.0.1'], PublicIpAddresses=[], InstanceState='RUNNING')


class VendorTextTests(unittest.TestCase):
    """display_text/display_hosts decide what a vendor string may look like in output."""

    def test_a_vendor_value_that_is_not_text_renders_as_empty(self):
        for value in (None, 123, 1.5, True, b'broker', ['broker'], {'name': 'broker'}):
            with self.subTest(value=value):
                self.assertEqual(display_text(value), '')

    def test_text_at_the_bound_is_kept_and_one_character_more_is_refused(self):
        self.assertEqual(display_text('x' * MAX_VENDOR_TEXT), 'x' * MAX_VENDOR_TEXT)
        for value in ('x' * (MAX_VENDOR_TEXT + 1), '\u001b[31mbroker', 'line\nbreak', 'null\x00byte'):
            with self.subTest(value=repr(value[:8])), self.assertRaises(FederationError) as error:
                display_text(value)
            self.assertEqual(str(error.exception), VENDOR_TEXT_REFUSAL)

    def test_an_absent_address_list_is_empty_and_a_non_list_is_refused(self):
        self.assertEqual(display_hosts(None), [])
        for value in ('10.0.0.1', 123, b'10.0.0.1', {'10.0.0.1'}, ('10.0.0.1',)):
            with self.subTest(value=repr(value)), self.assertRaises(FederationError) as error:
                display_hosts(value)
            self.assertEqual(str(error.exception), VENDOR_LIST_REFUSAL)

    def test_an_address_list_longer_than_the_text_bound_is_refused(self):
        self.assertEqual(display_hosts(['10.0.0.1'] * MAX_VENDOR_TEXT), ['10.0.0.1'] * MAX_VENDOR_TEXT)
        with self.assertRaises(FederationError) as error:
            display_hosts(['10.0.0.1'] * (MAX_VENDOR_TEXT + 1))
        self.assertEqual(str(error.exception), VENDOR_LIST_REFUSAL)

    def test_a_non_string_address_inside_a_valid_list_is_refused(self):
        # The vendor field is only required to be an address literal, not a routable IP.
        for item in (None, 123, '', '10.0.0.1; rm -rf /', '1' * 65):
            with self.subTest(item=item), self.assertRaises(FederationError) as error:
                display_hosts(['10.0.0.1', item])
            self.assertEqual(str(error.exception), 'Unexpected vendor address in inventory')


class InventoryBoundTests(unittest.TestCase):
    """discover() must terminate on a vendor page stream, not trust it."""

    def discover(self, cam, cvm, pages, regions=('ap-singapore',)):
        cam.return_value.ListUsers.return_value.Data = []
        cvm.return_value.DescribeInstances.side_effect = pages
        return Cloud('AKID-FAKE-ID', 'fake-secret-key').discover(list(regions))

    def test_a_none_instance_set_with_a_zero_total_is_an_empty_inventory(self):
        with patch(CAM_CLIENT) as cam, patch(CVM_CLIENT) as cvm:
            inventory = self.discover(cam, cvm, [SimpleNamespace(InstanceSet=None, TotalCount=0)])
            cvm.return_value.DescribeInstances.assert_called_once()
        self.assertEqual(inventory, {'users': [], 'instances': []})

    def test_pages_that_never_reach_the_total_exceed_the_page_bound(self):
        # 100 pages of one instance against a total of 101: the offset never lands on the
        # total, so the loop exhausts rather than finishing.
        pages = [SimpleNamespace(InstanceSet=[instance(f'ins-{index}')], TotalCount=101) for index in range(100)]
        with patch(CAM_CLIENT) as cam, patch(CVM_CLIENT) as cvm:
            with self.assertRaises(FederationError) as error:
                self.discover(cam, cvm, pages)
            calls = cvm.return_value.DescribeInstances.call_args_list
        self.assertEqual(str(error.exception), PAGE_BOUND_REFUSAL)
        self.assertEqual([call.args[0].Offset for call in calls], list(range(100)))
        self.assertEqual({call.args[0].Limit for call in calls}, {100})

    def test_a_region_beyond_the_total_record_bound_is_refused(self):
        # A single region cannot pass the bound (TotalCount is capped at 10000), so the
        # overflow needs a second region after a first one that filled it exactly.
        full = [SimpleNamespace(InstanceSet=[instance(f'ins-{page:02d}{item:02d}') for item in range(100)], TotalCount=10000)
                for page in range(100)]
        extra = SimpleNamespace(InstanceSet=[instance('ins-extra')], TotalCount=1)
        with patch(CAM_CLIENT) as cam, patch(CVM_CLIENT) as cvm:
            with self.assertRaises(FederationError) as error:
                self.discover(cam, cvm, [*full, extra], regions=('ap-singapore', 'ap-guangzhou'))
            calls = cvm.return_value.DescribeInstances.call_args_list
        self.assertEqual(str(error.exception), RECORD_BOUND_REFUSAL)
        self.assertEqual(len(calls), 101)
        self.assertEqual(cvm.call_args_list[-1].args[1], 'ap-guangzhou')


class SourceBindingRecheckTests(unittest.TestCase):
    def setUp(self):
        self.cloud, self.vault = MagicMock(), MagicMock()
        self.operation = 'a' * 32
        self.vault.account.return_value = {
            'id': 'old-account', 'address': 'www.tencentcloud.com', 'userName': 'broker',
            'platformId': 'TencentSTS', 'safeName': 'CloudSafe',
            'platformAccountProperties': {'TencentRoleProfile': 'readonly', 'TencentSecretId': 'old-id'},
        }

    def test_prepare_refuses_a_source_that_does_not_bind_its_own_key(self):
        """prepare re-checks the binding instead of trusting validate_source's return.

        With an intact record validate_source raises the same refusal first, so the
        re-check is only observable once the identifier validator is relaxed: that is
        what recreates the state the guard exists for, and prepare must still refuse
        before it reaches the cloud.
        """
        del self.vault.account.return_value['platformAccountProperties']['TencentSecretId']
        with patch('pam.lifecycle.validate_identifier'):
            with self.assertRaises(LifecycleError) as error:
                prepare(self.cloud, self.vault, 'old-account', '123', 'readonly', self.operation)
        self.assertEqual(str(error.exception), BINDING_REFUSAL)
        self.cloud.keys.assert_not_called()
        self.cloud.create_key.assert_not_called()
        self.vault.create.assert_not_called()

    def test_the_binding_refusal_is_the_same_text_either_way(self):
        """The two guards share one message, so an operator sees one remediation."""
        self.vault.account.return_value['platformAccountProperties']['TencentRoleProfile'] = 'other'
        with self.assertRaises(LifecycleError) as error:
            prepare(self.cloud, self.vault, 'old-account', '123', 'readonly', self.operation)
        self.assertEqual(str(error.exception), BINDING_REFUSAL)
        self.cloud.keys.assert_not_called()


class IdentityCapacityTests(unittest.TestCase):
    """The per-identity bound must be an integer inside the shared pool it borrows from."""

    def local_store(self, capacity, identity_capacity):
        return TokenStore(capacity=capacity, ttl=60, identity_capacity=identity_capacity)

    def shared_store(self, capacity, identity_capacity):
        return RedisTokenStore(MagicMock(), namespace='prod', capacity=capacity, ttl=60, identity_capacity=identity_capacity)

    def test_a_non_integer_per_identity_bound_is_refused_by_both_stores(self):
        for value in (True, False, '3', 2.5, [2], {'bound': 2}):
            for build in (self.local_store, self.shared_store):
                with self.subTest(bound=value, store=build.__name__), self.assertRaises(ValueError) as error:
                    build(10, value)
                self.assertEqual(str(error.exception), IDENTITY_CAPACITY_REFUSAL)

    def test_a_per_identity_bound_outside_the_pool_is_refused_by_both_stores(self):
        for capacity, identity_capacity in ((2, 3), (1, 2), (10, 11), (1000, 1001), (10, 0), (10, -1)):
            for build in (self.local_store, self.shared_store):
                with self.subTest(capacity=capacity, bound=identity_capacity, store=build.__name__), self.assertRaises(ValueError) as error:
                    build(capacity, identity_capacity)
                self.assertEqual(str(error.exception), IDENTITY_CAPACITY_REFUSAL)

    def test_an_explicit_redis_bound_inside_the_pool_is_kept_and_handed_to_the_script(self):
        client = MagicMock()
        client.eval.return_value = 1
        store = RedisTokenStore(client, namespace='prod', capacity=10, ttl=60, identity_capacity=2)
        self.assertEqual(store.identity_capacity, 2)
        self.assertIsInstance(store.issue('alice'), str)
        # The bound travels as the last script argument, next to the shared pool size.
        args = client.eval.call_args.args
        self.assertEqual((args[-3], args[-1]), (10, 2))

    def test_the_derived_bound_never_exceeds_a_small_pool(self):
        self.assertEqual(TokenStore(capacity=1, ttl=60).identity_capacity, 1)
        self.assertEqual(RedisTokenStore(MagicMock(), capacity=2, ttl=60).identity_capacity, 2)


if __name__ == '__main__':
    unittest.main()
