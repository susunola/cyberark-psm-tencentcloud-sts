"""Refusal paths and boundary checks for staged rotation and account onboarding.

test_lifecycle.py / test_recovery_maintenance.py cover the happy paths, and
test_input_validation.py covers the public scope rules. This module pins the remaining defensive
branches: every refusal must happen before a cloud write, a vault write or a key retirement.
"""

import copy
import unittest
from dataclasses import asdict
from unittest.mock import MagicMock

from pam.lifecycle import (
    LifecycleError,
    Ticket,
    finalize,
    prepare,
    recover_ticket,
    restore_old,
    validate_identifier,
    validate_source,
)
from pam.onboarding import validate_account

OPERATION = "b" * 32
TICKET_FIELDS = {
    "operation",
    "target_uin",
    "old_account",
    "new_account",
    "old_secret_id",
    "new_secret_id",
    "profile",
}


def source_account() -> dict:
    """Return a complete bound source account as the vault would return it."""
    return {
        "id": "old-account",
        "address": "www.tencentcloud.com",
        "userName": "broker",
        "safeName": "CloudSafe",
        "platformId": "TencentSTS",
        "platformAccountProperties": {"TencentSecretId": "old-id", "TencentRoleProfile": "readonly"},
    }


def allowed_settings() -> dict:
    """Return bridge settings that authorize both sides of a rotation."""
    return {
        "profiles": {
            "readonly": {
                "allowed_secret_ids": ["old-id", "new-id"],
                "role_arn": "qcs::cam::uin/123:roleName/ReadOnly",
                "duration_seconds": 300,
                "region": "ap-guangzhou",
            }
        }
    }


class IdentifierTests(unittest.TestCase):
    def test_identifier_accepts_bounded_ascii_and_returns_it_unchanged(self):
        self.assertEqual(validate_identifier("Ab_1-2"), "Ab_1-2")
        self.assertEqual(validate_identifier("x" * 256), "x" * 256)

    def test_identifier_rejects_everything_else(self):
        for value in (None, 42, b"old-id", "a", "x" * 257, "bad id", "../key", "key;drop"):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError) as error:
                validate_identifier(value)
            self.assertEqual(str(error.exception), "Invalid credential identifier")


class TicketTests(unittest.TestCase):
    def args(self) -> dict:
        return {
            "operation": OPERATION,
            "target_uin": "00123",
            "old_account": "1_2",
            "new_account": "1_3",
            "old_secret_id": "old-id",
            "new_secret_id": "new-id",
            "profile": "readonly",
        }

    def test_every_ticket_field_is_bounded(self):
        for field, value in [
            ("operation", 123),
            ("operation", "A" * 32),
            ("operation", "b" * 31),
            ("old_account", 12),
            ("old_account", "has space"),
            ("new_account", None),
            ("new_account", "x" * 129),
            ("old_secret_id", None),
            ("old_secret_id", "bad id"),
            ("new_secret_id", 7),
            ("profile", 7),
            ("profile", "bad profile"),
            ("profile", "x" * 81),
        ]:
            with self.subTest(field=field, value=repr(value)), self.assertRaises(ValueError):
                Ticket(**self.args() | {field: value})

    def test_replacement_account_must_differ_from_the_old_one(self):
        with self.assertRaises(ValueError) as error:
            Ticket(**(self.args() | {"new_account": "1_2"}))
        self.assertEqual(str(error.exception), "Ticket replacement must differ")

    def test_public_export_is_a_plain_secret_free_snapshot(self):
        ticket = Ticket(**self.args())
        exported = ticket.public()
        self.assertIs(type(exported), dict)
        self.assertEqual(exported, asdict(ticket))
        self.assertEqual(set(exported), TICKET_FIELDS)
        self.assertEqual(exported["target_uin"], "123")
        self.assertEqual(exported["old_secret_id"], "old-id")
        exported["old_secret_id"] = "tampered-id"
        self.assertEqual(ticket.old_secret_id, "old-id")


class SourceScopeTests(unittest.TestCase):
    def test_source_profile_must_be_bounded(self):
        for profile in (None, 42, "", "bad profile", "x" * 81):
            with self.subTest(profile=repr(profile)), self.assertRaises(LifecycleError) as error:
                validate_source(source_account(), profile)
            self.assertEqual(str(error.exception), "Invalid source profile")

    def test_every_scoped_field_must_be_present_and_sane(self):
        for field in ("address", "userName", "platformId", "safeName"):
            for value in (None, 42, "", "   ", "x" * 1025, "line\nbreak"):
                account = source_account()
                account[field] = value
                with self.subTest(field=field, value=repr(value)), self.assertRaises(LifecycleError) as error:
                    validate_source(account, "readonly")
                self.assertEqual(str(error.exception), "Incomplete source account scope")
            account = source_account()
            del account[field]
            with self.subTest(field=field, value="missing"), self.assertRaises(LifecycleError):
                validate_source(account, "readonly")

    def test_properties_must_be_a_dict_bound_to_the_profile(self):
        account = source_account()
        account["platformAccountProperties"] = ["TencentSecretId", "readonly"]
        with self.assertRaises(LifecycleError) as error:
            validate_source(account, "readonly")
        self.assertEqual(str(error.exception), "Account/profile binding mismatch")

        account = source_account()
        del account["platformAccountProperties"]
        with self.assertRaises(LifecycleError):
            validate_source(account, "readonly")

        account = source_account()
        account["platformAccountProperties"]["TencentRoleProfile"] = "other"
        with self.assertRaises(LifecycleError):
            validate_source(account, "readonly")

    def test_properties_must_carry_a_bounded_caller_key(self):
        account = source_account()
        del account["platformAccountProperties"]["TencentSecretId"]
        with self.assertRaises(ValueError) as error:
            validate_source(account, "readonly")
        self.assertEqual(str(error.exception), "Invalid credential identifier")

        account = source_account()
        account["platformAccountProperties"]["TencentSecretId"] = "a"
        with self.assertRaises(ValueError):
            validate_source(account, "readonly")

    def test_valid_source_returns_the_bound_properties(self):
        account = source_account()
        self.assertIs(validate_source(account, "readonly"), account["platformAccountProperties"])


class PrepareRefusalTests(unittest.TestCase):
    def setUp(self):
        self.cloud, self.vault = MagicMock(), MagicMock()
        self.cloud.keys.return_value = [{"id": "old-id", "status": "Active", "description": ""}]
        self.cloud.create_key.return_value = ("new-id", "FAKE-ROTATION-KEY")
        self.old = source_account()
        self.vault.account.return_value = self.old
        self.vault.create.return_value = "new-account"

    def run_prepare(self):
        return prepare(self.cloud, self.vault, "old-account", "00123", "readonly", OPERATION)

    def test_operation_id_must_be_uuid_hex_before_any_lookup(self):
        for operation in ("", "not-a-uuid", "B" * 32, "b" * 31, "b" * 33):
            with self.subTest(operation=operation), self.assertRaises(ValueError) as error:
                prepare(self.cloud, self.vault, "old-account", "123", "readonly", operation)
            self.assertEqual(str(error.exception), "Use a UUID hex operation ID")
        self.vault.account.assert_not_called()
        self.cloud.create_key.assert_not_called()

    def test_old_key_must_be_owned_by_the_canonical_target(self):
        self.cloud.keys.return_value = [{"id": "other-id", "status": "Active", "description": ""}]
        with self.assertRaises(LifecycleError) as error:
            self.run_prepare()
        self.assertEqual(str(error.exception), "Old key is not owned by target UIN")
        self.cloud.keys.assert_called_once_with("123")
        self.cloud.create_key.assert_not_called()

    def test_unusable_replacement_pair_never_reaches_the_vault(self):
        for pair in [
            ("new-id", ""),
            ("new-id", "x" * 513),
            ("new-id", None),
            ("new-id", 42),
            ("bad id", "key"),
        ]:
            self.cloud.create_key.return_value = pair
            with self.subTest(pair=pair), self.assertRaises(LifecycleError) as error:
                self.run_prepare()
            self.assertEqual(
                str(error.exception),
                "Preparation incomplete; old key retained. Reconcile cloud/Vault before retrying.",
            )
        self.vault.create.assert_not_called()
        self.cloud.set_key_status.assert_not_called()

    def test_vault_payload_disables_native_automatic_management(self):
        self.run_prepare()
        payload = self.vault.create.call_args.args[0]
        self.assertEqual(
            payload,
            {
                "name": "tc-rotation-" + OPERATION,
                "address": "www.tencentcloud.com",
                "userName": "broker",
                "platformId": "TencentSTS",
                "safeName": "CloudSafe",
                "secretType": "password",
                "secret": "FAKE-ROTATION-KEY",
                "platformAccountProperties": {"TencentSecretId": "new-id", "TencentRoleProfile": "readonly"},
                "secretManagement": {
                    "automaticManagementEnabled": False,
                    "manualManagementReason": "External staged rotation; native CPM not configured",
                },
            },
        )
        self.assertIs(payload["secretManagement"]["automaticManagementEnabled"], False)
        self.assertEqual(self.old["platformAccountProperties"]["TencentSecretId"], "old-id")


class FinalizeRefusalTests(unittest.TestCase):
    def setUp(self):
        self.cloud, self.vault = MagicMock(), MagicMock()
        self.old = source_account()
        self.new = copy.deepcopy(self.old)
        self.new["id"] = "new-account"
        self.new["platformAccountProperties"]["TencentSecretId"] = "new-id"
        self.vault.account.side_effect = lambda value: self.old if value == "old-account" else self.new
        self.vault.secret.return_value = "FAKE-ROTATION-KEY"
        self.old_key = {"id": "old-id", "status": "Active", "description": ""}
        self.new_key = {"id": "new-id", "status": "Active", "description": "psm-rotation:" + OPERATION}
        self.cloud.keys.return_value = [self.old_key, self.new_key]
        self.settings = allowed_settings()
        self.ticket = Ticket(OPERATION, "123", "old-account", "new-account", "old-id", "new-id", "readonly")

        def update_status(target, secret_id, status):
            for key in self.cloud.keys.return_value:
                if key["id"] == secret_id:
                    key["status"] = status

        self.cloud.set_key_status.side_effect = update_status

    def forged(self, **overrides) -> MagicMock:
        """Simulate a ticket that bypassed Ticket validation (hand-edited journal file)."""
        ticket = MagicMock()
        for field in TICKET_FIELDS:
            setattr(ticket, field, getattr(self.ticket, field))
        for field, value in overrides.items():
            setattr(ticket, field, value)
        return ticket

    def run_finalize(self, ticket, **kwargs):
        return finalize(self.cloud, self.vault, ticket, self.settings, confirmed_cutover=True, **kwargs)

    def test_identical_credentials_in_a_forged_ticket_are_refused(self):
        for overrides in ({"old_secret_id": "new-id"}, {"old_account": "new-account"}):
            with self.subTest(overrides=overrides), self.assertRaises(LifecycleError) as error:
                self.run_finalize(self.forged(**overrides))
            self.assertEqual(str(error.exception), "Old and new credentials must differ")
        self.vault.account.assert_not_called()
        self.cloud.keys.assert_not_called()
        self.cloud.set_key_status.assert_not_called()

    def test_changed_vault_binding_blocks_cutover(self):
        for field, value in [("TencentSecretId", "swapped-id"), ("TencentRoleProfile", "other")]:
            self.new["platformAccountProperties"] = {
                "TencentSecretId": "new-id",
                "TencentRoleProfile": "readonly",
            }
            self.new["platformAccountProperties"][field] = value
            with self.subTest(field=field), self.assertRaises(LifecycleError) as error:
                self.run_finalize(self.ticket)
            self.assertEqual(str(error.exception), "Vault account binding changed")
        self.cloud.keys.assert_not_called()
        self.cloud.verify.assert_not_called()
        self.cloud.set_key_status.assert_not_called()

    def test_unexpected_state_during_verification_never_retires(self):
        def break_old_key_state_during_verification(*args):
            self.old_key["status"] = "Unknown"

        with self.assertRaises(LifecycleError) as error:
            self.run_finalize(self.ticket, role_verifier=break_old_key_state_during_verification)
        self.assertEqual(str(error.exception), "Key state changed during verification; inspect inventory")
        self.cloud.verify.assert_called_once_with("new-id", "FAKE-ROTATION-KEY", "123")
        self.assertEqual(self.cloud.keys.call_count, 2)
        self.cloud.set_key_status.assert_not_called()

    def test_old_key_already_inactive_reports_cutover_without_a_second_write(self):
        def retire_old_during_verification(*args):
            self.old_key["status"] = "Inactive"

        result = self.run_finalize(self.ticket, role_verifier=retire_old_during_verification)
        self.assertEqual(
            result,
            {"operation": OPERATION, "status": "old-key-inactive", "new_account": "new-account"},
        )
        self.cloud.set_key_status.assert_not_called()


class RestoreOldTests(unittest.TestCase):
    def test_deleted_key_cannot_be_restored(self):
        cloud = MagicMock()
        cloud.keys.return_value = [{"id": "new-id", "status": "Active", "description": ""}]
        with self.assertRaises(LifecycleError) as error:
            restore_old(cloud, "123", "old-id")
        self.assertEqual(str(error.exception), "Cannot restore a deleted key")
        cloud.keys.assert_called_once_with("123")
        cloud.set_key_status.assert_not_called()


class RecoveryRefusalTests(unittest.TestCase):
    def setUp(self):
        self.cloud, self.vault = MagicMock(), MagicMock()
        self.journal = {
            "operation": OPERATION,
            "status": "preparing",
            "old_account": "old-account",
            "target_uin": "00123",
            "profile": "readonly",
        }
        self.old = source_account()
        self.new = copy.deepcopy(self.old)
        self.new["id"] = "new-account"
        self.new["platformAccountProperties"]["TencentSecretId"] = "new-id"
        self.vault.account.side_effect = lambda value: self.old if value == "old-account" else self.new
        self.vault.find_rotation_accounts.return_value = [{"id": "new-account"}]
        self.vault.secret.return_value = "FAKE-ROTATION-KEY"
        self.old_key = {"id": "old-id", "status": "Active", "description": ""}
        self.new_key = {"id": "new-id", "status": "Active", "description": "psm-rotation:" + OPERATION}
        self.cloud.keys.return_value = [self.old_key, self.new_key]

    def test_journal_must_be_an_intact_prepare_record(self):
        for journal in (
            ["not", "a", "mapping"],
            None,
            {"operation": OPERATION},
            {**self.journal, "extra": "field"},
            {**self.journal, "status": "completed"},
        ):
            with self.subTest(journal=journal), self.assertRaises(LifecycleError) as error:
                recover_ticket(self.cloud, self.vault, journal)
            self.assertEqual(str(error.exception), "Use an intact prepare journal with account/profile scope")
        self.vault.account.assert_not_called()
        self.cloud.create_key.assert_not_called()
        self.vault.create.assert_not_called()

    def test_journal_operation_must_be_uuid_hex(self):
        for operation in ("", "not-a-uuid", "B" * 32, "b" * 33, None, 42):
            with self.subTest(operation=repr(operation)), self.assertRaises(LifecycleError) as error:
                recover_ticket(self.cloud, self.vault, {**self.journal, "operation": operation})
            self.assertEqual(str(error.exception), "Invalid operation ID")
        self.vault.account.assert_not_called()
        self.cloud.create_key.assert_not_called()

    def test_old_account_profile_binding_is_rechecked(self):
        self.old["platformAccountProperties"]["TencentRoleProfile"] = "other"
        with self.assertRaises(LifecycleError) as error:
            recover_ticket(self.cloud, self.vault, self.journal)
        self.assertEqual(str(error.exception), "Old account/profile binding mismatch")
        self.cloud.keys.assert_not_called()

    def test_old_account_without_caller_key_cannot_be_recovered(self):
        del self.old["platformAccountProperties"]["TencentSecretId"]
        with self.assertRaises(LifecycleError) as error:
            recover_ticket(self.cloud, self.vault, self.journal)
        self.assertEqual(str(error.exception), "Old account/profile binding mismatch")
        self.cloud.keys.assert_not_called()

    def test_exactly_one_active_replacement_key_is_required(self):
        for keys in (
            [dict(self.old_key)],
            [dict(self.old_key), dict(self.new_key), {**self.new_key, "id": "dup-id"}],
            [dict(self.old_key), {**self.new_key, "status": "Inactive"}],
            [dict(self.old_key), {**self.new_key, "description": "psm-rotation:" + "c" * 32}],
        ):
            self.cloud.keys.return_value = keys
            with self.subTest(keys=[k["id"] for k in keys]), self.assertRaises(LifecycleError) as error:
                recover_ticket(self.cloud, self.vault, self.journal)
            self.assertEqual(
                str(error.exception), "Need exactly one active replacement key; inspect cloud inventory"
            )
        self.vault.find_rotation_accounts.assert_not_called()
        self.cloud.create_key.assert_not_called()
        self.vault.create.assert_not_called()

    def test_replacement_binding_is_rechecked(self):
        for field, value in [("TencentSecretId", "swapped-id"), ("TencentRoleProfile", "other")]:
            self.new["platformAccountProperties"] = {
                "TencentSecretId": "new-id",
                "TencentRoleProfile": "readonly",
            }
            self.new["platformAccountProperties"][field] = value
            with self.subTest(field=field), self.assertRaises(LifecycleError) as error:
                recover_ticket(self.cloud, self.vault, self.journal)
            self.assertEqual(str(error.exception), "Replacement binding mismatch")
        self.cloud.verify.assert_not_called()
        self.vault.secret.assert_not_called()
        self.cloud.set_key_status.assert_not_called()

    def test_old_and_replacement_cloud_binding_must_differ_and_still_exist(self):
        self.old["platformAccountProperties"]["TencentSecretId"] = "new-id"
        self.cloud.keys.return_value = [dict(self.new_key)]
        with self.assertRaises(LifecycleError) as error:
            recover_ticket(self.cloud, self.vault, self.journal)
        self.assertEqual(str(error.exception), "Old/replacement cloud binding mismatch")

        self.old["platformAccountProperties"]["TencentSecretId"] = "gone-id"
        with self.assertRaises(LifecycleError) as error:
            recover_ticket(self.cloud, self.vault, self.journal)
        self.assertEqual(str(error.exception), "Old/replacement cloud binding mismatch")
        self.vault.find_rotation_accounts.assert_not_called()
        self.cloud.create_key.assert_not_called()
        self.vault.create.assert_not_called()

    def test_aliased_replacement_record_is_not_a_valid_pair(self):
        self.new["id"] = "old-account"
        self.vault.account.side_effect = [self.old, self.new]
        self.vault.find_rotation_accounts.return_value = [{"id": "old-account"}]
        with self.assertRaises(LifecycleError) as error:
            recover_ticket(self.cloud, self.vault, self.journal)
        self.assertEqual(str(error.exception), "Replacement account must differ")
        self.cloud.verify.assert_not_called()
        self.vault.secret.assert_not_called()
        self.cloud.create_key.assert_not_called()
        self.vault.create.assert_not_called()


class OnboardingValidationTests(unittest.TestCase):
    def payload(self) -> dict:
        return {
            "name": "guest",
            "address": "10.0.0.1",
            "userName": "admin",
            "platformId": "UnixSSH",
            "safeName": "Guests",
            "secretType": "password",
            "secret": "FAKE-SECRET",
            "connection_component": "PSM-SSH",
        }

    def test_payload_must_be_a_mapping_with_a_known_component(self):
        for payload in (None, [], "account", 42):
            with self.subTest(payload=repr(payload)), self.assertRaises(ValueError) as error:
                validate_account(payload, "Guests", "UnixSSH")
            self.assertEqual(str(error.exception), "Expected an account object")

        for component in ("PSM-RDP2", "rdp", "", 7, {"PSM-SSH": True}):
            candidate = self.payload()
            candidate["connection_component"] = component
            with self.subTest(component=repr(component)), self.assertRaises(ValueError) as error:
                validate_account(candidate, "Guests", "UnixSSH")
            self.assertEqual(str(error.exception), "Unknown proposal component")

        candidate = self.payload()
        candidate["connection_component"] = "PSM-RDP"
        self.assertNotIn("connection_component", validate_account(candidate, "Guests", "UnixSSH"))

    def test_metadata_fields_must_be_bounded_text(self):
        for field in ("name", "address", "userName", "secretType"):
            for value in (None, 42, "", "   ", "x" * 1025, "line\nbreak"):
                candidate = self.payload()
                candidate[field] = value
                with self.subTest(field=field, value=repr(value)), self.assertRaises(ValueError) as error:
                    validate_account(candidate, "Guests", "UnixSSH")
                self.assertEqual(str(error.exception), "Invalid account metadata")

    def test_metadata_boundaries_are_inclusive(self):
        candidate = self.payload()
        candidate["address"] = "x" * 1024
        self.assertEqual(validate_account(candidate, "Guests", "UnixSSH")["address"], "x" * 1024)

    def test_secret_must_be_a_bounded_password_string(self):
        for field, value in [
            ("secretType", "key"),
            ("secretType", "PASSWORD"),
            ("secret", ""),
            ("secret", 42),
            ("secret", {"nested": "FAKE-SECRET"}),
            ("secret", "x" * 4097),
        ]:
            candidate = self.payload()
            candidate[field] = value
            with self.subTest(field=field, value=repr(value)), self.assertRaises(ValueError) as error:
                validate_account(candidate, "Guests", "UnixSSH")
            self.assertEqual(str(error.exception), "Explicit bounded password credential required")

        candidate = self.payload()
        candidate["secret"] = "x" * 4096
        self.assertEqual(validate_account(candidate, "Guests", "UnixSSH")["secret"], "x" * 4096)

    def test_platform_properties_must_be_a_string_mapping(self):
        for properties in (["TencentSecretId"], "TencentSecretId", 7, None):
            candidate = self.payload()
            candidate["platformAccountProperties"] = properties
            with self.subTest(properties=repr(properties)), self.assertRaises(ValueError) as error:
                validate_account(candidate, "Guests", "UnixSSH")
            self.assertEqual(str(error.exception), "Platform properties must be bounded strings")

    def test_property_keys_and_values_must_be_bounded_strings(self):
        for properties in (
            {"": "value"},
            {"k" * 129: "value"},
            {7: "value"},
            {"key": 7},
            {"key": None},
            {"key": "v" * 1025},
        ):
            candidate = self.payload()
            candidate["platformAccountProperties"] = properties
            with self.subTest(properties=repr(properties)[:40]), self.assertRaises(ValueError) as error:
                validate_account(candidate, "Guests", "UnixSSH")
            self.assertEqual(str(error.exception), "Platform properties must be bounded strings")

        candidate = self.payload()
        candidate["platformAccountProperties"] = {"k" * 128: "v" * 1024}
        self.assertEqual(
            validate_account(candidate, "Guests", "UnixSSH")["platformAccountProperties"],
            {"k" * 128: "v" * 1024},
        )

    def test_management_flags_are_strictly_typed(self):
        for management in (
            [],
            "enabled",
            {},
            {"manualManagementReason": "external"},
            {"automaticManagementEnabled": 1},
            {"automaticManagementEnabled": "false"},
            {"automaticManagementEnabled": False, "unknownFlag": True},
        ):
            candidate = self.payload()
            candidate["secretManagement"] = management
            with self.subTest(management=management), self.assertRaises(ValueError) as error:
                validate_account(candidate, "Guests", "UnixSSH")
            self.assertEqual(str(error.exception), "Invalid management flags")

    def test_management_reason_must_be_bounded_text(self):
        for reason in (42, None, "r" * 1025):
            candidate = self.payload()
            candidate["secretManagement"] = {
                "automaticManagementEnabled": False,
                "manualManagementReason": reason,
            }
            with self.subTest(reason=repr(reason)[:12]), self.assertRaises(ValueError) as error:
                validate_account(candidate, "Guests", "UnixSSH")
            self.assertEqual(str(error.exception), "Invalid management reason")

        candidate = self.payload()
        candidate["secretManagement"] = {"automaticManagementEnabled": True}
        self.assertEqual(
            validate_account(candidate, "Guests", "UnixSSH")["secretManagement"],
            {"automaticManagementEnabled": True},
        )

    def test_cam_binding_requires_disabled_automatic_management(self):
        candidate = self.payload()
        candidate["platformAccountProperties"] = {
            "TencentSecretId": "caller-id",
            "TencentRoleProfile": "readonly",
        }
        candidate["secretManagement"] = {"automaticManagementEnabled": True}
        with self.assertRaises(ValueError) as error:
            validate_account(candidate, "Guests", "UnixSSH")
        self.assertEqual(
            str(error.exception),
            "CAM key accounts must explicitly disable native automatic management",
        )

        candidate["secretManagement"] = {"automaticManagementEnabled": False}
        self.assertEqual(
            validate_account(candidate, "Guests", "UnixSSH")["platformAccountProperties"],
            {"TencentSecretId": "caller-id", "TencentRoleProfile": "readonly"},
        )

    def test_result_is_a_deep_copy_of_the_submitted_payload(self):
        payload = self.payload()
        payload["platformAccountProperties"] = {
            "TencentSecretId": "caller-id",
            "TencentRoleProfile": "readonly",
        }
        payload["secretManagement"] = {"automaticManagementEnabled": False}
        snapshot = copy.deepcopy(payload)
        validated = validate_account(payload, "Guests", "UnixSSH")
        self.assertIsNot(validated, payload)
        self.assertIsNot(validated["platformAccountProperties"], payload["platformAccountProperties"])
        validated["name"] = "tampered"
        validated["secret"] = "tampered"
        validated["platformAccountProperties"]["TencentSecretId"] = "tampered-id"
        validated["secretManagement"]["automaticManagementEnabled"] = True
        self.assertEqual(payload, snapshot)
        self.assertIn("connection_component", payload)


if __name__ == "__main__":
    unittest.main()
