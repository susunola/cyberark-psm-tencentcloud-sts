"""Branch-level coverage for scoped maintenance and strict startup configuration.

Complements ``tests/test_recovery_maintenance.py`` (uncertain rotation recovery) and
``tests/test_hardening.py`` (request handling): the assertions here pin the job-scope
grammar of ``pam.maintenance.validate_jobs``, the lock/journal ordering of
``pam.maintenance.run``, and the 1 MiB / 100 profile / 10 SecretId bounds of
``configuration.py``.
"""

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from configuration import load_settings, validate_settings
from federation import FederationError
from pam import maintenance
from pam.files import private_output, read_json
from pam.maintenance import run, validate_jobs

JOB_FIELDS = {
    "id": "caller",
    "action": "verify-cam",
    "account": "old-account",
    "target_uin": "123",
    "profile": "readonly",
    "safe": "CloudSafe",
    "platform": "TencentSTS",
}


def job(**overrides):
    """Return one otherwise-valid maintenance job with explicit overrides applied."""
    return {**JOB_FIELDS, **overrides}


def jobs(*entries):
    return {"jobs": list(entries)}


def profile(**overrides):
    """Return one otherwise-valid bridge profile with explicit overrides applied."""
    value = copy.deepcopy(settings()["profiles"]["readonly"])
    value.update(overrides)
    return value


def settings():
    """Return a minimal valid bridge configuration."""
    return {
        "profiles": {
            "readonly": {
                "role_arn": "qcs::cam::uin/123:roleName/ReadOnly",
                "allowed_secret_ids": ["old-id"],
                "destination": "https://console.tencentcloud.com/",
                "duration_seconds": 300,
                "region": "ap-guangzhou",
            }
        }
    }


class MaintenanceJobValidationTests(unittest.TestCase):
    def test_configuration_must_be_a_jobs_object_only(self):
        for configuration in ([], None, "jobs", {}, {"job": []}, {"jobs": [], "extra": 1}):
            with (
                self.subTest(configuration=configuration),
                self.assertRaisesRegex(ValueError, "Expected maintenance jobs only"),
            ):
                validate_jobs(configuration)

    def test_job_count_bounds(self):
        for configuration in (jobs(), {"jobs": "caller"}):
            with (
                self.subTest(configuration=configuration),
                self.assertRaisesRegex(ValueError, "Configure 1..100 jobs"),
            ):
                validate_jobs(configuration)
        overloaded = {"jobs": [job(id=f"job-{index}") for index in range(101)]}
        with self.assertRaisesRegex(ValueError, "Configure 1..100 jobs"):
            validate_jobs(overloaded)
        at_limit = validate_jobs({"jobs": [job(id=f"job-{index}") for index in range(100)]})
        self.assertEqual([entry["id"] for entry in at_limit], [f"job-{index}" for index in range(100)])

    def test_job_field_set_is_exact(self):
        missing = job()
        del missing["platform"]
        for entry in ("caller", [], missing, job(extra="value")):
            with (
                self.subTest(entry=entry),
                self.assertRaisesRegex(ValueError, "Invalid maintenance job fields"),
            ):
                validate_jobs(jobs(entry))

    def test_job_values_must_be_nonempty_strings(self):
        for entry in (job(target_uin=123), job(target_uin=None), job(account=""), job(safe=0), job(id="")):
            with (
                self.subTest(entry=entry),
                self.assertRaisesRegex(ValueError, "Maintenance fields must be nonempty strings"),
            ):
                validate_jobs(jobs(entry))

    def test_job_ids_are_distinct_and_never_windows_devices(self):
        for identifier in (
            "bad id!",
            "caller/../other",
            "x" * 81,
            "CON",
            "PRN",
            "AUX",
            "NUL",
            "COM1",
            "LPT1",
        ):
            with (
                self.subTest(identifier=identifier),
                self.assertRaisesRegex(ValueError, "Use distinct safe job IDs"),
            ):
                validate_jobs(jobs(job(id=identifier)))
        with self.assertRaisesRegex(ValueError, "Use distinct safe job IDs"):
            validate_jobs(jobs(job(id="caller"), job(id="Caller")))
        accepted = validate_jobs(jobs(job(id="caller"), job(id="caller2")))
        self.assertEqual([entry["id"] for entry in accepted], ["caller", "caller2"])

    def test_account_and_profile_patterns_are_bounded(self):
        for entry in (
            job(account="bad account!"),
            job(account="x" * 129),
            job(profile="bad profile!"),
            job(profile="x" * 81),
        ):
            with (
                self.subTest(entry=entry),
                self.assertRaisesRegex(ValueError, "Invalid maintenance account/profile"),
            ):
                validate_jobs(jobs(entry))

    def test_safe_and_platform_scope_is_bounded(self):
        for key in ("safe", "platform"):
            for value in ("   ", "Cloud\x07Safe", "x" * 1025):
                with (
                    self.subTest(key=key, value=value),
                    self.assertRaisesRegex(ValueError, "Invalid maintenance scope"),
                ):
                    validate_jobs(jobs(job(**{key: value})))
        accepted = validate_jobs(jobs(job(safe="CloudS afe", platform="TencentSTS")))
        self.assertEqual(accepted[0]["safe"], "CloudS afe")

    def test_only_verification_and_preparation_actions_are_accepted(self):
        for action in ("finalize", "Verify-CAM", "verify-cam ", "prepare key", "rotate"):
            with (
                self.subTest(action=action),
                self.assertRaisesRegex(ValueError, "cannot finalize, delete, approve or reset"),
            ):
                validate_jobs(jobs(job(action=action)))
        for action in ("verify-cam", "prepare-key"):
            self.assertEqual(validate_jobs(jobs(job(action=action)))[0]["action"], action)

    def test_target_uin_is_canonicalized_without_mutating_the_caller(self):
        configuration = jobs(job(target_uin="00123"))
        validated = validate_jobs(configuration)
        self.assertEqual(validated[0]["target_uin"], "123")
        self.assertIsInstance(validated[0]["target_uin"], str)
        self.assertEqual(configuration["jobs"][0]["target_uin"], "00123")
        for target in ("0", "abc", "1.5", "-1", "1" * 21):
            with (
                self.subTest(target=target),
                self.assertRaisesRegex(ValueError, "Explicit positive target UIN required"),
            ):
                validate_jobs(jobs(job(target_uin=target)))

    def test_one_preparation_per_target_uin_per_run(self):
        duplicate = jobs(
            job(action="prepare-key", target_uin="123"),
            job(id="second", action="prepare-key", target_uin="0123"),
        )
        with self.assertRaisesRegex(ValueError, "One preparation per target UIN per run"):
            validate_jobs(duplicate)
        repeated = validate_jobs(jobs(job(), job(id="second", target_uin="0123")))
        self.assertEqual(len(repeated), 2)
        self.assertEqual({entry["target_uin"] for entry in repeated}, {"123"})
        separated = validate_jobs(
            jobs(job(action="prepare-key"), job(id="second", action="prepare-key", target_uin="456"))
        )
        self.assertEqual([entry["target_uin"] for entry in separated], ["123", "456"])


class MaintenanceRunTests(unittest.TestCase):
    def setUp(self):
        self.cloud, self.vault = MagicMock(), MagicMock()
        self.settings = settings()
        self.old = {
            "id": "old-account",
            "address": "www.tencentcloud.com",
            "safeName": "CloudSafe",
            "platformId": "TencentSTS",
            "userName": "broker",
            "platformAccountProperties": {"TencentSecretId": "old-id", "TencentRoleProfile": "readonly"},
        }
        self.vault.account.return_value = self.old
        self.vault.secret.return_value = "FAKE-SECRET"

    def test_state_directory_must_exist(self):
        with tempfile.TemporaryDirectory() as folder:
            missing = Path(folder) / "state"
            with self.assertRaisesRegex(ValueError, "Pre-create a protected maintenance state directory"):
                run(jobs(job()), self.settings, missing, self.cloud, self.vault, MagicMock())
            self.assertFalse(missing.exists())
        self.vault.account.assert_not_called()

    def test_invalid_jobs_never_create_a_lock(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, "Configure 1..100 jobs"):
                run(jobs(), self.settings, folder, self.cloud, self.vault, MagicMock())
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_failed_job_releases_the_lock(self):
        self.vault.account.return_value = {**copy.deepcopy(self.old), "platformId": "OtherPlatform"}
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, "outside approved scope"):
                run(jobs(job()), self.settings, folder, self.cloud, self.vault, MagicMock())
            self.assertFalse((Path(folder) / ".maintenance.lock").exists())
        self.vault.secret.assert_not_called()
        self.cloud.verify.assert_not_called()

    def test_concurrent_runner_cannot_steal_an_active_lock(self):
        with tempfile.TemporaryDirectory() as folder:
            lock = Path(folder) / ".maintenance.lock"
            with private_output(lock) as held:
                held.write("running")
                held.flush()
                with self.assertRaises(FileExistsError):
                    run(jobs(job()), self.settings, folder, self.cloud, self.vault, MagicMock())
                self.assertTrue(lock.exists())
                self.assertEqual(lock.read_text(), "running")
        self.vault.account.assert_not_called()

    def test_verification_resolves_the_secret_and_verifies_identity_and_role(self):
        role = MagicMock()
        with tempfile.TemporaryDirectory() as folder:
            results = run(jobs(job()), self.settings, folder, self.cloud, self.vault, role)
            self.assertFalse((Path(folder) / ".maintenance.lock").exists())
        self.assertEqual(results, [{"job": "caller", "status": "identity-and-role-verified"}])
        self.vault.account.assert_called_once_with("old-account")
        self.vault.secret.assert_called_once_with(
            "old-account", "Scheduled Tencent credential verification caller"
        )
        self.cloud.verify.assert_called_once_with("old-id", "FAKE-SECRET", "123")
        role.assert_called_once()
        secret_id, secret, arn, session_name, duration, region, site = role.call_args.args
        self.assertEqual(
            (secret_id, secret, arn, duration, region, site),
            ("old-id", "FAKE-SECRET", "qcs::cam::uin/123:roleName/ReadOnly", 300, "ap-guangzhou", "intl"),
        )
        self.assertRegex(session_name, r"^verify-[0-9a-f]{32}$")
        self.assertNotIn("FAKE-SECRET", repr(results))
        self.cloud.create_key.assert_not_called()
        self.vault.create.assert_not_called()

    def test_preparation_journals_before_prepare_and_swaps_the_ticket_atomically(self):
        self.cloud.keys.return_value = [{"id": "old-id", "status": "Active", "description": ""}]
        self.cloud.create_key.return_value = ("new-id-2", "FAKE-NEW-KEY")
        self.vault.create.return_value = "new-account"
        observed = {}
        real_prepare = maintenance.prepare

        with tempfile.TemporaryDirectory() as folder:

            def spy(*args):
                # The crash journal must already be durable before prepare touches the cloud.
                observed["journal"] = read_json(Path(folder) / "rotate.json")
                observed["cloud_write_first"] = self.cloud.create_key.called
                observed["temporary_exists"] = (Path(folder) / "rotate.json.tmp").exists()
                return real_prepare(*args)

            with (
                patch.object(maintenance, "prepare", side_effect=spy) as fake,
                patch.object(maintenance.os, "replace", wraps=os.replace) as replace,
            ):
                results = run(
                    jobs(job(id="rotate", action="prepare-key")),
                    self.settings,
                    folder,
                    self.cloud,
                    self.vault,
                    MagicMock(),
                )
            ticket_path = Path(folder) / "rotate.json"
            self.assertEqual(fake.call_count, 1)
            self.assertEqual(replace.call_args.args, (Path(folder) / "rotate.json.tmp", ticket_path))
            self.assertFalse((Path(folder) / "rotate.json.tmp").exists())
            self.assertFalse((Path(folder) / ".maintenance.lock").exists())
            self.assertEqual(
                results,
                [
                    {
                        "job": "rotate",
                        "status": "prepared-awaiting-tested-cutover",
                        "ticket": str(ticket_path),
                    }
                ],
            )
            ticket = read_json(ticket_path)

        journal = observed["journal"]
        self.assertEqual(journal["status"], "preparing")
        self.assertEqual(journal["target_uin"], "123")
        self.assertEqual(journal["old_account"], "old-account")
        self.assertEqual(journal["profile"], "readonly")
        self.assertRegex(journal["operation"], r"^[0-9a-f]{32}$")
        self.assertFalse(observed["cloud_write_first"])
        self.assertFalse(observed["temporary_exists"])
        self.assertEqual(
            ticket,
            {
                "operation": journal["operation"],
                "target_uin": "123",
                "old_account": "old-account",
                "new_account": "new-account",
                "old_secret_id": "old-id",
                "new_secret_id": "new-id-2",
                "profile": "readonly",
            },
        )
        self.assertNotIn("FAKE-NEW-KEY", json.dumps(ticket))
        self.assertNotIn("FAKE-NEW-KEY", repr(results))
        self.cloud.verify.assert_called_once_with("new-id-2", "FAKE-NEW-KEY", "123")
        self.vault.create.assert_called_once()
        self.cloud.set_key_status.assert_not_called()

    def test_account_outside_the_approved_scope_is_rejected(self):
        for field, value in (("safeName", "OtherSafe"), ("platformId", "OtherPlatform")):
            with self.subTest(field=field):
                self.vault.account.return_value = {**copy.deepcopy(self.old), field: value}
                with tempfile.TemporaryDirectory() as folder:
                    with self.assertRaisesRegex(ValueError, "outside approved scope"):
                        run(jobs(job()), self.settings, folder, self.cloud, self.vault, MagicMock())
                    self.assertFalse((Path(folder) / ".maintenance.lock").exists())
        rebound = copy.deepcopy(self.old)
        rebound["platformAccountProperties"]["TencentRoleProfile"] = "admin"
        self.vault.account.return_value = rebound
        with (
            tempfile.TemporaryDirectory() as folder,
            self.assertRaisesRegex(ValueError, "outside approved scope"),
        ):
            run(jobs(job()), self.settings, folder, self.cloud, self.vault, MagicMock())
        self.vault.secret.assert_not_called()

    def test_caller_must_be_authorized_in_the_bridge_profile(self):
        unbound = copy.deepcopy(self.old)
        unbound["platformAccountProperties"]["TencentRoleProfile"] = "admin"
        missing_sid = copy.deepcopy(self.old)
        del missing_sid["platformAccountProperties"]["TencentSecretId"]
        foreign_sid = copy.deepcopy(self.old)
        foreign_sid["platformAccountProperties"]["TencentSecretId"] = "other-id"
        for name, account, job_profile in (
            ("unknown-profile", unbound, "admin"),
            ("missing-secret-id", missing_sid, "readonly"),
            ("secret-id-not-allowed", foreign_sid, "readonly"),
        ):
            with self.subTest(name=name):
                self.vault.account.return_value = account
                with tempfile.TemporaryDirectory() as folder:
                    with self.assertRaisesRegex(ValueError, "caller not authorized in bridge profile"):
                        run(
                            jobs(job(profile=job_profile)),
                            self.settings,
                            folder,
                            self.cloud,
                            self.vault,
                            MagicMock(),
                        )
                    self.assertFalse((Path(folder) / ".maintenance.lock").exists())
        self.vault.secret.assert_not_called()
        self.cloud.verify.assert_not_called()


class ConfigurationLoadBoundaryTests(unittest.TestCase):
    def test_size_bound_is_exact(self):
        document = json.dumps(settings()).encode("utf-8")
        with tempfile.TemporaryDirectory() as folder:
            at_limit = Path(folder) / "at-limit.json"
            at_limit.write_bytes(document + b" " * (1024 * 1024 - len(document)))
            self.assertEqual(at_limit.stat().st_size, 1024 * 1024)
            self.assertEqual(load_settings(at_limit), settings())
            over_limit = Path(folder) / "over-limit.json"
            over_limit.write_bytes(document + b" " * (1024 * 1024 + 1 - len(document)))
            with self.assertRaisesRegex(ValueError, "size limit"):
                load_settings(over_limit)

    def test_utf8_bom_is_accepted(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "settings.json"
            path.write_bytes(b"\xef\xbb\xbf" + json.dumps(settings()).encode("utf-8"))
            self.assertEqual(load_settings(path), settings())

    def test_duplicate_keys_anywhere_are_rejected(self):
        for document in (
            '{"profiles":{},"profiles":{}}',
            '{"profiles":{"readonly":{"role_arn":"a","role_arn":"b"}}}',
        ):
            with self.subTest(document=document), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "settings.json"
                path.write_bytes(document.encode("utf-8"))
                with self.assertRaisesRegex(ValueError, "Duplicate configuration field"):
                    load_settings(path)


class ConfigurationValidationTests(unittest.TestCase):
    def test_root_shape_is_strict(self):
        for source in ([], None, "profiles", {}, {"profile": {}}, {"profiles": {}, "extra": 1}):
            with (
                self.subTest(source=source),
                self.assertRaisesRegex(ValueError, "Expected a profiles object only"),
            ):
                validate_settings(source)

    def test_profile_count_bounds(self):
        for count in (0, 101):
            profiles = {f"profile-{index}": profile() for index in range(count)}
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, "Configure 1..100 profiles"):
                validate_settings({"profiles": profiles})
        full = {f"profile-{index}": profile(allowed_secret_ids=[f"broker-{index}"]) for index in range(100)}
        self.assertEqual(len(validate_settings({"profiles": full})["profiles"]), 100)

    def test_profile_names_and_fields_are_strict(self):
        for name in ("bad name!", "invalid/name", "x" * 81):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "Invalid profile name"):
                validate_settings({"profiles": {name: profile()}})
        incomplete = profile()
        del incomplete["region"]
        for body in ([], "readonly", {}, profile(extra="field"), incomplete):
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, "Invalid profile fields"):
                validate_settings({"profiles": {"readonly": body}})

    def test_role_arn_rules(self):
        for arn in (
            "arn:aws:iam::123:role/ReadOnly",
            "qcs::cam::uin/abc:roleName/ReadOnly",
            "qcs::cam::uin/123:roleName/Bad Name",
            "qcs::cam::uin/123:Role/ReadOnly",
            "qcs::cam::uin/123:roleName/ReadOnly/extra",
            None,
        ):
            with self.subTest(arn=arn), self.assertRaisesRegex(ValueError, "Invalid ordinary CAM role ARN"):
                validate_settings({"profiles": {"readonly": profile(role_arn=arn)}})

    def test_destination_delegates_to_federation(self):
        for destination in ("https://evil.example.com/", "http://console.tencentcloud.com/", "", 123, None):
            with self.subTest(destination=destination), self.assertRaises(FederationError):
                validate_settings({"profiles": {"readonly": profile(destination=destination)}})

    def test_duration_seconds_rejects_bools_and_out_of_range_values(self):
        # The floor mirrors federation's 30-second credential margin: anything shorter
        # can never satisfy it, so accepting it would only create a dead profile.
        for duration in (True, False, "300", 300.0, 0, -1, 1, 30, 301, None):
            with (
                self.subTest(duration=duration),
                self.assertRaisesRegex(ValueError, "Duration must be 31..300 seconds"),
            ):
                validate_settings({"profiles": {"readonly": profile(duration_seconds=duration)}})
        for duration in (31, 300):
            validated = validate_settings({"profiles": {"readonly": profile(duration_seconds=duration)}})
            self.assertEqual(validated["profiles"]["readonly"]["duration_seconds"], duration)

    def test_allowed_secret_id_count_bounds(self):
        for ids in ("broker-id", None, [], [f"broker-{index}" for index in range(11)]):
            with (
                self.subTest(ids=ids),
                self.assertRaisesRegex(ValueError, "Configure 1..10 caller SecretIds per profile"),
            ):
                validate_settings({"profiles": {"readonly": profile(allowed_secret_ids=ids)}})
        full = profile(allowed_secret_ids=[f"broker-{index}" for index in range(10)])
        validated = validate_settings({"profiles": {"readonly": full}})
        self.assertEqual(len(validated["profiles"]["readonly"]["allowed_secret_ids"]), 10)

    def test_caller_secret_ids_must_be_real_and_unique(self):
        for sid in (123, None, "", "a", "broker!", "broker id", "AKID-REPLACE", "REPLACE_ME"):
            with self.subTest(sid=sid), self.assertRaisesRegex(ValueError, "Configure real caller SecretIds"):
                validate_settings({"profiles": {"readonly": profile(allowed_secret_ids=[sid])}})
        shared = {"profiles": {"readonly": profile(), "second": profile(allowed_secret_ids=["old-id"])}}
        with self.assertRaisesRegex(ValueError, "one profile only"):
            validate_settings(shared)

    def test_region_rules(self):
        for region in (None, 123, "", "ap", "AP-guangzhou", "ap_guangzhou", "a-guangzhou"):
            with self.subTest(region=region), self.assertRaisesRegex(ValueError, "Invalid cloud region"):
                validate_settings({"profiles": {"readonly": profile(region=region)}})
        # Suffix forms are syntactically valid; availability stays a cloud-side decision.
        for region in ("ap-guangzhou", "ap-singapore", "na-siliconvalley", "ap-guangzhou-1"):
            validated = validate_settings({"profiles": {"readonly": profile(region=region)}})
            self.assertEqual(validated["profiles"]["readonly"]["region"], region)

    def test_validated_settings_are_a_deep_copy(self):
        source = settings()
        result = validate_settings(source)
        self.assertIsNot(result, source)
        self.assertIsNot(result["profiles"], source["profiles"])
        self.assertIsNot(result["profiles"]["readonly"], source["profiles"]["readonly"])
        self.assertIsNot(
            result["profiles"]["readonly"]["allowed_secret_ids"],
            source["profiles"]["readonly"]["allowed_secret_ids"],
        )
        result["profiles"]["readonly"]["allowed_secret_ids"].append("second-id")
        result["profiles"]["readonly"]["duration_seconds"] = 1
        result["profiles"]["added"] = profile()
        self.assertEqual(source["profiles"]["readonly"]["allowed_secret_ids"], ["old-id"])
        self.assertEqual(source["profiles"]["readonly"]["duration_seconds"], 300)
        self.assertNotIn("added", source["profiles"])
        self.assertEqual(source, settings())


if __name__ == "__main__":
    unittest.main()
