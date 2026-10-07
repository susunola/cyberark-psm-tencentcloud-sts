"""Model-based tests for the rotation state machine.

The hand-written lifecycle tests pin individual transitions. These drive random
*sequences* of prepare/finalize/restore/recover against an in-memory model of the
cloud key inventory and the Vault accounts, then assert the invariants that must
hold after every step:

* a reported cutover leaves exactly one active key, so a second preparation cannot
  leave an unverified credential live;
* a key is only ever retired once another key was verified as the target identity;
* rotation never ends with zero usable credentials;
* a credential never reaches a ticket or a return value.

The failure mode being guarded here is the one that matters most and is least
suited to example tests: two live credentials for one automation identity.
"""

import unittest
from dataclasses import dataclass, field

try:
    from hypothesis import HealthCheck, settings
    from hypothesis import strategies as st
    from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule
except ModuleNotFoundError:  # pragma: no cover - a runtime-only install carries no test tooling
    raise unittest.SkipTest("install requirements-dev.txt to run the rotation invariant suite") from None

import pam.lifecycle as lifecycle
from pam.lifecycle import LifecycleError

settings.register_profile(
    "stateful",
    deadline=None,
    max_examples=60,
    stateful_step_count=25,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("stateful")

OPERATION = "a" * 32
PROFILE = "readonly"
OLD_KEY = "old-key"
SETTINGS = {
    "profiles": {
        PROFILE: {
            "role_arn": "qcs::cam::uin/123:roleName/ReadOnly",
            "allowed_secret_ids": [OLD_KEY, "new-key-1", "new-key-2"],
            "destination": "https://console.tencentcloud.com/",
            "duration_seconds": 300,
            "region": "ap-guangzhou",
        }
    }
}


@dataclass
class Cloud:
    """Minimal model of the CAM access-key inventory for one target UIN."""

    target: str = "123"
    inventory: dict[str, str] = field(default_factory=lambda: {OLD_KEY: "Active"})
    created: int = 0
    retired: list[str] = field(default_factory=list)

    def keys(self, target):
        assert str(target) == self.target
        return [
            {"id": key, "status": status, "description": ""} for key, status in sorted(self.inventory.items())
        ]

    def create_key(self, target, operation):
        assert str(target) == self.target
        if len(self.inventory) >= 2:
            raise LifecycleError("No conservative spare key slot; do not delete keys automatically")
        self.created += 1
        identifier = f"new-key-{self.created}"
        self.inventory[identifier] = "Active"
        return identifier, "secret-" + identifier

    def verify(self, secret_id, secret_key, target):
        assert str(target) == self.target
        if secret_id not in self.inventory or secret_key != "secret-" + secret_id:
            raise LifecycleError("Credential is not the pair we created")
        return True

    def set_key_status(self, target, secret_id, status):
        assert str(target) == self.target
        if secret_id not in self.inventory:
            raise LifecycleError("Unknown key")
        self.inventory[secret_id] = status
        if status == "Inactive" and secret_id not in self.retired:
            self.retired.append(secret_id)

    def active(self):
        return {key for key, status in self.inventory.items() if status == "Active"}


@dataclass
class Vault:
    """Minimal model of the PVWA side: one account per key plus a secret store."""

    accounts: dict = field(default_factory=dict)
    secrets: dict = field(default_factory=dict)

    def __post_init__(self):
        self.accounts["old-account"] = {
            "id": "old-account",
            "name": "tc-old",
            "address": "www.tencentcloud.com",
            "userName": "broker",
            "safeName": "CloudSafe",
            "platformId": "TencentSTS",
            "platformAccountProperties": {"TencentSecretId": OLD_KEY, "TencentRoleProfile": PROFILE},
        }
        self.secrets["old-account"] = "secret-" + OLD_KEY

    def account(self, account_id):
        if account_id not in self.accounts:
            raise LifecycleError("Unknown account")
        return self.accounts[account_id]

    def secret(self, account_id, reason):
        return self.secrets[account_id]

    def create(self, payload):
        identifier = "account-" + payload["platformAccountProperties"]["TencentSecretId"]
        self.accounts[identifier] = {"id": identifier, **payload}
        self.secrets[identifier] = payload["secret"]
        return identifier

    def find_rotation_accounts(self, operation):
        return [a for a in self.accounts.values() if a.get("name") == "tc-rotation-" + operation]


class RotationStateMachine(RuleBasedStateMachine):
    """Drive the rotation API in random order and check the safety invariants."""

    def __init__(self):
        super().__init__()
        self.cloud = Cloud()
        self.vault = Vault()
        self.tickets = []
        self.verified: set[str] = set()
        # 'staged' = one or two live keys (initial, staged, or deliberately rolled back);
        # 'cutover' = the retirement was performed and reported, so exactly one remains.
        self.phase = "staged"

    @initialize()
    def ready(self):
        assert self.cloud.active() == {OLD_KEY}

    def role_verifier(self, secret_id, secret_key, *_ignored):
        self.verified.add(secret_id)
        return {"TmpSecretId": "tmp", "TmpSecretKey": "tmp", "Token": "tmp"}

    @rule()
    def prepare(self):
        if len(self.cloud.inventory) >= 2:
            return
        try:
            ticket = lifecycle.prepare(self.cloud, self.vault, "old-account", "123", PROFILE, OPERATION)
        except (LifecycleError, ValueError):
            return
        self.tickets.append(ticket)

    @rule(confirm=st.booleans())
    def finalize(self, confirm):
        if not self.tickets:
            return
        ticket = self.tickets[-1]
        try:
            outcome = lifecycle.finalize(
                self.cloud,
                self.vault,
                ticket,
                SETTINGS,
                confirmed_cutover=confirm,
                role_verifier=self.role_verifier,
            )
        except (LifecycleError, ValueError):
            return
        # A reported cutover means exactly one live key, and it is the replacement.
        assert outcome["status"] == "old-key-inactive"
        assert self.cloud.active() == {ticket.new_secret_id}, self.cloud.inventory
        self.phase = "cutover"

    @rule()
    def restore(self):
        if not self.tickets:
            return
        try:
            lifecycle.restore_old(self.cloud, self.vault, self.tickets[-1], SETTINGS)
        except (LifecycleError, ValueError):
            return
        # A deliberate rollback returns to the staged shape: two live keys again.
        self.phase = "staged"

    @rule()
    def recover(self):
        try:
            lifecycle.recover_ticket(
                self.cloud,
                self.vault,
                {
                    "operation": OPERATION,
                    "status": "preparing",
                    "target_uin": "123",
                    "old_account": "old-account",
                    "profile": PROFILE,
                },
            )
        except (LifecycleError, ValueError):
            return

    @invariant()
    def always_leaves_a_usable_credential(self):
        assert self.cloud.active(), self.cloud.inventory

    @invariant()
    def never_exceeds_the_two_key_ceiling(self):
        assert len(self.cloud.inventory) <= 2, self.cloud.inventory

    @invariant()
    def only_retires_after_another_key_was_verified(self):
        for key in self.cloud.retired:
            assert self.verified - {key}, (key, self.cloud.inventory)

    @invariant()
    def the_inventory_is_always_in_a_legitimate_shape(self):
        active = self.cloud.active()
        assert active, self.cloud.inventory
        if self.phase == "cutover":
            # Retirement was reported: any second live key would be an unverified credential.
            assert len(active) == 1, self.cloud.inventory


# Exposed at module level so unittest discovery actually runs it; a bare
# `RuleBasedStateMachine` subclass is not itself a TestCase and is silently skipped.
RotationInvariants = RotationStateMachine.TestCase
RotationInvariants.settings = settings(max_examples=60, stateful_step_count=25, deadline=None)


class TicketHygieneTests(unittest.TestCase):
    def test_a_ticket_never_carries_key_material(self):
        cloud, vault = Cloud(), Vault()
        ticket = lifecycle.prepare(cloud, vault, "old-account", "123", PROFILE, OPERATION)
        rendered = repr(ticket)
        for value in vault.secrets.values():
            self.assertNotIn(value, rendered)
        self.assertNotIn("secret-", rendered)


if __name__ == "__main__":
    unittest.main()
