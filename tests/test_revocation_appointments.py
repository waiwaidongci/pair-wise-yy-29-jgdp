import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import ApiError, CredentialService, Store, iso, now


class ScheduledRevocationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = CredentialService(Store(Path(self.tmp.name) / "test.db"))
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self.template = self.service.create_template(
            "issuer-a", "issuer", "degree", "学位凭证",
            [{"name": "name", "required": True}, {"name": "degree", "required": True}], 365,
        )
        self.credential = self.service.issue(
            "issuer-a", "issuer", self.template["id"], "alice",
            {"name": "Alice", "degree": "BSc"}, "issue-1",
        )
        self.proof = self.service.present("alice", "holder", self.credential["id"], None)
        self.effective = now() + timedelta(hours=12)

    def tearDown(self):
        self.service.store.close()
        self.tmp.cleanup()

    def _schedule(self, **overrides):
        params = {"effective_at": iso(self.effective), "reason": "夜间批量撤证"}
        params.update(overrides)
        return self.service.scheduler.schedule(
            "issuer-a", "issuer", self.credential["id"], params["reason"], params["effective_at"]
        )

    def test_before_effective_time_verification_keeps_original_conclusion(self):
        self._schedule()
        before = self.service.verify(self.proof["token"], at=iso(now() + timedelta(hours=1)))
        self.assertTrue(before["valid"])
        self.assertEqual("valid_until_revocation", before["status"])
        self.assertEqual(iso(self.effective), before["revocation_starts_at"])
        self.assertEqual("夜间批量撤证", before["revocation_reason"])
        credential = self.service._row("credentials", self.credential["id"])
        self.assertEqual("active", credential["status"])

    def test_after_effective_time_revoked_and_new_issue_allowed(self):
        self._schedule()
        # Time arrives: materialization flips the credential.
        applied = self.service.scheduler.apply_due(now() + timedelta(hours=13))
        self.assertEqual(1, len(applied))
        self.assertEqual("已生效", applied[0]["status_label"])
        after = self.service.verify(self.proof["token"], at=iso(now() + timedelta(hours=13)))
        self.assertFalse(after["valid"])
        self.assertEqual("revoked", after["status"])
        self.assertEqual("夜间批量撤证", after["reason"])
        # Same holder can be issued a new credential once the slot is freed.
        new_credential = self.service.issue(
            "issuer-a", "issuer", self.template["id"], "alice",
            {"name": "Alice", "degree": "MSc"}, "issue-2",
        )
        self.assertNotEqual(self.credential["id"], new_credential["id"])

    def test_only_one_open_appointment_per_credential(self):
        self._schedule()
        with self.assertRaises(ApiError) as ctx:
            self._schedule(reason="另一次预约")
        self.assertEqual(409, ctx.exception.status)
        # Direct revocation is also blocked while an appointment is pending.
        with self.assertRaises(ApiError) as ctx:
            self.service.revoke("issuer-a", "issuer", self.credential["id"], "立即撤销")
        self.assertEqual(409, ctx.exception.status)

    def test_withdraw_before_effective_restores_normal_verification(self):
        appointment = self._schedule()
        withdrawn = self.service.scheduler.withdraw("issuer-a", "issuer", appointment["id"])
        self.assertEqual("withdrawn", withdrawn["status"])
        self.assertEqual("已撤回", withdrawn["status_label"])
        result = self.service.verify(self.proof["token"], at=iso(now() + timedelta(hours=1)))
        self.assertTrue(result["valid"])
        self.assertEqual("valid", result["status"])
        # New appointment can be registered after withdrawal.
        again = self._schedule()
        self.assertEqual("pending", again["status"])

    def test_withdraw_after_effective_rejected_and_revocation_stands(self):
        appointment = self._schedule()
        self.service.scheduler.apply_due(now() + timedelta(hours=13))
        with self.assertRaises(ApiError):
            self.service.scheduler.withdraw("issuer-a", "issuer", appointment["id"])
        result = self.service.verify(self.proof["token"], at=iso(now() + timedelta(hours=14)))
        self.assertFalse(result["valid"])
        self.assertEqual("revoked", result["status"])

    def test_list_shows_pending_withdrawn_and_effective(self):
        withdrawn_one = self._schedule(effective_at=iso(now() + timedelta(hours=6)))
        self.service.scheduler.withdraw("issuer-a", "issuer", withdrawn_one["id"])
        self._schedule(effective_at=iso(now() + timedelta(hours=12)))
        other = self.service.issue(
            "issuer-a", "issuer", self.template["id"], "bob",
            {"name": "Bob", "degree": "BA"}, "issue-bob",
        )
        pending_one = self.service.scheduler.schedule(
            "issuer-a", "issuer", other["id"], "bob 的夜间撤证", iso(now() + timedelta(hours=24))
        )
        self.service.scheduler.apply_due(now() + timedelta(hours=13))
        views = self.service.appointments()
        statuses = {v["status"] for v in views}
        self.assertEqual({"pending", "withdrawn", "effective"}, statuses)
        self.assertEqual(pending_one["id"], next(v["id"] for v in views if v["status"] == "pending"))
        self.assertEqual(len(views), len(self.service.state()["revocation_appointments"]))

    def test_schedule_validation(self):
        with self.assertRaises(ApiError) as ctx:
            self.service.scheduler.schedule("issuer-a", "issuer", self.credential["id"], "x", iso(now() - timedelta(minutes=1)))
        self.assertEqual(400, ctx.exception.status)
        with self.assertRaises(ApiError) as ctx:
            self.service.scheduler.schedule("issuer-a", "issuer", self.credential["id"], "", iso(now() + timedelta(hours=1)))
        self.assertEqual(400, ctx.exception.status)
        with self.assertRaises(ApiError):
            self.service.scheduler.schedule("issuer-b", "issuer", self.credential["id"], "x", iso(now() + timedelta(hours=1)))

    def test_historical_check_before_effective_still_valid_even_after_materialization(self):
        self._schedule()
        self.service.scheduler.apply_due(now() + timedelta(hours=13))
        # A past verification moment (e.g. daytime audit replayed) is judged at that moment.
        historical = self.service.verify(self.proof["token"], at=iso(now() + timedelta(hours=1)))
        self.assertTrue(historical["valid"])
        self.assertEqual("valid_until_revocation", historical["status"])


if __name__ == "__main__":
    unittest.main()
