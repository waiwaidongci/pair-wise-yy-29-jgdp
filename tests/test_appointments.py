import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import ApiError, CredentialService, Store, iso, now


class RevocationAppointmentTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = CredentialService(Store(Path(self.tmp.name) / "test.db"))
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self.template = self.service.create_template(
            "issuer-a", "issuer", "pass", "通行凭证", [{"name": "name", "required": True}], 30
        )

    def tearDown(self):
        self.service.store.close()
        self.tmp.cleanup()

    def _issue(self, holder="alice", key="k-1"):
        return self.service.issue(
            "issuer-a", "issuer", self.template["id"], holder, {"name": holder.title()}, key
        )

    def _token(self, credential, holder="alice"):
        return self.service.present(holder, "holder", credential["id"], ["name"])["token"]

    def test_scheduled_revocation_keeps_credential_valid_until_effective_time(self):
        credential = self._issue()
        token = self._token(credential)
        evening = now() + timedelta(hours=8)

        appointment = self.service.revoke(
            "issuer-a", "issuer", credential["id"], "夜间统一撤证", iso(evening)
        )
        self.assertEqual("pending", appointment["status"])
        self.assertEqual(iso(evening), appointment["effective_at"])
        # 凭证状态白天不变，同一持有人不能再被签一张。
        self.assertEqual("active", self.service._row("credentials", credential["id"])["status"])

        before = self.service.verify(token, at=iso(now() + timedelta(hours=1)))
        self.assertTrue(before["valid"])
        self.assertEqual("valid_until_revocation", before["status"])
        self.assertEqual(iso(evening), before["revocation_starts_at"])
        self.assertEqual("夜间统一撤证", before["revocation_reason"])

        with self.assertRaises(ApiError) as ctx:
            self._issue(key="k-2")
        self.assertEqual(409, ctx.exception.status)

    def test_only_one_pending_appointment_per_credential(self):
        credential = self._issue()
        self.service.revoke("issuer-a", "issuer", credential["id"], "原因一", iso(now() + timedelta(hours=2)))
        with self.assertRaises(ApiError) as ctx:
            self.service.revoke("issuer-a", "issuer", credential["id"], "原因二", iso(now() + timedelta(hours=4)))
        self.assertEqual(409, ctx.exception.status)

    def test_withdraw_before_effective_restores_normal_flow(self):
        credential = self._issue()
        token = self._token(credential)
        appointment = self.service.revoke(
            "issuer-a", "issuer", credential["id"], "误操作", iso(now() + timedelta(hours=3))
        )
        withdrawn = self.service.withdraw_appointment("issuer-a", "issuer", appointment["id"])
        self.assertEqual("withdrawn", withdrawn["status"])
        self.assertEqual("issuer-a", withdrawn["withdrawn_by"])

        result = self.service.verify(token)
        self.assertTrue(result["valid"])
        self.assertEqual("valid", result["status"])
        # 撤回后可以重新登记预约。
        again = self.service.revoke(
            "issuer-a", "issuer", credential["id"], "确需撤销", iso(now() + timedelta(hours=5))
        )
        self.assertEqual("pending", again["status"])

    def test_cannot_withdraw_after_due(self):
        credential = self._issue()
        appointment = self.service.revoke(
            "issuer-a", "issuer", credential["id"], "到期撤证", iso(now() + timedelta(hours=1))
        )
        self.service.settle_due(now() + timedelta(hours=2))
        with self.assertRaises(ApiError) as ctx:
            self.service.withdraw_appointment("issuer-a", "issuer", appointment["id"])
        self.assertEqual(409, ctx.exception.status)

    def test_settling_at_due_time_revokes_and_allows_reissue(self):
        credential = self._issue()
        token = self._token(credential)
        evening = now() + timedelta(hours=8)
        self.service.revoke("issuer-a", "issuer", credential["id"], "夜间统一撤证", iso(evening))

        # 显式按生效后的时刻核验：返回撤销结论。
        after = self.service.verify(token, at=iso(evening + timedelta(minutes=1)))
        self.assertFalse(after["valid"])
        self.assertEqual("revoked", after["status"])
        self.assertEqual("夜间统一撤证", after["reason"])

        # 结算（到点处理）后凭证才真正写入 revoked。
        self.service.settle_due(evening + timedelta(minutes=1))
        self.assertEqual("revoked", self.service._row("credentials", credential["id"])["status"])
        self.assertEqual(iso(evening), self.service._row("credentials", credential["id"])["revocation_effective_at"])
        # 撤销生效后，同一持有人可以被签发新凭证。
        new_credential = self._issue(key="k-new")
        self.assertNotEqual(credential["id"], new_credential["id"])
        self.assertEqual("active", new_credential["status"])

    def test_immediate_revocation_still_works(self):
        credential = self._issue(holder="bob", key="b-1")
        token = self._token(credential, holder="bob")
        appointment = self.service.revoke("issuer-a", "issuer", credential["id"], "立即撤销")
        self.assertEqual("effective", appointment["status"])
        self.assertEqual("revoked", self.service.verify(token)["status"])

    def test_list_appointments_grouped_by_status(self):
        kept = self._issue(holder="c1", key="c1")
        withdrawn_one = self._issue(holder="c2", key="c2")
        effective_one = self._issue(holder="c3", key="c3")

        self.service.revoke("issuer-a", "issuer", kept["id"], "待生效", iso(now() + timedelta(hours=3)))
        w = self.service.revoke("issuer-a", "issuer", withdrawn_one["id"], "将撤回", iso(now() + timedelta(hours=3)))
        self.service.withdraw_appointment("issuer-a", "issuer", w["id"])
        self.service.revoke("issuer-a", "issuer", effective_one["id"], "立即生效")

        pending = self.service.list_appointments("pending")["revocation_appointments"]
        withdrawn = self.service.list_appointments("withdrawn")["revocation_appointments"]
        effective = self.service.list_appointments("effective")["revocation_appointments"]
        self.assertEqual([kept["id"]], [a["credential_id"] for a in pending])
        self.assertEqual([withdrawn_one["id"]], [a["credential_id"] for a in withdrawn])
        self.assertEqual([effective_one["id"]], [a["credential_id"] for a in effective])

        all_records = self.service.list_appointments()["revocation_appointments"]
        self.assertEqual(3, len(all_records))
        # 展示记录带持有人信息，且与凭证写入解耦。
        self.assertEqual("c1", pending[0]["holder_id"])

    def test_other_issuer_cannot_schedule_or_withdraw(self):
        credential = self._issue()
        with self.assertRaises(ApiError):
            self.service.revoke("issuer-b", "issuer", credential["id"], "越权", iso(now() + timedelta(hours=1)))
        appointment = self.service.revoke(
            "issuer-a", "issuer", credential["id"], "本机构", iso(now() + timedelta(hours=1))
        )
        with self.assertRaises(ApiError):
            self.service.withdraw_appointment("issuer-b", "issuer", appointment["id"])


if __name__ == "__main__":
    unittest.main()
