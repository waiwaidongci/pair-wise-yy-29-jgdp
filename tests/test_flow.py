import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import ApiError, CredentialService, Store


class CredentialFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = CredentialService(Store(Path(self.tmp.name) / "test.db"))
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")

    def tearDown(self):
        self.service.store.close()
        self.tmp.cleanup()

    def test_issue_minimal_disclosure_revoke_and_dispute(self):
        template = self.service.create_template("issuer-a", "issuer", "degree", "学位凭证", [{"name": "name", "required": True}, {"name": "degree", "required": True}, {"name": "gpa", "required": False}], 365)
        credential = self.service.issue("issuer-a", "issuer", template["id"], "alice", {"name": "Alice", "degree": "BSc", "gpa": "3.8"}, "issue-1")
        self.assertEqual("active", credential["status"])
        proof = self.service.present("alice", "holder", credential["id"], ["name", "degree"])
        self.assertEqual({"name", "degree"}, set(proof["payload"]["claims"]))
        self.assertNotIn("gpa", proof["token"])
        self.assertEqual("valid_offline", self.service.verify(proof["token"], online=False)["status"])
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self.assertTrue(self.service.verify(proof["token"])["key_retired"])
        self.service.revoke("issuer-a", "issuer", credential["id"], "持有人申请撤销")
        self.assertEqual("revoked", self.service.verify(proof["token"])["status"])
        dispute = self.service.dispute("alice", "holder", credential["id"], "撤销依据错误")
        result = self.service.resolve_dispute("regulator-1", "regulator", dispute["id"], "reject", "撤销依据不足")
        self.assertEqual("active", result["credential_status"])

    def test_permissions_duplicate_and_stale_dispute(self):
        template = self.service.create_template("issuer-a", "issuer", "skill", "技能凭证", [{"name": "skill", "required": True}], 30)
        with self.assertRaises(ApiError):
            self.service.issue("issuer-b", "issuer", template["id"], "bob", {"skill": "Python"}, "x")
        first = self.service.issue("issuer-a", "issuer", template["id"], "bob", {"skill": "Python"}, "same-key")
        second = self.service.issue("issuer-a", "issuer", template["id"], "bob", {"skill": "Python"}, "same-key")
        self.assertEqual(first["id"], second["id"])
        with self.assertRaises(ApiError) as ctx:
            self.service.issue("issuer-a", "issuer", template["id"], "bob", {"skill": "Python"}, "different-key")
        self.assertEqual(409, ctx.exception.status)
        with self.assertRaises(ApiError):
            self.service.dispute("charlie", "holder", first["id"], "冒名争议")


if __name__ == "__main__":
    unittest.main()
