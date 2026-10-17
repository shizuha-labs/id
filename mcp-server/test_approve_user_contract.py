"""
Regression test for ID-38: id_admin_approve_user sent the wrong payload.

The approve endpoint's UserApprovalReviewSerializer requires
`status` ('approved'|'denied') + optional `review_note`. The MCP tool sent the
legacy `{approved: bool, reason}`, which the serializer rejected with HTTP 400
("status: This field is required"), so no agent could approve a pending user.
These tests pin the outgoing payload to the field names the serializer accepts.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
os.environ.setdefault("SHIZUHA_ID_URL", "http://localhost:8001/api")

import id_server  # noqa: E402


class ApproveUserContractTests(unittest.TestCase):
    def _call(self, **kwargs):
        """Invoke the approve tool with base.api_request mocked; return posted data."""
        with mock.patch.object(id_server.base, "api_request", return_value={"ok": True}) as api:
            id_server.admin_approve_user(**kwargs)
        args, kw = api.call_args
        # api_request(method, endpoint, ..., data=...)
        self.assertEqual(args[0], "PATCH")
        self.assertEqual(args[1], f"/auth/admin/users/{kwargs['user_id']}/approve/")
        return kw.get("data") or (args[3] if len(args) > 3 else None)

    def test_approve_sends_status_approved(self):
        data = self._call(user_id=253, approved=True, reason="KOT-26 QA account")
        self.assertEqual(data.get("status"), "approved")
        self.assertEqual(data.get("review_note"), "KOT-26 QA account")
        # The legacy fields the serializer rejects must be gone.
        self.assertNotIn("approved", data)
        self.assertNotIn("reason", data)

    def test_reject_sends_status_denied(self):
        data = self._call(user_id=99, approved=False, reason="spam")
        self.assertEqual(data.get("status"), "denied")
        self.assertEqual(data.get("review_note"), "spam")

    def test_no_reason_omits_review_note(self):
        data = self._call(user_id=7, approved=True)
        self.assertEqual(data.get("status"), "approved")
        self.assertNotIn("review_note", data)


if __name__ == "__main__":
    unittest.main()
