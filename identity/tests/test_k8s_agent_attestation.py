from unittest import mock

import jwt
from types import SimpleNamespace

from django.test import SimpleTestCase, override_settings
from rest_framework.test import APIRequestFactory, force_authenticate

from identity.k8s_agent_attestation import (
    ERR_AGENT_ID_LABEL_MISMATCH,
    ERR_NAMESPACE_MISMATCH,
    ERR_SA_TOKEN_INVALID,
    MintAttestationError,
    verify_agent_service_account_token,
)
from identity.audit import emit_mint_attestation_rejection
from identity.views import ServiceTokenView

_projection_patcher = None


def setUpModule():
    global _projection_patcher
    _projection_patcher = mock.patch(
        'identity.views._fetch_membership_projection',
        return_value=({}, [], {}),
    )
    _projection_patcher.start()


def tearDownModule():
    _projection_patcher.stop()


def _sa_token(namespace="rt-ryo", pod_name="ryo-0", subject_namespace=None):
    subject_namespace = subject_namespace or namespace
    return jwt.encode(
        {
            "iss": "https://kubernetes.default.svc",
            "sub": f"system:serviceaccount:{subject_namespace}:default",
            "kubernetes.io": {
                "namespace": namespace,
                "pod": {"name": pod_name, "uid": "pod-uid"},
                "serviceaccount": {"name": "default", "uid": "sa-uid"},
            },
        },
        "test-secret",
        algorithm="HS256",
    )


class _Resp:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


def _token_review(authenticated=True, namespace="rt-ryo", pod_name="ryo-0", audiences=None):
    return {
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenReview",
        "status": {
            "authenticated": authenticated,
            "audiences": ["shizuha-mcp-auth-proxy"] if audiences is None else audiences,
            "user": {
                "username": f"system:serviceaccount:{namespace}:default",
                "extra": {
                    "authentication.kubernetes.io/namespace": [namespace],
                    "authentication.kubernetes.io/pod-name": [pod_name],
                },
            },
        },
    }


def _pod(label="ryo"):
    labels = {} if label is None else {"shizuha.io/agent-id": label}
    return {"metadata": {"labels": labels}}


@override_settings(KUBERNETES_REVIEWER_TOKEN="reviewer-token", KUBERNETES_API_URL="https://k8s.test")
class AgentMintAttestationTests(SimpleTestCase):
    def _mock_k8s(self, token_review_payload, pod_payload=None):
        calls = []

        def fake_request(method, url, **kwargs):
            calls.append((method, url, kwargs))
            if method == "POST":
                return _Resp(token_review_payload)
            return _Resp(pod_payload if pod_payload is not None else _pod())

        return calls, mock.patch("identity.k8s_agent_attestation.requests.request", side_effect=fake_request)

    def test_matching_token_label_and_namespace_succeeds(self):
        calls, patcher = self._mock_k8s(_token_review(), _pod("ryo"))
        with patcher:
            attestation = verify_agent_service_account_token(
                agent_id="ryo",
                service_account_token=_sa_token(),
            )
        self.assertEqual(attestation.namespace, "rt-ryo")
        self.assertEqual(attestation.pod_name, "ryo-0")
        self.assertEqual(attestation.pod_label_value, "ryo")
        self.assertEqual([c[0] for c in calls], ["POST", "GET"])
        self.assertEqual(
            calls[0][2]["json"]["spec"],
            {"token": _sa_token(), "audiences": ["shizuha-mcp-auth-proxy"]},
        )

    def test_tokenreview_without_required_audience_is_sa_token_invalid(self):
        calls, patcher = self._mock_k8s(_token_review(audiences=["other-audience"]))
        with patcher, self.assertRaises(MintAttestationError) as ctx:
            verify_agent_service_account_token(agent_id="ryo", service_account_token=_sa_token())
        self.assertEqual(ctx.exception.code, ERR_SA_TOKEN_INVALID)
        self.assertEqual([c[0] for c in calls], ["POST"])

    def test_unauthenticated_tokenreview_is_sa_token_invalid(self):
        calls, patcher = self._mock_k8s(_token_review(authenticated=False))
        with patcher, self.assertRaises(MintAttestationError) as ctx:
            verify_agent_service_account_token(agent_id="ryo", service_account_token=_sa_token())
        self.assertEqual(ctx.exception.code, ERR_SA_TOKEN_INVALID)
        self.assertEqual([c[0] for c in calls], ["POST"])

    def test_wrong_presented_agent_id_is_label_mismatch_even_if_namespace_would_also_fail(self):
        calls, patcher = self._mock_k8s(_token_review(namespace="rt-ryo"), _pod("ryo"))
        with patcher, self.assertRaises(MintAttestationError) as ctx:
            verify_agent_service_account_token(agent_id="sora", service_account_token=_sa_token(namespace="rt-ryo"))
        self.assertEqual(ctx.exception.code, ERR_AGENT_ID_LABEL_MISMATCH)
        self.assertEqual(ctx.exception.resolved_namespace, "rt-ryo")
        self.assertEqual([c[0] for c in calls], ["POST", "GET"])

    def test_wrong_namespace_is_distinguishable_after_label_matches(self):
        calls, patcher = self._mock_k8s(_token_review(namespace="wrong-ns"), _pod("ryo"))
        with patcher, self.assertRaises(MintAttestationError) as ctx:
            verify_agent_service_account_token(
                agent_id="ryo",
                service_account_token=_sa_token(namespace="wrong-ns", subject_namespace="wrong-ns"),
            )
        self.assertEqual(ctx.exception.code, ERR_NAMESPACE_MISMATCH)
        self.assertEqual(ctx.exception.resolved_namespace, "wrong-ns")
        self.assertEqual([c[0] for c in calls], ["POST", "GET"])

    def test_missing_agent_id_label_is_label_mismatch(self):
        calls, patcher = self._mock_k8s(_token_review(), _pod(label=None))
        with patcher, self.assertRaises(MintAttestationError) as ctx:
            verify_agent_service_account_token(agent_id="ryo", service_account_token=_sa_token())
        self.assertEqual(ctx.exception.code, ERR_AGENT_ID_LABEL_MISMATCH)
        self.assertEqual([c[0] for c in calls], ["POST", "GET"])


class _FakeAccessToken:
    def set_exp(self, **kwargs):
        return None

    def __str__(self):
        return "access-token"


class _FakeRefreshToken(dict):
    def __init__(self):
        super().__init__()
        self._access = _FakeAccessToken()

    @property
    def access_token(self):
        return self._access

    def set_exp(self, **kwargs):
        return None

    def __str__(self):
        return "refresh-token"


class ServiceTokenAgentMintViewTests(SimpleTestCase):
    def setUp(self):
        self.admin = SimpleNamespace(is_superuser=True, is_authenticated=True, email="admin@shizuha.com")
        self.agent = SimpleNamespace(
            id=42,
            username="ryo",
            email="ryo@shizuha.com",
            is_active=True,
            is_staff=True,
            is_superuser=False,
            profile=SimpleNamespace(account_type="agent"),
        )
        self.factory = APIRequestFactory()

    @mock.patch("identity.views.Tool.objects.filter")
    @mock.patch("identity.views._populate_standard_claims")
    @mock.patch("identity.views.RefreshToken.for_user", return_value=_FakeRefreshToken())
    @mock.patch("identity.views.User.objects.get")
    @mock.patch("identity.views.verify_agent_service_account_token")
    def test_agent_id_mint_invokes_k8s_attestation_and_mints_for_agent_username(
        self, verify_mock, user_get_mock, refresh_mock, populate_mock, tool_filter_mock
    ):
        user_get_mock.return_value = self.agent
        tool_filter_mock.return_value.values_list.return_value = ["id"]
        request = self.factory.post(
            "/api/auth/service-token/",
            {"agent_id": "ryo", "service_account_token": "sat", "correlation_id": "corr-1"},
            format="json",
        )
        force_authenticate(request, user=self.admin)
        response = ServiceTokenView.as_view()(request)
        self.assertEqual(response.status_code, 200)
        verify_mock.assert_called_once_with(agent_id="ryo", service_account_token="sat")
        user_get_mock.assert_called_once_with(username__iexact="ryo")
        self.assertEqual(response.data["user"]["username"], "ryo")
        self.assertEqual(response.data["access"], "access-token")


    @mock.patch("identity.views.verify_agent_service_account_token")
    def test_agent_id_and_email_are_mutually_exclusive(self, verify_mock):
        request = self.factory.post(
            "/api/auth/service-token/",
            {"agent_id": "ryo", "email": "victim@shizuha.com", "service_account_token": "sat"},
            format="json",
        )
        force_authenticate(request, user=self.admin)
        response = ServiceTokenView.as_view()(request)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["error"], "email and agent_id are mutually exclusive")
        verify_mock.assert_not_called()


    @mock.patch("identity.views.RefreshToken.for_user")
    @mock.patch("identity.views.User.objects.get")
    @mock.patch("identity.views.verify_agent_service_account_token")
    def test_agent_id_mint_rejects_non_agent_account(self, verify_mock, user_get_mock, refresh_mock):
        human_user = SimpleNamespace(
            id=99,
            username="ryo",
            email="ryo@shizuha.com",
            is_active=True,
            is_staff=False,
            is_superuser=False,
            profile=SimpleNamespace(account_type="human"),
        )
        user_get_mock.return_value = human_user
        request = self.factory.post(
            "/api/auth/service-token/",
            {"agent_id": "ryo", "service_account_token": "sat"},
            format="json",
        )
        force_authenticate(request, user=self.admin)
        response = ServiceTokenView.as_view()(request)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data["error"], "agent_id mints require an agent account")
        verify_mock.assert_called_once_with(agent_id="ryo", service_account_token="sat")
        refresh_mock.assert_not_called()

    @mock.patch("identity.views.emit_mint_attestation_rejection")
    @mock.patch("identity.views.verify_agent_service_account_token")
    def test_agent_id_mint_rejects_with_distinguishable_error_code_and_audit(self, verify_mock, audit_mock):
        verify_mock.side_effect = MintAttestationError(
            ERR_NAMESPACE_MISMATCH,
            "namespace mismatch",
            resolved_namespace="wrong-ns",
            pod_name="ryo-0",
        )
        request = self.factory.post(
            "/api/auth/service-token/",
            {"agent_id": "ryo", "service_account_token": "sat", "correlation_id": "corr-2"},
            format="json",
        )
        force_authenticate(request, user=self.admin)
        response = ServiceTokenView.as_view()(request)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data["error"], ERR_NAMESPACE_MISMATCH)
        audit_mock.assert_called_once_with(
            reason=ERR_NAMESPACE_MISMATCH,
            presented_agent_id="ryo",
            resolved_namespace="wrong-ns",
            pod_name="ryo-0",
            correlation_id="corr-2",
        )


class MintAttestationAuditTests(SimpleTestCase):
    @mock.patch("identity.audit.timezone.now")
    @mock.patch("identity.audit.logger.warning")
    def test_rejection_audit_payload_uses_mint_rejected_schema_with_timestamp(self, warning_mock, now_mock):
        now_mock.return_value.isoformat.return_value = "2026-06-04T17:40:00+00:00"
        emit_mint_attestation_rejection(
            reason=ERR_NAMESPACE_MISMATCH,
            presented_agent_id="ryo",
            resolved_namespace="wrong-ns",
            pod_name="ryo-0",
            correlation_id="corr-3",
        )
        payload = warning_mock.call_args.kwargs["extra"]["audit_signal"]
        self.assertEqual(payload["event_type"], "mint-rejected")
        self.assertEqual(payload["reason"], ERR_NAMESPACE_MISMATCH)
        self.assertEqual(payload["failure_class"], ERR_NAMESPACE_MISMATCH)
        self.assertEqual(payload["presented_agent_id"], "ryo")
        self.assertEqual(payload["claimed_agent_id"], "ryo")
        self.assertEqual(payload["resolved_namespace"], "wrong-ns")
        self.assertEqual(payload["verified_namespace"], "wrong-ns")
        self.assertEqual(payload["pod_name"], "ryo-0")
        self.assertEqual(payload["verified_pod_name"], "ryo-0")
        self.assertEqual(payload["correlation_id"], "corr-3")
        self.assertEqual(payload["timestamp"], "2026-06-04T17:40:00+00:00")
