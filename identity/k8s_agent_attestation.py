"""Kubernetes-backed agent mint attestation for service-token issuance.

PLAT-49 defense-in-depth: when the dashboard asks shizuha-id to mint a token
for ``agent_id=X``, shizuha-id independently verifies that the presented
Kubernetes ServiceAccount token belongs to the pod that is allowed to claim X.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import jwt
import requests
from django.conf import settings

AGENT_ID_LABEL = "shizuha.io/agent-id"
TOKEN_REVIEW_API = "/apis/authentication.k8s.io/v1/tokenreviews"
SERVICEACCOUNT_PREFIX = "system:serviceaccount:"
DEFAULT_TOKEN_REVIEW_AUDIENCE = "shizuha-mcp-auth-proxy"

ERR_SA_TOKEN_INVALID = "MINT_SA_TOKEN_INVALID"
ERR_AGENT_ID_LABEL_MISMATCH = "MINT_AGENT_ID_LABEL_MISMATCH"
ERR_NAMESPACE_MISMATCH = "MINT_NAMESPACE_MISMATCH"


class MintAttestationError(Exception):
    """Raised when a service-token mint request fails k8s attestation."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        resolved_namespace: str | None = None,
        pod_name: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.resolved_namespace = resolved_namespace
        self.pod_name = pod_name


@dataclass(frozen=True)
class AgentPodAttestation:
    """Resolved, independently verified pod identity for an agent mint."""

    agent_id: str
    namespace: str
    pod_name: str
    issuer: str
    subject: str
    pod_label_value: str


def verify_agent_service_account_token(
    *,
    agent_id: str,
    service_account_token: str,
) -> AgentPodAttestation:
    """Verify a mint request's SA token against k8s TokenReview + pod labels.

    Failure codes are intentionally distinguishable for PLAT-49 while avoiding
    deeper reasoning leaks for malformed/expired/forged tokens.
    """
    agent_id = (agent_id or "").strip()
    service_account_token = (service_account_token or "").strip()
    if not agent_id or not service_account_token:
        raise MintAttestationError(ERR_SA_TOKEN_INVALID, "agent_id and service_account_token are required")

    review = _token_review(service_account_token)
    status = review.get("status") if isinstance(review, dict) else None
    if not isinstance(status, dict) or not status.get("authenticated"):
        raise MintAttestationError(ERR_SA_TOKEN_INVALID, "service account token was not authenticated")
    if _token_review_audience() not in (status.get("audiences") or []):
        raise MintAttestationError(ERR_SA_TOKEN_INVALID, "service account token audience was not accepted")

    payload = _decode_unverified_payload(service_account_token)
    subject = str(status.get("user", {}).get("username") or payload.get("sub") or "")
    issuer = str(payload.get("iss") or "")
    namespace, pod_name = _resolve_pod_identity(status, payload, subject)
    if not namespace or not pod_name or not subject.startswith(SERVICEACCOUNT_PREFIX):
        raise MintAttestationError(ERR_SA_TOKEN_INVALID, "could not resolve pod identity from token review")

    pod = _get_pod(namespace, pod_name)
    label_value = str(
        ((pod.get("metadata") or {}).get("labels") or {}).get(AGENT_ID_LABEL) or ""
    )
    if label_value != agent_id:
        raise MintAttestationError(
            ERR_AGENT_ID_LABEL_MISMATCH,
            "pod agent-id label does not match requested agent_id",
            resolved_namespace=namespace,
            pod_name=pod_name,
        )

    expected_namespace = f"rt-{agent_id}"
    if namespace != expected_namespace:
        raise MintAttestationError(
            ERR_NAMESPACE_MISMATCH,
            "pod namespace does not match agent runtime namespace",
            resolved_namespace=namespace,
            pod_name=pod_name,
        )

    return AgentPodAttestation(
        agent_id=agent_id,
        namespace=namespace,
        pod_name=pod_name,
        issuer=issuer,
        subject=subject,
        pod_label_value=label_value,
    )


def _token_review(token: str) -> dict[str, Any]:
    body = {
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenReview",
        "spec": {"token": token, "audiences": [_token_review_audience()]},
    }
    return _k8s_request("POST", TOKEN_REVIEW_API, json=body)


def _token_review_audience() -> str:
    return str(
        getattr(settings, "KUBERNETES_TOKEN_REVIEW_AUDIENCE", "")
        or os.environ.get("KUBERNETES_TOKEN_REVIEW_AUDIENCE", "")
        or DEFAULT_TOKEN_REVIEW_AUDIENCE
    )


def _get_pod(namespace: str, pod_name: str) -> dict[str, Any]:
    try:
        return _k8s_request("GET", f"/api/v1/namespaces/{namespace}/pods/{pod_name}")
    except MintAttestationError:
        raise MintAttestationError(
            ERR_AGENT_ID_LABEL_MISMATCH,
            "pod could not be fetched for agent-id label verification",
            resolved_namespace=namespace,
            pod_name=pod_name,
        )


def _k8s_request(method: str, path: str, **kwargs) -> dict[str, Any]:
    url = f"{_k8s_base_url()}{path}"
    timeout = float(getattr(settings, "K8S_API_TIMEOUT_SECONDS", 3.0))
    headers = kwargs.pop("headers", {}) or {}
    headers.setdefault("Authorization", f"Bearer {_reviewer_token()}")
    verify = _ca_bundle_path()
    try:
        resp = requests.request(method, url, headers=headers, timeout=timeout, verify=verify, **kwargs)
    except requests.RequestException as exc:
        raise MintAttestationError(ERR_SA_TOKEN_INVALID, f"kubernetes API request failed: {exc}") from exc
    if resp.status_code < 200 or resp.status_code >= 300:
        raise MintAttestationError(ERR_SA_TOKEN_INVALID, f"kubernetes API returned HTTP {resp.status_code}")
    try:
        data = resp.json()
    except ValueError as exc:
        raise MintAttestationError(ERR_SA_TOKEN_INVALID, "kubernetes API returned invalid JSON") from exc
    return data if isinstance(data, dict) else {}


def _k8s_base_url() -> str:
    configured = getattr(settings, "KUBERNETES_API_URL", "") or os.environ.get("KUBERNETES_API_URL", "")
    if configured:
        return configured.rstrip("/")
    host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS") or os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    return f"https://{host}:{port}"


def _reviewer_token() -> str:
    configured = getattr(settings, "KUBERNETES_REVIEWER_TOKEN", "") or os.environ.get("KUBERNETES_REVIEWER_TOKEN", "")
    if configured:
        return configured
    token_path = getattr(
        settings,
        "KUBERNETES_SERVICEACCOUNT_TOKEN_PATH",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
    )
    try:
        with open(token_path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError as exc:
        raise MintAttestationError(ERR_SA_TOKEN_INVALID, "kubernetes reviewer token unavailable") from exc


def _ca_bundle_path() -> str | bool:
    ca_path = getattr(
        settings,
        "KUBERNETES_CA_CERT_PATH",
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    )
    return ca_path if ca_path and os.path.exists(ca_path) else True


def _decode_unverified_payload(token: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
    except Exception as exc:  # noqa: BLE001 - never leak JWT parser detail
        raise MintAttestationError(ERR_SA_TOKEN_INVALID, "service account token could not be parsed") from exc
    return payload if isinstance(payload, dict) else {}


def _resolve_pod_identity(status: dict[str, Any], payload: dict[str, Any], subject: str) -> tuple[str, str]:
    extra = (status.get("user") or {}).get("extra") or {}
    namespace = _first_extra(extra, "authentication.kubernetes.io/namespace")
    pod_name = _first_extra(extra, "authentication.kubernetes.io/pod-name")

    k8s_claims = payload.get("kubernetes.io") if isinstance(payload.get("kubernetes.io"), dict) else {}
    namespace = namespace or str(k8s_claims.get("namespace") or "")
    pod_claim = k8s_claims.get("pod") if isinstance(k8s_claims.get("pod"), dict) else {}
    pod_name = pod_name or str(pod_claim.get("name") or "")

    if not namespace and subject.startswith(SERVICEACCOUNT_PREFIX):
        parts = subject.split(":", 3)
        if len(parts) == 4:
            namespace = parts[2]

    return namespace, pod_name


def _first_extra(extra: dict[str, Any], key: str) -> str:
    value = extra.get(key)
    if isinstance(value, list) and value:
        return str(value[0])
    return str(value or "")
