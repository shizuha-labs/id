#!/usr/bin/env python3
"""Read-only live probe for the Shizuha ID user-lookup boundary (ID-60).

The accepted ADR-0028 contract is stronger than field-scoping at the public
edge: every ingress-borne ``/api/internal/users/*`` request is rejected by the
ingress guard with the same 404 body before user lookup.  Trusted ClusterIP
callers retain the full service-to-service response required by Pulse and
Connect.  This probe checks both sides without creating or mutating users.

Pass a short-lived ordinary-user bearer token through ID_PROBE_BEARER_TOKEN to
also exercise the authenticated cross-user and non-staff admin lanes.  The
token is never printed.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Mapping


PRIVATE_FIELDS = frozenset({
    "email",
    "first_name",
    "last_name",
    "is_staff",
    "is_superuser",
    "is_active",
    "date_joined",
    "approval_status",
    "lifecycle_state",
    "profile",
    "enabled_tools",
    "service_grants",
})
GUARD_BODY = b'{"error": "Not found"}'


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    content_type: str


def request(
    url: str,
    *,
    headers: Mapping[str, str] | None,
    timeout: float,
    context: ssl.SSLContext,
) -> Response:
    req = urllib.request.Request(url, headers=dict(headers or {}), method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            return Response(resp.status, resp.read(), resp.headers.get("Content-Type", ""))
    except urllib.error.HTTPError as exc:
        return Response(exc.code, exc.read(), exc.headers.get("Content-Type", ""))


def assert_no_private_keys(body: bytes, label: str) -> None:
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return

    def walk(value: object) -> set[str]:
        if isinstance(value, dict):
            keys = {str(key) for key in value}
            for child in value.values():
                keys.update(walk(child))
            return keys
        if isinstance(value, list):
            keys: set[str] = set()
            for child in value:
                keys.update(walk(child))
            return keys
        return set()

    leaked = sorted(PRIVATE_FIELDS & walk(payload))
    if leaked:
        raise AssertionError(f"{label}: private response keys present: {leaked}")


def check_guard_pair(
    *,
    base_url: str,
    label: str,
    existing_path: str,
    missing_path: str,
    headers: Mapping[str, str] | None,
    timeout: float,
    context: ssl.SSLContext,
) -> None:
    existing = request(
        base_url + existing_path,
        headers=headers,
        timeout=timeout,
        context=context,
    )
    missing = request(
        base_url + missing_path,
        headers=headers,
        timeout=timeout,
        context=context,
    )
    if existing.status != 404 or missing.status != 404:
        raise AssertionError(
            f"{label}: expected 404/404, got {existing.status}/{missing.status}"
        )
    if existing.body != GUARD_BODY or missing.body != GUARD_BODY:
        raise AssertionError(f"{label}: response did not match the ingress-guard body")
    if existing.body != missing.body or existing.content_type != missing.content_type:
        raise AssertionError(f"{label}: existing and missing users are distinguishable")
    assert_no_private_keys(existing.body, label)
    print(f"PASS {label}: status=404 bytes={len(existing.body)} uniform-existing/missing")


def expect_status(
    *,
    base_url: str,
    path: str,
    label: str,
    expected: int,
    headers: Mapping[str, str] | None,
    timeout: float,
    context: ssl.SSLContext,
) -> None:
    response = request(
        base_url + path,
        headers=headers,
        timeout=timeout,
        context=context,
    )
    if response.status != expected:
        raise AssertionError(f"{label}: expected {expected}, got {response.status}")
    assert_no_private_keys(response.body, label)
    print(f"PASS {label}: status={response.status} bytes={len(response.body)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--external-base-url", default="https://shizuha.com/id")
    parser.add_argument("--internal-base-url", default="")
    parser.add_argument("--target-user-id", required=True)
    parser.add_argument("--target-username", required=True)
    parser.add_argument("--target-email", required=True)
    parser.add_argument("--bearer-env", default="ID_PROBE_BEARER_TOKEN")
    parser.add_argument("--require-bearer", action="store_true")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--insecure", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    external = args.external_base_url.rstrip("/")
    internal = args.internal_base_url.rstrip("/")
    token = os.environ.get(args.bearer_env, "").strip()
    if args.require_bearer and not token:
        raise AssertionError(f"required bearer environment variable {args.bearer_env} is empty")

    context = ssl.create_default_context()
    if args.insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    quoted_username = urllib.parse.quote(args.target_username, safe="")
    quoted_email = urllib.parse.quote(args.target_email, safe="")
    pairs = [
        (
            "by-id",
            f"/api/internal/users/{args.target_user_id}/",
            "/api/internal/users/2147483647/",
        ),
        (
            "by-username",
            f"/api/internal/users/by-username/?username={quoted_username}",
            "/api/internal/users/by-username/?username=id60-nonexistent-probe",
        ),
        (
            "by-email",
            f"/api/internal/users/by-email/?email={quoted_email}",
            "/api/internal/users/by-email/?email=id60-nonexistent%40example.invalid",
        ),
    ]

    for endpoint, existing_path, missing_path in pairs:
        check_guard_pair(
            base_url=external,
            label=f"external anonymous {endpoint}",
            existing_path=existing_path,
            missing_path=missing_path,
            headers=None,
            timeout=args.timeout,
            context=context,
        )

    # At the public edge the list is also hidden rather than advertised with
    # a 401.  The ClusterIP check below separately locks the service contract
    # that unauthenticated direct callers cannot bulk-enumerate.
    expect_status(
        base_url=external,
        path="/api/internal/users/",
        label="external anonymous directory list",
        expected=404,
        headers=None,
        timeout=args.timeout,
        context=context,
    )

    if token:
        auth_headers = {"Authorization": f"Bearer {token}"}
        for endpoint, existing_path, missing_path in pairs:
            check_guard_pair(
                base_url=external,
                label=f"external authenticated cross-user {endpoint}",
                existing_path=existing_path,
                missing_path=missing_path,
                headers=auth_headers,
                timeout=args.timeout,
                context=context,
            )
        expect_status(
            base_url=external,
            path="/api/auth/admin/services/",
            label="ordinary user cannot enter staff admin surface",
            expected=403,
            headers=auth_headers,
            timeout=args.timeout,
            context=context,
        )
    else:
        print(f"SKIP authenticated lanes: {args.bearer_env} is not set")

    expect_status(
        base_url=external,
        path="/api/auth/admin/services/",
        label="anonymous caller cannot enter staff admin surface",
        expected=401,
        headers=None,
        timeout=args.timeout,
        context=context,
    )

    if internal:
        expect_status(
            base_url=internal,
            path="/api/internal/users/",
            label="ClusterIP anonymous directory list anti-enumeration",
            expected=401,
            headers=None,
            timeout=args.timeout,
            context=context,
        )

    print("ID-60 live isolation probe: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError) as exc:
        print(f"ID-60 live isolation probe: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
