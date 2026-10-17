"""Canonical user resolution for ID lookup surfaces (ID-45).

Every id/email/username/current-user surface should select the same User row,
load the same profile relation, and serialize with the same UserSerializer so
callers do not see divergent identity records depending on lookup path.
"""
from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model

User = get_user_model()


class UserResolutionError(ValueError):
    """Raised when a lookup value is malformed or unsupported."""


def normalize_email(value: Any) -> str:
    email = str(value or '').strip().lower()
    if not email:
        raise UserResolutionError('Email parameter is required')
    return email


def normalize_username(value: Any) -> str:
    username = str(value or '').strip()
    if not username:
        raise UserResolutionError('Username parameter is required')
    return username


def normalize_user_id(value: Any) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise UserResolutionError('User id must be an integer') from exc


def canonical_user_queryset():
    return User.objects.select_related('profile').order_by('id')


def resolve_user_by_id(user_id: Any):
    return canonical_user_queryset().filter(id=normalize_user_id(user_id)).first()


def resolve_user_by_email(email: Any):
    return canonical_user_queryset().filter(email__iexact=normalize_email(email)).first()


def resolve_user_by_username(username: Any):
    return canonical_user_queryset().filter(username__iexact=normalize_username(username)).first()
