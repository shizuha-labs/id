"""Canonical identifier normalization for Shizuha ID users (ID-44)."""

from __future__ import annotations

import re

_USERNAME_RE = re.compile(r'^[a-z0-9_]+$')


def normalize_email(value: str | None) -> str:
    """Trim and case-fold email identifiers for storage/lookup."""
    return (value or '').strip().casefold()


def normalize_username(value: str | None) -> str:
    """Trim and case-fold usernames for storage/lookup."""
    return (value or '').strip().casefold()


def validate_username_policy(value: str) -> None:
    """Raise ValueError when a canonical username violates ID policy."""
    if not _USERNAME_RE.match(value):
        raise ValueError('Username can only contain letters, numbers, and underscores')
    if len(value) < 3:
        raise ValueError('Username must be at least 3 characters')
    if len(value) > 30:
        raise ValueError('Username cannot exceed 30 characters')
