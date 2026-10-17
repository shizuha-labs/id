"""Fail-soft Hive notify so a new human gets one hibernated personal agent."""
import logging

import requests
from django.conf import settings

logger = logging.getLogger(__name__)


def notify_hive_default_personal_agent(
    *,
    user_id,
    username,
    email='',
    is_staff=False,
    is_superuser=False,
    account_type='human',
):
    """POST Hive's in-cluster ensure. Never raises to the activation caller."""
    if str(account_type or 'human') == 'agent':
        return
    if is_staff or is_superuser:
        return
    base = (getattr(settings, 'SHIZUHA_HIVE_INTERNAL_URL', '') or '').rstrip('/')
    if not base:
        return
    url = f'{base}/api/v1/fleet/internal/ensure-personal-agent/'
    try:
        requests.post(
            url,
            json={
                'owner_id': int(user_id),
                'username': username or '',
                'email': email or '',
                'is_staff': bool(is_staff),
                'is_superuser': bool(is_superuser),
                'account_type': account_type or 'human',
            },
            headers={
                'Content-Type': 'application/json',
                'X-Internal-Service': 'shizuha-id',
            },
            timeout=5,
        )
    except Exception:
        logger.exception(
            'hive default personal-agent notify failed for user %s', user_id,
        )
