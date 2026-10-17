"""Growth-first free-v1 onboarding projection and mock payment-provider port."""

import re
from dataclasses import dataclass

from django.contrib.auth import get_user_model
from django.db import transaction

from .models import BillingAccount, FreeTierGrant, UpgradeInterest


FREE_PLAN_CODE = 'free-v1'
FREE_PLAN_VERSION = 1
STARTER_PREVIEW_CODE = 'starter-999-v1-rc1'
_SCOPE_RE = re.compile(r'^[a-z0-9][a-z0-9._:-]*$')
SUPPORTED_INTEREST_CONTEXTS = {
    'id': {''},
    'cortex': {'inference.weighted_tokens'},
    'scs': {
        'storage.bytes',
        'compute.cpu_millisecond_seconds',
        'compute.memory_byte_seconds',
    },
}


def ensure_free_v1_for_user(user):
    """Return one stable account/grant pair, repairing old users lazily.

    Locking the immutable user row serializes concurrent signup and lazy-read
    repair. Database uniqueness is the final backstop.
    """

    User = get_user_model()
    with transaction.atomic():
        locked_user = User.objects.select_for_update().get(pk=user.pk)
        subject_key = f'user:{locked_user.pk}'
        account, _ = BillingAccount.objects.get_or_create(
            user=locked_user,
            defaults={'subject_key': subject_key},
        )
        if account.subject_key != subject_key:
            raise RuntimeError('billing account subject does not match its user')
        grant, _ = FreeTierGrant.objects.get_or_create(
            account=account,
            plan_code=FREE_PLAN_CODE,
            plan_version=FREE_PLAN_VERSION,
            defaults={'status': FreeTierGrant.Status.ACTIVE},
        )
        return account, grant


def validate_interest_scope(value, *, field, max_length, allow_blank=False):
    value = str(value or '').strip().lower()
    if allow_blank and not value:
        return ''
    if len(value) > max_length or not _SCOPE_RE.fullmatch(value):
        raise ValueError(f'invalid {field}')
    return value


def validate_interest_context(source, meter):
    """Return one bounded, product-owned display context.

    Browser context is untrusted display state. Only meters emitted by the
    free-v1 Cortex/SCS gates are accepted, so a caller cannot turn context
    dimensions into an unbounded storage keyspace.
    """

    source = validate_interest_scope(source, field='source', max_length=32)
    meter = validate_interest_scope(
        meter, field='meter', max_length=96, allow_blank=True,
    )
    if meter not in SUPPORTED_INTEREST_CONTEXTS.get(source, set()):
        raise ValueError('unsupported source and meter')
    return source, meter


def account_payload(account, grant):
    return {
        'account_id': str(account.account_id),
        'subject_key': account.subject_key,
        'account_type': account.account_type,
        'currency': account.currency,
        'status': account.status,
        'grant': {
            'plan': grant.plan_code,
            'version': grant.plan_version,
            'status': grant.status,
            'granted_at': grant.granted_at.isoformat(),
        },
    }


def plan_catalog():
    """Stable UX catalog; Starter is preview-only and cannot be purchased."""

    return [
        {
            'code': FREE_PLAN_CODE,
            'name': 'Free',
            'eyebrow': 'Your current plan',
            'status': 'active',
            'price_label': '₹0',
            'features': [
                '1,000,000 weighted Cortex tokens / month',
                '5 GB pooled standard storage',
                '100 vCPU-hours + 150 GB-RAM-hours / month',
                'One prototype runtime at a time',
            ],
        },
        {
            'code': STARTER_PREVIEW_CODE,
            'name': 'Starter',
            'eyebrow': 'Coming soon',
            'status': 'notify_only',
            'price_label': 'Join the preview',
            'features': [
                'Higher token, storage, and compute allowances',
                'More concurrent projects and runtimes',
                'Unified Shizuha usage controls',
                'No checkout during this preview',
            ],
        },
    ]


@dataclass(frozen=True)
class NotifyResult:
    interest: UpgradeInterest
    created: bool


class PaymentProvider:
    """Provider port. Real collection adapters are intentionally not present."""

    def notify_interest(self, *, account, target_plan, source, meter):
        raise NotImplementedError


class MockPaymentProvider(PaymentProvider):
    """Records interest only; never creates checkout, wallet, or gateway state."""

    def notify_interest(self, *, account, target_plan, source, meter):
        interest, created = UpgradeInterest.objects.update_or_create(
            account=account,
            target_plan=target_plan,
            defaults={'source': source, 'meter': meter},
        )
        return NotifyResult(interest=interest, created=created)


def payment_provider():
    return MockPaymentProvider()
