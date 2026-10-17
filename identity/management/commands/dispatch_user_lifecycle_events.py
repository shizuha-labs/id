"""Dispatch ID-39 user lifecycle outbox events to subscribed services."""
import hashlib
import hmac
import json
import os
import time
from datetime import timedelta

import requests
from django.core.management.base import BaseCommand
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from identity.models import UserLifecycleEvent, UserLifecycleEventDelivery


DEFAULT_TIMEOUT_SECONDS = 10
SERVICE_NAME = 'shizuha-id'


def _signed_json_request_kwargs(payload, secret):
    """Return requests kwargs for the signed ID lifecycle contract."""
    body = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')
    timestamp = str(int(timezone.now().timestamp()))
    signature = hmac.new(
        secret.encode('utf-8'),
        timestamp.encode('utf-8') + b'.' + body,
        hashlib.sha256,
    ).hexdigest()
    return {
        'data': body,
        'headers': {
            'Content-Type': 'application/json',
            'X-Shizuha-Service': SERVICE_NAME,
            'X-Shizuha-Timestamp': timestamp,
            'X-Shizuha-Signature': f'sha256={signature}',
        },
    }


def _event_payload(event):
    payload = dict(event.payload or {})
    payload.update({
        'event_id': str(event.id),
        'event_type': event.event_type,
        'user_id': event.user_id,
        'email': event.user_email,
        'username': event.user_username,
        'from_state': event.from_state,
        'to_state': event.to_state,
        'reason': event.reason,
        'created_at': event.created_at.isoformat() if event.created_at else None,
    })
    return payload


class Command(BaseCommand):
    help = (
        'Publish pending user lifecycle events from the transactional outbox. '
        'Invariant: no active grants/sessions/assignments should reference a '
        'deactivated or deleted Shizuha ID user. Failure path: run by DevOps; '
        'non-zero exit / outbox lag alerts route to DevOps via monitoring.'
    )

    def add_arguments(self, parser):
        parser.add_argument('--limit', type=int, default=100)
        parser.add_argument('--pulse-url', default=os.environ.get('PULSE_USER_LIFECYCLE_CONSUMER_URL', ''))
        parser.add_argument(
            '--pulse-secret',
            default=(
                os.environ.get('PULSE_USER_LIFECYCLE_CONSUMER_SECRET')
                or os.environ.get('ID_TO_PULSE_LIFECYCLE_SECRET')
                or ''
            ),
            help='Shared HMAC secret for the Pulse lifecycle consumer.',
        )
        parser.add_argument('--mail-url', default=os.environ.get('MAIL_USER_LIFECYCLE_CONSUMER_URL', ''))
        parser.add_argument(
            '--mail-secret',
            default=(
                os.environ.get('MAIL_USER_LIFECYCLE_CONSUMER_SECRET')
                or os.environ.get('ID_TO_MAIL_LIFECYCLE_SECRET')
                or ''
            ),
            help='Shared HMAC secret for the Mail lifecycle consumer.',
        )
        parser.add_argument(
            '--consumers',
            default=os.environ.get('USER_LIFECYCLE_CONSUMERS', 'pulse,mail'),
            help='Comma-separated delivery consumers to run (pulse,mail).',
        )
        parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT_SECONDS)
        parser.add_argument('--max-lag-seconds', type=int, default=300)
        parser.add_argument('--dry-run', action='store_true')
        parser.add_argument(
            '--loop',
            action='store_true',
            help='Run continuously as the reliable relay worker (intended for the compose/k8s dispatcher service).',
        )
        parser.add_argument(
            '--interval',
            type=int,
            default=int(os.environ.get('USER_LIFECYCLE_DISPATCH_INTERVAL_SECONDS', '30')),
            help='Seconds to sleep between loop iterations when --loop is set.',
        )

    def handle(self, *args, **options):
        if options.get('loop'):
            interval = max(1, int(options.get('interval') or 30))
            self.stdout.write(f'user lifecycle dispatcher loop started interval={interval}s')
            while True:
                self._dispatch_once(options)
                time.sleep(interval)
            return
        self._dispatch_once(options)

    def _dispatch_once(self, options):
        now = timezone.now()
        limit = max(1, options['limit'])
        configurations = {
            UserLifecycleEventDelivery.CONSUMER_PULSE: (
                (options['pulse_url'] or '').strip(),
                (options['pulse_secret'] or '').strip(),
            ),
            UserLifecycleEventDelivery.CONSUMER_MAIL: (
                (options['mail_url'] or '').strip(),
                (options['mail_secret'] or '').strip(),
            ),
        }
        selected_consumers = {
            value.strip() for value in (options.get('consumers') or '').split(',') if value.strip()
        }
        unknown = selected_consumers - set(configurations)
        if unknown:
            raise SystemExit(f'unknown lifecycle consumers: {sorted(unknown)}')
        dry_run = options['dry_run']
        timeout = options['timeout']
        max_lag = timedelta(seconds=max(0, options['max_lag_seconds']))

        retryable_statuses = [
            UserLifecycleEvent.STATUS_PENDING,
            UserLifecycleEvent.STATUS_FAILED,
            UserLifecycleEvent.STATUS_PUBLISHING,
        ]
        qs = UserLifecycleEventDelivery.objects.select_related('event').filter(
            consumer__in=selected_consumers,
            status__in=retryable_statuses,
        ).filter(
            Q(next_attempt_at__isnull=True) | Q(next_attempt_at__lte=now),
        )
        deliveries = list(qs.order_by('created_at')[:limit])
        oldest = deliveries[0].created_at if deliveries else None
        lag_seconds = int((now - oldest).total_seconds()) if oldest else 0

        self.stdout.write(
            f'pending_deliveries={len(deliveries)} oldest_lag_seconds={lag_seconds} dry_run={dry_run}'
        )
        if oldest and lag_seconds > max_lag.total_seconds():
            self.stderr.write(
                f'WARNING user lifecycle outbox lag {lag_seconds}s exceeds {int(max_lag.total_seconds())}s'
            )

        if dry_run:
            return
        for consumer in selected_consumers:
            url, secret = configurations[consumer]
            if not url:
                raise SystemExit(f'{consumer} lifecycle consumer URL is required')
            if not secret:
                raise SystemExit(f'{consumer} lifecycle consumer secret is required')

        published = 0
        for delivery in deliveries:
            event = delivery.event
            consumer_url, consumer_secret = configurations[delivery.consumer]
            with transaction.atomic():
                locked = UserLifecycleEventDelivery.objects.select_for_update().get(id=delivery.id)
                if locked.status == UserLifecycleEvent.STATUS_PUBLISHED:
                    continue
                locked.status = UserLifecycleEvent.STATUS_PUBLISHING
                locked.attempts += 1
                locked.next_attempt_at = timezone.now() + timedelta(seconds=max(1, timeout))
                locked.save(update_fields=['status', 'attempts', 'next_attempt_at', 'updated_at'])

            try:
                request_kwargs = _signed_json_request_kwargs(_event_payload(event), consumer_secret)
                response = requests.post(consumer_url, timeout=timeout, **request_kwargs)
                response.raise_for_status()
            except Exception as exc:  # noqa: BLE001 - recorded for retry/backoff visibility
                with transaction.atomic():
                    failed = UserLifecycleEventDelivery.objects.select_for_update().get(id=delivery.id)
                    failed.status = UserLifecycleEvent.STATUS_FAILED
                    failed.last_error = str(exc)[:4000]
                    backoff = min(3600, 2 ** min(failed.attempts, 10))
                    failed.next_attempt_at = timezone.now() + timedelta(seconds=backoff)
                    failed.save(update_fields=['status', 'last_error', 'next_attempt_at', 'updated_at'])
                self._refresh_event_status(event.id)
                self.stderr.write(f'failed {event.id}->{delivery.consumer}: {exc}')
                continue

            with transaction.atomic():
                sent = UserLifecycleEventDelivery.objects.select_for_update().get(id=delivery.id)
                sent.status = UserLifecycleEvent.STATUS_PUBLISHED
                sent.published_at = timezone.now()
                sent.last_error = ''
                sent.next_attempt_at = None
                sent.save(update_fields=['status', 'published_at', 'last_error', 'next_attempt_at', 'updated_at'])
            self._refresh_event_status(event.id)
            published += 1

        self.stdout.write(f'published={published}')

    @staticmethod
    def _refresh_event_status(event_id):
        """Project independent delivery state onto the legacy event summary."""
        with transaction.atomic():
            event = UserLifecycleEvent.objects.select_for_update().get(id=event_id)
            deliveries = list(event.deliveries.all())
            statuses = {delivery.status for delivery in deliveries}
            if deliveries and statuses == {UserLifecycleEvent.STATUS_PUBLISHED}:
                event.status = UserLifecycleEvent.STATUS_PUBLISHED
                event.published_at = max(delivery.published_at for delivery in deliveries)
                event.next_attempt_at = None
                event.last_error = ''
            elif UserLifecycleEvent.STATUS_FAILED in statuses:
                event.status = UserLifecycleEvent.STATUS_FAILED
                event.published_at = None
                event.next_attempt_at = min(
                    (delivery.next_attempt_at for delivery in deliveries if delivery.next_attempt_at),
                    default=None,
                )
                event.last_error = '; '.join(
                    f'{delivery.consumer}: {delivery.last_error}'
                    for delivery in deliveries if delivery.last_error
                )[:4000]
            elif UserLifecycleEvent.STATUS_PUBLISHING in statuses:
                event.status = UserLifecycleEvent.STATUS_PUBLISHING
                event.published_at = None
            else:
                event.status = UserLifecycleEvent.STATUS_PENDING
                event.published_at = None
            event.attempts = sum(delivery.attempts for delivery in deliveries)
            event.save(update_fields=[
                'status', 'published_at', 'next_attempt_at', 'last_error',
                'attempts', 'updated_at',
            ])
