"""
Models for Shizuha ID (Identity Service).

Merged from shizuha-notify/authentication/models.py
"""
import secrets
import uuid
from datetime import timedelta

from django.db import models, transaction
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password, make_password
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone

User = get_user_model()


class Tool(models.Model):
    """
    Tools/features available to users with tier-based access control.
    """
    TIER_CHOICES = [
        ('free', 'Free'),
        ('basic', 'Basic'),
        ('premium', 'Premium'),
        ('enterprise', 'Enterprise'),
    ]

    slug = models.SlugField(unique=True, help_text="Backend identifier for the tool")
    display_name = models.CharField(max_length=100, help_text="User-facing name")
    description = models.TextField(blank=True)
    icon = models.CharField(max_length=50, blank=True, help_text="Icon identifier")
    minimum_tier = models.CharField(
        max_length=50,
        choices=TIER_CHOICES,
        default='free',
        help_text="Minimum subscription tier required"
    )
    is_active = models.BooleanField(default=True)
    is_default_enabled = models.BooleanField(
        default=True,
        help_text="Whether this tool is enabled by default for new users"
    )
    requires_approval = models.BooleanField(
        default=False,
        help_text="Whether this tool requires admin approval"
    )
    requires_superuser = models.BooleanField(
        default=False,
        help_text="Whether this tool requires superuser status"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['display_name']

    def __str__(self):
        return self.display_name


class UserProfile(models.Model):
    """
    Extended user profile with OAuth data, location, and tool preferences.
    """
    TIER_CHOICES = [
        ('free', 'Free'),
        ('basic', 'Basic'),
        ('premium', 'Premium'),
        ('enterprise', 'Enterprise'),
    ]

    ACCOUNT_TYPE_CHOICES = [
        ('human', 'Human'),
        ('agent', 'Agent'),
    ]

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='profile'
    )

    # Account type — distinguishes human users from AI agents
    account_type = models.CharField(
        max_length=10,
        choices=ACCOUNT_TYPE_CHOICES,
        default='human',
        db_index=True,
        help_text="Whether this account belongs to a human or an AI agent"
    )
    # For agent accounts: the human who provisioned this agent
    created_by = models.ForeignKey(
        User, null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='created_agents',
        help_text="Human who provisioned this agent (only for account_type=agent)"
    )
    ownership_class = models.CharField(
        max_length=40,
        blank=True,
        default='',
        db_index=True,
        help_text='System ownership policy; personal_default_member identities cannot be claimed or reassigned.',
    )
    # For agent accounts: which runtime currently hosts this agent
    agent_runtime_id = models.CharField(
        max_length=100, null=True, blank=True,
        help_text="Runtime ID that currently hosts this agent"
    )

    # OAuth data
    google_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    profile_picture = models.URLField(max_length=500, null=True, blank=True)
    is_google_user = models.BooleanField(default=False)

    # Location data
    timezone = models.CharField(max_length=100, null=True, blank=True)
    display_currency = models.CharField(
        max_length=8,
        default='USD',
        help_text='Indicative fiat suffix for Hane (USD default). Not a peg.',
    )
    country = models.CharField(max_length=100, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)

    # Subscription
    subscription_tier = models.CharField(
        max_length=50,
        choices=TIER_CHOICES,
        default='free'
    )

    # Tool preferences
    enabled_tools = models.ManyToManyField(Tool, blank=True, related_name='enabled_by')
    tool_preferences = models.JSONField(default=dict, blank=True)

    # Login-time 2FA enforcement (PLAT-493 / SEC-2)
    twofa_enrolled_at = models.DateTimeField(null=True, blank=True)
    twofa_enforced = models.BooleanField(
        default=False,
        help_text='Hard-enforce login 2FA for this user regardless of grace policy',
    )
    twofa_enforcement_deadline = models.DateTimeField(null=True, blank=True)

    # ID-13: user-level access-token revocation cutoff. Bumped to now() on logout
    # and password-change (revoke_all_user_tokens); an access token whose iat is
    # <= this timestamp is rejected on the next request. Closes the stale-token
    # gap — short access TTL alone left a logged-out user's access token valid up
    # to its full lifetime. Mirrors OAuthClient.access_revoked_before at the user
    # level. (User is the default auth.User, so the cutoff lives on its profile.)
    access_revoked_before = models.DateTimeField(
        null=True, blank=True, db_index=True,
        help_text=(
            'User-level access-token cutoff (ID-13). Access tokens for this user '
            'with iat <= this timestamp are rejected. Bumped on logout / password-change.'
        ),
    )

    # ID-1 §3.1 / PLAT-5996: monotonic token version. Bumped (incremented) on
    # logout / password-change / family revocation inside revoke_all_user_tokens,
    # in the same atomic transaction as the access_revoked_before cutoff. Every
    # access token carries this value as a `token_version` claim; consumers
    # (Pulse, Hive, and every RS256 verifier) reject any token whose claim is
    # strictly less than the subject's current version — closing the
    # revive-by-replay gap that a timestamp cutoff alone leaves open (a replayed
    # pre-revocation token can carry an iat that post-dates the cutoff).
    token_version = models.PositiveIntegerField(
        default=0,
        help_text=(
            'Monotonic token version (ID-1 §3.1 / PLAT-5996). Incremented on '
            'logout / password-change / family revocation; access tokens carry '
            'this claim and consumers reject tokens whose token_version < current.'
        ),
    )

    # Account approval — fail-safe: new profiles start pending until explicitly approved (ID-31).
    approval_status = models.CharField(max_length=20, choices=[
        ('approved', 'Approved'), ('pending', 'Pending'), ('denied', 'Denied'),
    ], default='pending')
    approved_by_id = models.IntegerField(null=True, blank=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    approval_note = models.TextField(blank=True, default='')

    # Lifecycle FSM (ID-32, HLD ID-3 §4.1/§4.3). Authoritative state; the
    # legacy approval_status / User.is_active pair is kept in sync by
    # identity.lifecycle.transition_user — mutate lifecycle ONLY through it.
    lifecycle_state = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'), ('active', 'Active'), ('denied', 'Denied'),
            ('deactivated', 'Deactivated'), ('deleted', 'Deleted'),
        ],
        default='pending',
        db_index=True,
    )
    deactivated_at = models.DateTimeField(null=True, blank=True)
    # Soft-delete tombstone (HLD §4.3): rows are never hard-deleted by the
    # admin delete path; audit trail survives. Hard purge is a later slice.
    deleted_at = models.DateTimeField(null=True, blank=True)

    # Declarative service-grants role for reconciliation (SCLI-45 / ID-12).
    # For agent accounts: set to the agent role string (engineer, architect, etc.).
    # Null = not set (human default or untagged agent — reconciler uses account_type).
    service_grants_role = models.CharField(
        max_length=50, null=True, blank=True, db_index=True,
        help_text="Agent role for declarative grant reconciliation (SCLI-45 / ID-12).",
    )

    # Account management
    deletion_requested = models.BooleanField(default=False)
    deletion_requested_at = models.DateTimeField(null=True, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'

    def __str__(self):
        return f"Profile for {self.user.username}"

    def get_available_tools(self):
        """Get all tools available to this user based on tier."""
        tier_order = ['free', 'basic', 'premium', 'enterprise']
        user_tier_index = tier_order.index(self.subscription_tier)

        return Tool.objects.filter(
            is_active=True,
            minimum_tier__in=tier_order[:user_tier_index + 1]
        ).exclude(
            requires_superuser=True
        ) if not self.user.is_superuser else Tool.objects.filter(is_active=True)

    def enable_tool(self, tool):
        """Enable a tool for this user."""
        if isinstance(tool, str):
            tool = Tool.objects.get(slug=tool)
        self.enabled_tools.add(tool)

    def disable_tool(self, tool):
        """Disable a tool for this user."""
        if isinstance(tool, str):
            tool = Tool.objects.get(slug=tool)
        self.enabled_tools.remove(tool)

    def update_location(self, city=None, country=None, latitude=None, longitude=None, timezone=None):
        """Update user location data."""
        if city:
            self.city = city
        if country:
            self.country = country
        if latitude is not None:
            self.latitude = latitude
        if longitude is not None:
            self.longitude = longitude
        if timezone:
            self.timezone = timezone
        self.save()

    def request_account_deletion(self):
        """Mark account for deletion."""
        from django.utils import timezone
        self.deletion_requested = True
        self.deletion_requested_at = timezone.now()
        self.save()


class BillingAccount(models.Model):
    """Signup-time individual billing identity for the free-v1 fast slice.

    This is the stable bootstrap mapping consumed by onboarding/UX. Product
    services continue enforcing their existing local meters until the approved
    neutral Metering Core imports this mapping and becomes authoritative.
    """

    class Status(models.TextChoices):
        ACTIVE = 'active', 'Active'
        SUSPENDED = 'suspended', 'Suspended'

    account_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    user = models.OneToOneField(
        User,
        on_delete=models.PROTECT,
        related_name='billing_account',
    )
    subject_key = models.CharField(max_length=160, unique=True, editable=False)
    account_type = models.CharField(max_length=16, default='individual', editable=False)
    currency = models.CharField(max_length=3, default='INR', editable=False)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.ACTIVE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'{self.account_id} ({self.subject_key})'


class FreeTierGrant(models.Model):
    """Immutable-version free entitlement attached to one BillingAccount."""

    class Status(models.TextChoices):
        ACTIVE = 'active', 'Active'
        REVOKED = 'revoked', 'Revoked'

    account = models.ForeignKey(
        BillingAccount,
        on_delete=models.PROTECT,
        related_name='grants',
    )
    plan_code = models.CharField(max_length=64, default='free-v1')
    plan_version = models.PositiveIntegerField(default=1)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.ACTIVE)
    granted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['account', 'plan_code', 'plan_version'],
                name='uniq_billing_account_plan_version',
            ),
        ]

    def __str__(self):
        return f'{self.account_id}:{self.plan_code}@{self.plan_version}'


class UpgradeInterest(models.Model):
    """Idempotent mock-provider interest; never a checkout or money record."""

    account = models.ForeignKey(
        BillingAccount,
        on_delete=models.PROTECT,
        related_name='upgrade_interests',
    )
    target_plan = models.CharField(max_length=64, default='starter-999-v1-rc1')
    source = models.CharField(max_length=32)
    meter = models.CharField(max_length=96, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['account', 'target_plan'],
                name='uniq_upgrade_interest_plan',
            ),
        ]

    def __str__(self):
        return f'{self.account_id}:{self.target_plan}:{self.source}:{self.meter}'


class UserLifecycleAudit(models.Model):
    """Per-transition lifecycle audit row (ID-32, INV-1).

    One row per attempted transition — applied AND rejected — capturing actor,
    subject, from→to, timestamp, and outcome (field set per the ID-25 audit
    decision). Deletion never destroys audit: soft-deleted users keep their
    rows (mirrors DRV INV-5).
    """
    OUTCOME_CHOICES = [('applied', 'Applied'), ('rejected', 'Rejected')]

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='lifecycle_audit_rows',
        help_text='Subject of the transition',
    )
    actor_id = models.IntegerField(
        null=True, blank=True,
        help_text='User id that requested the transition (null = system)',
    )
    from_state = models.CharField(max_length=20)
    to_state = models.CharField(max_length=20)
    reason = models.TextField(blank=True, default='')
    outcome = models.CharField(max_length=10, choices=OUTCOME_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.user_id}: {self.from_state}->{self.to_state} ({self.outcome})'


class UserLifecycleEvent(models.Model):
    """Transactional outbox row for cross-service user lifecycle cleanup (ID-39).

    Written in the same database transaction as ``transition_user`` so a
    deactivate/delete/reactivate can never commit without its cleanup event.
    A dispatcher publishes rows at-least-once; consumers must dedupe by
    ``event_id``.
    """
    EVENT_ACTIVATED = 'user.activated'
    EVENT_DEACTIVATED = 'user.deactivated'
    EVENT_DELETED = 'user.deleted'
    EVENT_REACTIVATED = 'user.reactivated'
    EVENT_CHOICES = [
        (EVENT_ACTIVATED, 'User activated'),
        (EVENT_DEACTIVATED, 'User deactivated'),
        (EVENT_DELETED, 'User deleted'),
        (EVENT_REACTIVATED, 'User reactivated'),
    ]

    STATUS_PENDING = 'pending'
    STATUS_PUBLISHING = 'publishing'
    STATUS_PUBLISHED = 'published'
    STATUS_FAILED = 'failed'
    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_PUBLISHING, 'Publishing'),
        (STATUS_PUBLISHED, 'Published'),
        (STATUS_FAILED, 'Failed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event_type = models.CharField(max_length=40, choices=EVENT_CHOICES, db_index=True)
    user_id = models.IntegerField(db_index=True)
    user_email = models.EmailField(blank=True, default='')
    user_username = models.CharField(max_length=150, blank=True, default='')
    from_state = models.CharField(max_length=20)
    to_state = models.CharField(max_length=20)
    reason = models.TextField(blank=True, default='')
    payload = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True)
    attempts = models.PositiveIntegerField(default=0)
    next_attempt_at = models.DateTimeField(null=True, blank=True, db_index=True)
    last_error = models.TextField(blank=True, default='')
    published_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['created_at']
        indexes = [
            models.Index(fields=['status', 'next_attempt_at', 'created_at']),
            models.Index(fields=['event_type', 'user_id']),
        ]

    def __str__(self):
        return f'{self.event_type} user={self.user_id} status={self.status}'


class UserLifecycleEventDelivery(models.Model):
    """Independent at-least-once delivery state for each lifecycle consumer.

    A lifecycle event is complete only after every subscribed consumer has
    acknowledged it.  Keeping one row per consumer prevents a healthy Pulse
    delivery from hiding a failed Mail provision (and vice versa).
    """

    CONSUMER_PULSE = 'pulse'
    CONSUMER_MAIL = 'mail'
    CONSUMER_CHOICES = [
        (CONSUMER_PULSE, 'Pulse'),
        (CONSUMER_MAIL, 'Mail'),
    ]

    event = models.ForeignKey(
        UserLifecycleEvent,
        on_delete=models.CASCADE,
        related_name='deliveries',
    )
    consumer = models.CharField(max_length=30, choices=CONSUMER_CHOICES, db_index=True)
    status = models.CharField(
        max_length=20,
        choices=UserLifecycleEvent.STATUS_CHOICES,
        default=UserLifecycleEvent.STATUS_PENDING,
        db_index=True,
    )
    attempts = models.PositiveIntegerField(default=0)
    next_attempt_at = models.DateTimeField(null=True, blank=True, db_index=True)
    last_error = models.TextField(blank=True, default='')
    published_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['created_at', 'id']
        constraints = [
            models.UniqueConstraint(
                fields=['event', 'consumer'],
                name='uniq_lifecycle_event_consumer',
            ),
        ]
        indexes = [
            models.Index(fields=['consumer', 'status', 'next_attempt_at', 'created_at']),
        ]

    def __str__(self):
        return f'{self.event_id} -> {self.consumer} ({self.status})'


class ToolCall(models.Model):
    """
    Record of MCP tool calls made by users.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('executing', 'Executing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='tool_calls'
    )
    tool_name = models.CharField(max_length=100)
    raw_content = models.TextField(blank=True)
    python_code = models.TextField(blank=True)
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )
    conversation_context = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.tool_name} by {self.user.username} ({self.status})"


class ToolResponse(models.Model):
    """
    Response from a tool call.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tool_call = models.OneToOneField(
        ToolCall,
        on_delete=models.CASCADE,
        related_name='response'
    )
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='tool_responses'
    )
    raw_content = models.TextField(blank=True)
    response_data = models.JSONField(default=dict, blank=True)
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)
    execution_time_ms = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        status = "Success" if self.success else "Failed"
        return f"Response for {self.tool_call.tool_name} ({status})"


class ServiceAccessRequest(models.Model):
    """
    Request from a user to access a restricted service.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('denied', 'Denied'),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='service_access_requests'
    )
    tool = models.ForeignKey(
        Tool,
        on_delete=models.CASCADE,
        related_name='access_requests'
    )
    organization_id = models.IntegerField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    reason = models.TextField(blank=True)
    reviewed_by_id = models.IntegerField(null=True, blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_note = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username} requesting {self.tool.slug} ({self.status})"


class PasswordResetToken(models.Model):
    """
    Secure password reset token with explicit expiration and single-use enforcement.
    """
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='password_reset_tokens'
    )
    token = models.CharField(max_length=64, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['token', 'expires_at']),
        ]

    def __str__(self):
        status = "used" if self.used_at else ("expired" if self.is_expired else "valid")
        return f"Reset token for {self.user.email} ({status})"

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    @property
    def is_valid(self):
        return not self.is_expired and self.used_at is None

    def mark_used(self):
        self.used_at = timezone.now()
        self.save(update_fields=['used_at'])

    @classmethod
    def create_for_user(cls, user, ip_address=None, expiry_hours=1):
        """Create a new reset token for a user."""
        token = secrets.token_urlsafe(32)  # 43 characters
        expires_at = timezone.now() + timedelta(hours=expiry_hours)

        return cls.objects.create(
            user=user,
            token=token,
            expires_at=expires_at,
            ip_address=ip_address
        )

    @classmethod
    def cleanup_expired(cls):
        """Delete expired tokens older than 24 hours."""
        cutoff = timezone.now() - timedelta(hours=24)
        deleted, _ = cls.objects.filter(expires_at__lt=cutoff).delete()
        return deleted


class PushToken(models.Model):
    """
    Expo push tokens for mobile push notifications.
    Stored in shizuha-id as the identity source of truth.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='push_tokens')
    token = models.CharField(max_length=1000, unique=True)
    device_id = models.CharField(max_length=255)
    # ID-21 (HLD 815412d1 §3.6): the access-token jti of the session that
    # registered/last-refreshed this push token, associating the push token with
    # its issuing session/refresh family. Best-effort (blank when the registering
    # request carried no jti); the revoke-path purge is the guarantee, this is
    # the association for future per-session revocation.
    session_jti = models.CharField(max_length=255, blank=True, default='', db_index=True)
    # ID-70: stable session-family identifier. Unlike the access-token jti above,
    # ``sid`` survives refresh rotation, so ordinary logout can deactivate only
    # the push channel belonging to the logged-out session.
    session_sid = models.CharField(max_length=64, blank=True, default='', db_index=True)
    platform = models.CharField(max_length=20, choices=[
        ('android', 'Android'),
        ('ios', 'iOS'),
        ('web', 'Web'),
        ('wearos', 'Wear OS'),
    ])
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_used = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'device_id')
        ordering = ['-last_used']

    def __str__(self):
        return f'{self.user} - {self.platform} - {self.device_id}'


class OAuthClient(models.Model):
    """
    OAuth 2.0 client registered for authorization code + PKCE flow.

    Public clients (PKCE, no secret) cover CLI tools, SPAs, and Claude Code.
    Confidential clients are for server-side integrations; secret is compared
    against its SHA-256 hash.
    """
    CLIENT_TYPE_PUBLIC = 'public'
    CLIENT_TYPE_CONFIDENTIAL = 'confidential'

    client_id = models.CharField(max_length=64, unique=True, db_index=True)
    client_secret_hash = models.CharField(max_length=128, blank=True, default='')
    client_name = models.CharField(max_length=200)
    redirect_uris = models.JSONField(
        default=list,
        help_text='Exact-match allowlist. Use "http://localhost" or "http://127.0.0.1" prefix for CLI tools.',
    )
    grant_types = models.JSONField(default=list)
    response_types = models.JSONField(default=list)
    scope = models.CharField(max_length=500, default='*')
    access_token_ttl_minutes = models.PositiveSmallIntegerField(
        default=60,
        help_text=(
            'Access-token lifetime for this client. Federated protocols that '
            'validate JWTs offline should use a short TTL to bound revocation lag.'
        ),
    )
    client_type = models.CharField(
        max_length=20,
        choices=[(CLIENT_TYPE_PUBLIC, 'Public'), (CLIENT_TYPE_CONFIDENTIAL, 'Confidential')],
        default=CLIENT_TYPE_PUBLIC,
    )
    is_system = models.BooleanField(
        default=False,
        help_text='System clients cannot be deleted via public registration endpoints.',
    )
    access_revoked_before = models.DateTimeField(
        null=True, blank=True, db_index=True,
        help_text=(
            'OAuth access-token cutoff for emergency client revocation. '
            'Access tokens for this client with iat <= this timestamp are rejected.'
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    owner = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL,
        related_name='oauth_clients',
    )

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.client_name} ({self.client_id})'

    def redirect_uri_allowed(self, redirect_uri: str) -> bool:
        if not redirect_uri:
            return False
        for allowed in self.redirect_uris:
            if allowed == redirect_uri:
                return True
            # Localhost port-wildcard: allowed="http://localhost" matches any port/path
            # when the registered URI has no scheme+host+port component beyond the host.
            if allowed.endswith('/*') and redirect_uri.startswith(allowed[:-2]):
                return True
            # Localhost loopback with any port (OAuth 2.1 / BCP for native apps)
            if allowed in ('http://localhost', 'http://127.0.0.1'):
                if redirect_uri.startswith(allowed + ':') or redirect_uri.startswith(allowed + '/'):
                    return True
        return False


class AuthorizationCode(models.Model):
    """
    Short-lived one-time authorization code for OAuth 2.0 authorization_code grant.
    Stores PKCE parameters so token endpoint can verify the code_verifier.
    """
    code = models.CharField(max_length=128, unique=True, db_index=True)
    client = models.ForeignKey(OAuthClient, on_delete=models.CASCADE, related_name='auth_codes')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='auth_codes')
    redirect_uri = models.CharField(max_length=2000)
    scope = models.CharField(max_length=500, default='*')
    code_challenge = models.CharField(max_length=256)
    code_challenge_method = models.CharField(
        max_length=10,
        choices=[('S256', 'S256'), ('plain', 'plain')],
        default='S256',
    )
    nonce = models.CharField(max_length=256, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at

    def is_used(self) -> bool:
        return self.used_at is not None


class IssuedRefreshToken(models.Model):
    """
    Tracks refresh tokens we've issued so users can see "my authorized apps"
    and revoke a client's access. Access tokens aren't tracked (1h TTL, too
    churny for a list).
    """
    jti = models.CharField(max_length=200, unique=True, db_index=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='issued_refresh_tokens')
    client = models.ForeignKey(OAuthClient, on_delete=models.CASCADE, related_name='issued_refresh_tokens')
    scope = models.CharField(max_length=500, default='*')
    issued_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, blank=True, default='')
    # DRV-106: refresh-family + device binding. ``token_family`` is a stable
    # opaque id shared by every descendant of one original refresh grant;
    # rotation invalidates the consumed token while keeping the family alive,
    # and reuse of an already-consumed/revoked token revokes the whole family.
    # ``device`` links the refresh family to the registered desktop device
    # (null for non-device flows).
    token_family = models.CharField(max_length=64, blank=True, default='', db_index=True)
    device = models.ForeignKey(
        'OAuthDevice', null=True, blank=True, on_delete=models.SET_NULL,
        related_name='refresh_tokens',
    )

    class Meta:
        ordering = ['-issued_at']

    def __str__(self):
        return f'{self.user}:{self.client}:{self.jti[:8]}…'


class OAuthDevice(models.Model):
    """
    DRV-106: server-bound device registry for the Drive Desktop client.

    A device is registered/heartbeated by the desktop client and bound to the
    refresh-token family it was issued under. The server can deny a stale or
    revoked device, revoke a single device's refresh family (logout), or sign
    out every device (revoke-all).
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='oauth_devices')
    device_id = models.CharField(max_length=255, db_index=True)
    client = models.ForeignKey(
        OAuthClient, null=True, blank=True, on_delete=models.SET_NULL,
        related_name='oauth_devices',
    )
    name = models.CharField(max_length=255, blank=True, default='')
    os = models.CharField(max_length=100, blank=True, default='')
    build = models.CharField(max_length=100, blank=True, default='')
    last_seen_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'device_id')
        ordering = ['-last_seen_at']

    def __str__(self):
        return f'{self.user} - {self.device_id} ({self.name})'


class RevokedToken(models.Model):
    """
    OAuth 2.0 revocation list (RFC 7009).

    Keyed by JWT `jti`. Refresh grant checks this table before minting new
    access tokens; downstream services may consult it when Phase 4 enforcement
    lands. Access tokens natural-expire (1h) so we don't keep rows beyond a day.
    """
    jti = models.CharField(max_length=200, unique=True, db_index=True)
    token_type = models.CharField(
        max_length=20,
        choices=[('access', 'access'), ('refresh', 'refresh')],
        default='refresh',
    )
    user = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL,
        related_name='revoked_tokens',
    )
    client = models.ForeignKey(
        OAuthClient, null=True, blank=True, on_delete=models.SET_NULL,
        related_name='revoked_tokens',
    )
    revoked_at = models.DateTimeField(auto_now_add=True)
    reason = models.CharField(max_length=100, blank=True, default='')

    class Meta:
        ordering = ['-revoked_at']

    def __str__(self):
        return f'revoked:{self.token_type}:{self.jti}'


class RevokedSession(models.Model):
    """Authoritative deny-list for one interactive login session family.

    The opaque JWT ``sid`` is minted once per login and retained when the
    refresh-token ``jti`` rotates. Ordinary logout writes one row here; account
    lifecycle/password revocation continues to use the user-wide cutoff.
    """

    sid = models.CharField(max_length=64, unique=True, db_index=True)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='revoked_sessions',
    )
    revoked_at = models.DateTimeField(auto_now_add=True, db_index=True)
    reason = models.CharField(max_length=100, blank=True, default='logout')

    class Meta:
        ordering = ['-revoked_at']

    def __str__(self):
        return f'revoked-session:{self.user_id}:{self.sid}'


class ActiveSession(models.Model):
    """Authoritative allow-list for one issued session family (ID-70 P1 #1).

    The opaque JWT ``sid`` is minted once per login / service-token / api-token
    and retained when the refresh-token ``jti`` rotates. A row here proves the
    sid was issued by this ID service. The session-revocation gate fails closed:
    a sid with no ``ActiveSession`` row (unknown / never issued / expired) is
    treated as revoked, so an arbitrary or stale sid can never be accepted.
    """

    sid = models.CharField(max_length=64, unique=True, db_index=True)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='active_sessions',
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    last_seen_at = models.DateTimeField(auto_now=True, db_index=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'active-session:{self.user_id}:{self.sid}'


class OAuthClientAgentRevocationCutoff(models.Model):
    """Per-agent OAuth access-token cutoff for agent-scoped client revocation."""

    client = models.ForeignKey(
        OAuthClient, on_delete=models.CASCADE, related_name='agent_revocation_cutoffs'
    )
    agent_id = models.CharField(max_length=150, db_index=True)
    access_revoked_before = models.DateTimeField(
        help_text=(
            'OAuth access-token cutoff for this client + agent_id. '
            'Matching access tokens with iat <= this timestamp are rejected.'
        ),
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']
        unique_together = [('client', 'agent_id')]

    def __str__(self):
        return f'revoked-before:{self.client.client_id}:{self.agent_id}'


# ---------------------------------------------------------------------------
# Step-up re-authentication (HIVE-6 / HLD page 7197343e)
#
# Producer side of the destructive-action step-up gate consumed by HIVE-4
# §6.1 (export / hard-delete / rename) and the Hive dashboard-url minter.
# Three models back the begin -> answer -> verify flow:
#   * TOTPDevice          — first-class authenticator on the user (A3)
#   * StepUpEnrollmentToken — single-use email-OOB enrollment leg (§4.1)
#   * StepUpChallenge     — the begin/answer challenge state (§5)
# ---------------------------------------------------------------------------


class TOTPDevice(models.Model):
    """
    A second-factor authenticator bound to a user (HLD §4 / §6 A3).

    Modelled MFA-general in *shape* (a ``device_type`` discriminator so a future
    login-time MFA program adopts the same table) but step-up-scoped in *flow*
    (v1 ships no general enrollment UX). The TOTP ``secret`` is base32 per
    RFC 6238 / ``pyotp``.

    A device is **provisional/inactive** (``confirmed=False``) until the §4.1
    email-OOB enrollment link is consumed; only confirmed devices may answer a
    step-up challenge. The enrollment trust-bootstrap lives in the enrollment
    views, not here — this model only records the factor and its confirmed state.
    """
    DEVICE_TOTP = 'totp'
    DEVICE_WEBAUTHN = 'webauthn'
    DEVICE_TYPE_CHOICES = [
        (DEVICE_TOTP, 'TOTP'),
        (DEVICE_WEBAUTHN, 'WebAuthn / passkey'),
    ]

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='totp_devices'
    )
    device_type = models.CharField(
        max_length=20, choices=DEVICE_TYPE_CHOICES, default=DEVICE_TOTP
    )
    name = models.CharField(max_length=100, blank=True, default='')
    secret = models.CharField(
        max_length=255, blank=True, default='',
        help_text='Base32 TOTP secret or WebAuthn credential id (websafe base64)',
    )
    webauthn_credential_data = models.TextField(
        blank=True, default='',
        help_text='Serialized WebAuthn AttestedCredentialData (websafe base64)',
    )
    webauthn_state = models.JSONField(
        default=dict, blank=True,
        help_text='Pending WebAuthn registration challenge state',
    )
    webauthn_transports = models.JSONField(default=list, blank=True)
    confirmed = models.BooleanField(
        default=False,
        help_text='Provisional until the §4.1 email-OOB enrollment link is consumed',
    )
    confirmed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'device_type', 'confirmed']),
        ]

    def __str__(self):
        state = 'confirmed' if self.confirmed else 'provisional'
        return f'{self.device_type} for {self.user.username} ({state})'

    def mark_confirmed(self):
        """Activate a provisional device once its email-OOB link is consumed."""
        self.confirmed = True
        self.confirmed_at = timezone.now()
        self.save(update_fields=['confirmed', 'confirmed_at', 'updated_at'])


class RecoveryCode(models.Model):
    """Single-use hashed backup code for login-time MFA recovery (PLAT-493)."""

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='twofa_recovery_codes'
    )
    code_hash = models.CharField(max_length=255)
    prefix = models.CharField(max_length=12, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'prefix', 'used_at']),
        ]

    def __str__(self):
        state = 'used' if self.used_at else 'unused'
        return f'recovery code {self.prefix} for {self.user_id} ({state})'

    @staticmethod
    def generate_plain_code() -> str:
        raw = secrets.token_urlsafe(18).replace('-', '').replace('_', '').upper()[:20]
        return '-'.join(raw[i:i + 4] for i in range(0, 20, 4))

    @classmethod
    def regenerate_for_user(cls, user, *, count: int = 10) -> list[str]:
        """Invalidate existing codes and return new plaintext codes once."""
        now = timezone.now()
        cls.objects.filter(user=user, used_at__isnull=True).update(used_at=now)
        plain_codes = [cls.generate_plain_code() for _ in range(count)]
        cls.objects.bulk_create([
            cls(
                user=user,
                prefix=code.split('-', 1)[0],
                code_hash=make_password(code),
            )
            for code in plain_codes
        ])
        return plain_codes

    @classmethod
    def consume(cls, user, code: str) -> bool:
        normalized = (code or '').strip().upper()
        if not normalized:
            return False
        prefix = normalized.split('-', 1)[0]
        with transaction.atomic():
            for recovery_code in cls.objects.select_for_update().filter(
                user=user, prefix=prefix, used_at__isnull=True
            ):
                if check_password(normalized, recovery_code.code_hash):
                    recovery_code.used_at = timezone.now()
                    recovery_code.save(update_fields=['used_at'])
                    return True
        return False

    @classmethod
    def remaining_for_user(cls, user) -> int:
        return cls.objects.filter(user=user, used_at__isnull=True).count()


class StepUpEnrollmentToken(models.Model):
    """
    Single-use, short-TTL email-OOB enrollment token (HLD §4.1).

    Mirrors ``PasswordResetToken`` exactly — it is the out-of-band leg the
    session-hijacker lacks. Bound to the *provisional* ``TOTPDevice`` it
    confirms. ``purpose`` distinguishes the asymmetric lifecycle legs:
      * ``first_enroll`` — no factor existed yet (§4.1a)
      * ``reenroll``     — replacing an existing factor (§4.1b, gated by the
                           existing factor *in addition* to this token)
      * ``recover``      — lost-factor recovery (§4.1c, gated by cooldown +
                           OOB notification on top of this token)
    """
    PURPOSE_FIRST_ENROLL = 'first_enroll'
    PURPOSE_REENROLL = 'reenroll'
    PURPOSE_RECOVER = 'recover'
    PURPOSE_CHOICES = [
        (PURPOSE_FIRST_ENROLL, 'First enroll'),
        (PURPOSE_REENROLL, 'Re-enroll / device replace'),
        (PURPOSE_RECOVER, 'Lost-factor recovery'),
    ]

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='stepup_enrollment_tokens'
    )
    device = models.ForeignKey(
        TOTPDevice, on_delete=models.CASCADE, related_name='enrollment_tokens'
    )
    token = models.CharField(max_length=64, unique=True, db_index=True)
    purpose = models.CharField(
        max_length=20, choices=PURPOSE_CHOICES, default=PURPOSE_FIRST_ENROLL
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['token', 'expires_at']),
        ]

    def __str__(self):
        status = 'used' if self.used_at else ('expired' if self.is_expired else 'valid')
        return f'Enrollment token ({self.purpose}) for {self.user.email} ({status})'

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    @property
    def is_valid(self):
        return not self.is_expired and self.used_at is None

    def mark_used(self):
        self.used_at = timezone.now()
        self.save(update_fields=['used_at'])

    @classmethod
    def create_for_device(cls, device, purpose=PURPOSE_FIRST_ENROLL,
                          ip_address=None, expiry_hours=1):
        """Create a single-use enrollment token bound to a provisional device."""
        token = secrets.token_urlsafe(32)  # 43 characters
        expires_at = timezone.now() + timedelta(hours=expiry_hours)
        return cls.objects.create(
            user=device.user,
            device=device,
            token=token,
            purpose=purpose,
            expires_at=expires_at,
            ip_address=ip_address,
        )

    @classmethod
    def cleanup_expired(cls):
        """Delete enrollment tokens expired more than 24 hours ago."""
        cutoff = timezone.now() - timedelta(hours=24)
        deleted, _ = cls.objects.filter(expires_at__lt=cutoff).delete()
        return deleted


class StepUpChallenge(models.Model):
    """
    A step-up challenge issued by ``/step-up/begin`` (HLD §5.1) and answered by
    ``/step-up/answer`` (§5.2).

    The challenge carries the scope tuple ``(user, resource_id, action)`` and the
    selected factor. ``begin`` issues the challenge (never a token); ``answer``
    submits the factor response and, on success, mints the one-shot step-up JWT.
    ``attempts`` + ``locked`` back the §7 lock-after-N brute-force bound; because
    the canonical flow is strict two-step (no inline fast-path, A2), the lock has
    a durable row to bite on.
    """
    challenge_id = models.CharField(max_length=64, unique=True, db_index=True)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='stepup_challenges'
    )
    device = models.ForeignKey(
        TOTPDevice, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='challenges'
    )
    action = models.CharField(max_length=100)
    resource_id = models.CharField(max_length=255)
    factor = models.CharField(max_length=20, default=TOTPDevice.DEVICE_TOTP)
    # A7 (a): the access-token hash captured at begin so answer can bind the
    # minted token's cnf.ath to the originating session for irreversible actions.
    session_ath = models.CharField(max_length=64, blank=True, default='')
    webauthn_state = models.JSONField(
        default=dict, blank=True,
        help_text='WebAuthn assertion challenge state for passkey-backed step-up',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    attempts = models.PositiveIntegerField(default=0)
    locked = models.BooleanField(default=False)
    answered_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['challenge_id', 'expires_at']),
        ]

    def __str__(self):
        return f'challenge {self.challenge_id} ({self.action}/{self.resource_id})'

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    @property
    def is_open(self):
        """A challenge can still be answered: unanswered, unlocked, unexpired."""
        return (
            self.answered_at is None
            and not self.locked
            and not self.is_expired
        )

    @classmethod
    def new_id(cls):
        return f'chl_{secrets.token_urlsafe(24)}'

    @classmethod
    def cleanup_expired(cls):
        """Delete challenges expired more than 24 hours ago."""
        cutoff = timezone.now() - timedelta(hours=24)
        deleted, _ = cls.objects.filter(expires_at__lt=cutoff).delete()
        return deleted


# ---------------------------------------------------------------------------
# Admin audit ledger (ID-34 / HLD ID-5: ID Admin Operations & Audit).
# ---------------------------------------------------------------------------
ADMIN_AUDIT_GENESIS_HASH = '0' * 64


class AdminAuditEventManager(models.Manager):
    def append(self, *, action, actor=None, target_type='', target_id='',
               target_repr='', before=None, after=None, request_metadata=None):
        """Append one event to the hash chain.

        Serializes chain writers with a row lock on the current head; the
        unique constraints on ``seq``/``event_hash`` are the backstop if two
        writers still race (e.g. on backends where ``select_for_update`` is a
        no-op, like SQLite) — the loser gets an IntegrityError and the caller's
        transaction rolls back rather than forking the chain.
        """
        with transaction.atomic():
            head = (
                self.select_for_update()
                .order_by('-seq')
                .first()
            )
            prev_hash = head.event_hash if head else ADMIN_AUDIT_GENESIS_HASH
            seq = (head.seq + 1) if head else 1
            event = self.model(
                seq=seq,
                action=action,
                actor_id=getattr(actor, 'id', None),
                actor_username=getattr(actor, 'username', '') or '',
                actor_email=getattr(actor, 'email', '') or '',
                target_type=target_type,
                target_id=str(target_id),
                target_repr=target_repr,
                before=before or {},
                after=after or {},
                request_metadata=request_metadata or {},
                created_at=timezone.now(),
                prev_hash=prev_hash,
            )
            event.event_hash = event.compute_hash()
            event.save(force_insert=True)
            return event


class AdminAuditEvent(models.Model):
    """Append-only, tamper-evident ledger of privileged admin mutations.

    Every privileged admin mutation (service catalog update, grant/revoke,
    access-request review, account approval, admin password set) MUST go
    through the ``identity.admin_audit`` wrappers, which write the mutation
    and this event in one transaction — the mutation cannot commit without
    its audit row.

    Tamper evidence: each event stores a SHA-256 over its own canonical
    payload including ``prev_hash``, forming a verifiable chain from the
    genesis sentinel. Rows are append-only at the ORM layer (``save`` on an
    existing row and ``delete`` raise); direct SQL/queryset tampering is
    caught by ``identity.admin_audit.verify_chain``.
    """

    seq = models.PositiveBigIntegerField(unique=True, editable=False)
    action = models.CharField(max_length=64, db_index=True)
    actor_id = models.IntegerField(null=True, blank=True, db_index=True)
    actor_username = models.CharField(max_length=254, blank=True)
    actor_email = models.CharField(max_length=254, blank=True)
    target_type = models.CharField(max_length=64, db_index=True)
    target_id = models.CharField(max_length=64, blank=True, db_index=True)
    target_repr = models.CharField(max_length=254, blank=True)
    before = models.JSONField(default=dict, blank=True)
    after = models.JSONField(default=dict, blank=True)
    request_metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False, db_index=True)
    prev_hash = models.CharField(max_length=64, editable=False)
    event_hash = models.CharField(max_length=64, unique=True, editable=False)

    objects = AdminAuditEventManager()

    class Meta:
        ordering = ['seq']

    def __str__(self):
        return f"#{self.seq} {self.action} {self.target_type}:{self.target_id} by {self.actor_username or self.actor_id}"

    def hash_payload(self):
        """Canonical JSON string the event hash commits to."""
        import json

        return json.dumps(
            {
                'seq': self.seq,
                'action': self.action,
                'actor_id': self.actor_id,
                'actor_username': self.actor_username,
                'actor_email': self.actor_email,
                'target_type': self.target_type,
                'target_id': self.target_id,
                'target_repr': self.target_repr,
                'before': self.before,
                'after': self.after,
                'request_metadata': self.request_metadata,
                'created_at': self.created_at.isoformat(),
                'prev_hash': self.prev_hash,
            },
            sort_keys=True,
            separators=(',', ':'),
            default=str,
        )

    def compute_hash(self):
        import hashlib

        return hashlib.sha256(self.hash_payload().encode('utf-8')).hexdigest()

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError('AdminAuditEvent is append-only; updates are forbidden')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError('AdminAuditEvent is append-only; deletes are forbidden')
