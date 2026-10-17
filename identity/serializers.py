"""
Serializers for Shizuha ID (Identity Service).
"""
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .canonicalization import normalize_email, normalize_username, validate_username_policy
from .models import UserProfile, Tool, ToolCall, ToolResponse, ServiceAccessRequest

User = get_user_model()


class StrictInputMixin:
    """ID-55 (ID-6 deny-by-default): reject any request key that is not a declared
    serializer field with a consistent 400, instead of DRF's default behaviour of
    silently ignoring unknown input.

    Mix in BEFORE ``serializers.Serializer`` on INPUT serializers only (never on
    read/output serializers). Unknown keys -> ``ValidationError`` (HTTP 400), so a
    caller can no longer smuggle unvalidated params past the API or rely on a
    typo'd field being silently dropped. See the wiki Standard
    "shizuha-id API authz + PII-scope matrix (ID-6)".
    """

    def to_internal_value(self, data):
        if isinstance(data, dict):
            unexpected = [key for key in data if key not in self.fields]
            if unexpected:
                raise serializers.ValidationError({
                    key: ['Unexpected field (deny-by-default input validation, ID-55).']
                    for key in sorted(unexpected)
                })
        return super().to_internal_value(data)


class ToolSerializer(serializers.ModelSerializer):
    """Serializer for Tool model."""

    class Meta:
        model = Tool
        fields = [
            'slug', 'display_name', 'description', 'icon',
            'minimum_tier', 'is_active', 'is_default_enabled'
        ]


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for UserProfile model."""
    enabled_tools = ToolSerializer(many=True, read_only=True)
    user_id = serializers.IntegerField(source='user.id', read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    first_name = serializers.CharField(source='user.first_name', read_only=True)
    last_name = serializers.CharField(source='user.last_name', read_only=True)
    is_active = serializers.BooleanField(source='user.is_active', read_only=True)

    class Meta:
        model = UserProfile
        fields = [
            'user_id', 'username', 'email', 'first_name', 'last_name', 'is_active',
            'google_id', 'profile_picture', 'is_google_user',
            'timezone', 'display_currency', 'country', 'city', 'latitude', 'longitude',
            'subscription_tier', 'enabled_tools', 'tool_preferences',
            'approval_status', 'lifecycle_state', 'deletion_requested', 'created_at', 'updated_at',
            # ADR-0004 Phase 1: expose agent identity so the fleet daemon can
            # validate/guarantee each child's canonical Shizuha-ID at spawn
            # (account_type=agent + which runtime hosts it). is_active already
            # comes from User on UserSerializer. Provisioning-set, never user-editable.
            'account_type', 'agent_runtime_id'
        ]
        read_only_fields = [
            'google_id', 'is_google_user', 'subscription_tier',
            'approval_status', 'lifecycle_state', 'deletion_requested', 'created_at', 'updated_at',
            'account_type', 'agent_runtime_id'
        ]


class UserSerializer(serializers.ModelSerializer):
    """Serializer for canonical User records with profile state."""
    profile = UserProfileSerializer(read_only=True)
    display_name = serializers.SerializerMethodField()
    approval_status = serializers.CharField(source='profile.approval_status', read_only=True)
    lifecycle_state = serializers.CharField(source='profile.lifecycle_state', read_only=True)
    account_type = serializers.CharField(source='profile.account_type', read_only=True)

    def get_display_name(self, obj):
        return (f'{obj.first_name} {obj.last_name}'.strip() or obj.username or obj.email)

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 'display_name',
            'is_staff', 'is_superuser', 'is_active', 'date_joined',
            'approval_status', 'lifecycle_state', 'account_type', 'profile'
        ]
        read_only_fields = ['id', 'is_staff', 'is_superuser', 'is_active', 'date_joined']



class PublicUserSerializer(serializers.ModelSerializer):
    """Minimal-PII serializer for cross-user lookups (ID-52).

    Returned when a non-staff, non-self caller reads another user via an
    internal endpoint. Per ID-51 PII-scope matrix, public-directory minimal
    fields are id + username; first_name/last_name are NOT public-directory-safe.
    display_name is always the username — never a real name — in this serializer.
    account_type and profile_picture are non-PII identity signals exposed to
    support UI rendering (e.g. agent vs human badge, avatar).
    """
    display_name = serializers.SerializerMethodField()
    account_type = serializers.CharField(source='profile.account_type', read_only=True, default=None)
    profile_picture = serializers.CharField(source='profile.profile_picture', read_only=True, default=None)

    def get_display_name(self, obj):
        return obj.username

    class Meta:
        model = User
        fields = ['id', 'username', 'display_name', 'account_type', 'profile_picture']


class UserUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user info."""
    username = serializers.CharField(
        required=False,
        allow_blank=True,
        min_length=3,
        max_length=30,
        help_text="Username must be 3-30 characters, alphanumeric and underscores only"
    )

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email']

    def validate_username(self, value):
        """Validate username format and canonical uniqueness."""
        value = normalize_username(value)
        if not value:
            raise serializers.ValidationError("Username cannot be empty")

        try:
            validate_username_policy(value)
        except ValueError as exc:
            raise serializers.ValidationError(str(exc))

        # Check reserved usernames
        reserved = ['admin', 'root', 'system', 'shizuha', 'administrator', 'support', 'help', 'api', 'www', 'mail']
        if value in reserved:
            raise serializers.ValidationError(
                "This username is reserved and cannot be used"
            )

        # Check uniqueness (case-insensitive). The DB functional unique index is
        # the race-proof backstop; this keeps API errors friendly.
        user = self.context.get('request').user if self.context.get('request') else None
        existing = User.objects.filter(username__iexact=value)
        if user:
            existing = existing.exclude(id=user.id)
        if existing.exists():
            raise serializers.ValidationError(
                "This username is already taken"
            )

        return value

    def validate_email(self, value):
        """Canonicalize and validate email uniqueness."""
        value = normalize_email(value)
        if not value:
            raise serializers.ValidationError("Email cannot be empty")
        user = self.context.get('request').user if self.context.get('request') else None
        existing = User.objects.filter(email__iexact=value)
        if user:
            existing = existing.exclude(id=user.id)
        if existing.exists():
            raise serializers.ValidationError("This email is already taken")
        return value

    def validate_first_name(self, value):
        return (value or '').strip()

    def validate_last_name(self, value):
        return (value or '').strip()

    def validate(self, attrs):
        reject_forbidden_update_fields(
            self.initial_data,
            mutable_fields=MUTABLE_USER_UPDATE_FIELDS,
            immutable_fields=IMMUTABLE_USER_UPDATE_FIELDS,
        )
        return attrs


IMMUTABLE_USER_UPDATE_FIELDS = {
    'id', 'pk', 'is_staff', 'is_superuser', 'is_active', 'date_joined',
    'last_login', 'password', 'groups', 'user_permissions', 'profile',
}

MUTABLE_USER_UPDATE_FIELDS = {'username', 'first_name', 'last_name', 'email'}

IMMUTABLE_PROFILE_UPDATE_FIELDS = {
    'id', 'pk', 'user', 'user_id', 'google_id', 'is_google_user',
    'subscription_tier', 'enabled_tools', 'approval_status', 'approved_by_id',
    'approved_at', 'approval_note', 'account_type', 'created_by',
    'created_by_id', 'agent_runtime_id', 'service_grants_role',
    'access_revoked_before', 'twofa_enrolled_at', 'twofa_enforced',
    'twofa_enforcement_deadline', 'deletion_requested',
    'deletion_requested_at', 'lifecycle_state', 'deactivated_at',
    'deleted_at', 'created_at', 'updated_at',
}

MUTABLE_PROFILE_UPDATE_FIELDS = {
    'profile_picture', 'timezone', 'display_currency', 'country', 'city', 'latitude',
    'longitude', 'tool_preferences',
}


def reject_forbidden_update_fields(initial_data, *, mutable_fields, immutable_fields):
    """Raise clear validation errors for unknown or immutable update keys."""
    provided = set((initial_data or {}).keys())
    immutable = sorted(provided & immutable_fields)
    unknown = sorted(provided - mutable_fields - immutable_fields)
    errors = {}
    for field in immutable:
        errors[field] = f"Field '{field}' is immutable and cannot be updated here"
    for field in unknown:
        errors[field] = f"Field '{field}' is not a supported profile update field"
    if errors:
        raise serializers.ValidationError(errors)


class ProfileUpdateSerializer(serializers.ModelSerializer):
    """Serializer for owner-editable extended profile fields (ID-47)."""
    profile_picture = serializers.URLField(required=False, allow_blank=True, allow_null=True, max_length=500)
    timezone = serializers.CharField(required=False, allow_blank=True, allow_null=True, max_length=100)
    display_currency = serializers.CharField(required=False, allow_blank=False, max_length=8)
    country = serializers.CharField(required=False, allow_blank=True, allow_null=True, max_length=100)
    city = serializers.CharField(required=False, allow_blank=True, allow_null=True, max_length=100)
    latitude = serializers.FloatField(required=False, allow_null=True, min_value=-90, max_value=90)
    longitude = serializers.FloatField(required=False, allow_null=True, min_value=-180, max_value=180)
    tool_preferences = serializers.DictField(required=False)

    class Meta:
        model = UserProfile
        fields = sorted(MUTABLE_PROFILE_UPDATE_FIELDS)

    def validate_display_currency(self, value):
        code = str(value or '').strip().upper()
        if code not in {'USD', 'INR', 'EUR', 'GBP'}:
            raise serializers.ValidationError('Display currency must be USD, INR, EUR, or GBP')
        return code

    def validate(self, attrs):
        reject_forbidden_update_fields(
            self.initial_data,
            mutable_fields=MUTABLE_PROFILE_UPDATE_FIELDS,
            immutable_fields=IMMUTABLE_PROFILE_UPDATE_FIELDS,
        )
        return attrs


class ToolCallSerializer(serializers.ModelSerializer):
    """Serializer for ToolCall model."""

    class Meta:
        model = ToolCall
        fields = [
            'id', 'tool_name', 'raw_content', 'python_code',
            'status', 'conversation_context', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class ToolResponseSerializer(serializers.ModelSerializer):
    """Serializer for ToolResponse model."""

    class Meta:
        model = ToolResponse
        fields = [
            'id', 'tool_call', 'raw_content', 'response_data',
            'success', 'error_message', 'execution_time_ms', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class LoginSerializer(StrictInputMixin, serializers.Serializer):
    """Serializer for login requests."""
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)


class RegisterSerializer(StrictInputMixin, serializers.Serializer):
    """Serializer for registration requests."""
    username = serializers.CharField()
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)
    first_name = serializers.CharField(required=False, allow_blank=True)
    last_name = serializers.CharField(required=False, allow_blank=True)
    # ID-56 (kai's live compat audit): RegisterView reads request.data.get('intent')
    # for the Drive self-registration gate (DRV-49, register?intent=drive). It's a
    # legitimately-accepted field, so it MUST be declared or a strict flip would
    # 400 the drive-register path (regression: test_drive_self_registration.py).
    intent = serializers.CharField(required=False, allow_blank=True)
    captcha_token = serializers.CharField(required=False, allow_blank=True)
    # Honeypot — real users leave this empty. Bots that fill every field trip it.
    website = serializers.CharField(required=False, allow_blank=True)


class PasswordChangeSerializer(StrictInputMixin, serializers.Serializer):
    """Serializer for password change requests."""
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    new_password2 = serializers.CharField(write_only=True)


class TokenSerializer(serializers.Serializer):
    """Serializer for JWT tokens."""
    access = serializers.CharField()
    refresh = serializers.CharField()


class AuthResponseSerializer(serializers.Serializer):
    """Serializer for authentication responses."""
    user = UserSerializer()
    tokens = TokenSerializer()


class PasswordResetRequestSerializer(StrictInputMixin, serializers.Serializer):
    """Serializer for requesting a password reset."""
    email = serializers.EmailField()


class PasswordResetValidateSerializer(StrictInputMixin, serializers.Serializer):
    """Serializer for validating a reset token."""
    token = serializers.CharField()


class PasswordResetConfirmSerializer(StrictInputMixin, serializers.Serializer):
    """Serializer for confirming password reset with new password."""
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)
    new_password2 = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['new_password'] != data['new_password2']:
            raise serializers.ValidationError({'new_password2': 'Passwords do not match'})
        return data


# --- Service Access Control serializers ---

class ServiceWithStatusSerializer(serializers.ModelSerializer):
    """Tool/service with user-specific status fields."""
    is_enabled = serializers.BooleanField(read_only=True)
    pending_request = serializers.BooleanField(read_only=True)
    can_toggle = serializers.BooleanField(read_only=True)

    class Meta:
        model = Tool
        fields = [
            'slug', 'display_name', 'description', 'icon',
            'minimum_tier', 'is_active', 'is_default_enabled',
            'requires_approval', 'is_enabled', 'pending_request', 'can_toggle',
        ]


class ServiceAccessRequestCreateSerializer(StrictInputMixin, serializers.Serializer):
    """For creating a service access request.

    ID-42: the product-facing surface and the ``id_request_service`` MCP tool send
    the slug as ``service`` / ``service_slug`` (the internal model is ``Tool``).
    Accept any of ``tool_slug`` / ``service`` / ``service_slug`` so the MCP tool
    arg and the serializer field agree; downstream code reads
    ``validated_data['tool_slug']``.
    """
    tool_slug = serializers.SlugField(required=False)
    service = serializers.SlugField(required=False)
    service_slug = serializers.SlugField(required=False)
    reason = serializers.CharField(required=False, allow_blank=True, default='')
    organization_id = serializers.IntegerField(required=False, allow_null=True, default=None)

    def validate(self, attrs):
        slug = attrs.get('tool_slug') or attrs.get('service') or attrs.get('service_slug')
        if not slug:
            raise serializers.ValidationError(
                {'service': 'A service slug is required (send "service").'}
            )
        attrs['tool_slug'] = slug
        return attrs


class ServiceAccessRequestListSerializer(serializers.ModelSerializer):
    """For listing access requests with related info."""
    tool_slug = serializers.SlugRelatedField(source='tool', slug_field='slug', read_only=True)
    tool_name = serializers.CharField(source='tool.display_name', read_only=True)
    user_email = serializers.EmailField(source='user.email', read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model = ServiceAccessRequest
        fields = [
            'id', 'user_id', 'user_email', 'username',
            'tool_slug', 'tool_name', 'organization_id',
            'status', 'reason', 'reviewed_by_id', 'reviewed_at',
            'review_note', 'created_at', 'updated_at',
        ]


class ServiceAccessRequestReviewSerializer(StrictInputMixin, serializers.Serializer):
    """For approving/denying a request."""
    status = serializers.ChoiceField(choices=['approved', 'denied'])
    review_note = serializers.CharField(required=False, allow_blank=True, default='')
    # ID-55: the view consults `_break_glass_reason(request)` (SoD override),
    # which reads these from request.data — declare them so deny-by-default
    # accepts a legitimate break-glass review instead of 400-ing it.
    break_glass = serializers.BooleanField(required=False, default=False)
    break_glass_reason = serializers.CharField(required=False, allow_blank=True, default='')
    reason = serializers.CharField(required=False, allow_blank=True, default='')


class AdminServiceUpdateSerializer(StrictInputMixin, serializers.Serializer):
    """For updating service config (staff only)."""
    is_default_enabled = serializers.BooleanField(required=False)
    requires_approval = serializers.BooleanField(required=False)
    is_active = serializers.BooleanField(required=False)


class AdminUserServiceGrantSerializer(StrictInputMixin, serializers.Serializer):
    """For granting/revoking services for a user."""
    service_slugs = serializers.ListField(child=serializers.SlugField())
    action = serializers.ChoiceField(choices=['grant', 'revoke'])
    # ID-55: the view consults `_break_glass_reason(request)` (SoD override),
    # which reads these from request.data — declare them so deny-by-default
    # accepts a legitimate break-glass grant/revoke instead of 400-ing it.
    break_glass = serializers.BooleanField(required=False, default=False)
    break_glass_reason = serializers.CharField(required=False, allow_blank=True, default='')
    reason = serializers.CharField(required=False, allow_blank=True, default='')


class UserApprovalReviewSerializer(StrictInputMixin, serializers.Serializer):
    """For approving/denying a user account registration."""
    status = serializers.ChoiceField(choices=['approved', 'denied'])
    review_note = serializers.CharField(required=False, allow_blank=True, default='')
