"""
Django admin configuration for Shizuha ID.
"""
from django.contrib import admin
from django.db import transaction
from .admin_audit import ACTION_DJANGO_ADMIN_MUTATION, request_metadata
from .models import AdminAuditEvent, UserProfile, Tool, ToolCall, ToolResponse, RecoveryCode


class AuditedModelAdmin(admin.ModelAdmin):
    """ID-34: Django admin is a privileged mutation surface too — every
    save/delete of an audited model lands in the AdminAuditEvent ledger.

    Django wraps the admin change/delete views in ``transaction.atomic``; bulk
    delete is action-driven, so ``delete_queryset`` adds its own transaction.
    In every path a failed ledger append rolls the admin mutation back (same
    fail-closed semantics as the identity.admin_audit service wrappers).
    """

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        changed = sorted(getattr(form, 'changed_data', []) or [])
        AdminAuditEvent.objects.append(
            action=ACTION_DJANGO_ADMIN_MUTATION,
            actor=request.user,
            target_type=obj._meta.model_name,
            target_id=obj.pk,
            target_repr=str(obj)[:254],
            before={'change': bool(change)},
            after={'changed_fields': changed},
            request_metadata=request_metadata(request),
        )

    def delete_model(self, request, obj):
        target_id, target_repr = obj.pk, str(obj)[:254]
        super().delete_model(request, obj)
        AdminAuditEvent.objects.append(
            action=ACTION_DJANGO_ADMIN_MUTATION,
            actor=request.user,
            target_type=obj._meta.model_name,
            target_id=target_id,
            target_repr=target_repr,
            before={'existed': True},
            after={'deleted': True},
            request_metadata=request_metadata(request),
        )

    def delete_queryset(self, request, queryset):
        model_name = queryset.model._meta.model_name
        ids = [str(pk) for pk in queryset.values_list('pk', flat=True)]
        with transaction.atomic():
            super().delete_queryset(request, queryset)
            AdminAuditEvent.objects.append(
                action=ACTION_DJANGO_ADMIN_MUTATION,
                actor=request.user,
                target_type=model_name,
                target_id='bulk',
                target_repr=f'{len(ids)} {model_name} row(s)',
                before={'ids': ids},
                after={'deleted': True},
                request_metadata=request_metadata(request),
            )


@admin.register(UserProfile)
class UserProfileAdmin(AuditedModelAdmin):
    list_display = ['user', 'subscription_tier', 'is_google_user', 'timezone', 'twofa_enrolled_at', 'twofa_enforced', 'deletion_requested']
    list_filter = ['subscription_tier', 'is_google_user', 'twofa_enforced', 'deletion_requested']
    search_fields = ['user__username', 'user__email', 'google_id']
    readonly_fields = ['created_at', 'updated_at']
    filter_horizontal = ['enabled_tools']


@admin.register(Tool)
class ToolAdmin(AuditedModelAdmin):
    list_display = ['slug', 'display_name', 'minimum_tier', 'is_active', 'is_default_enabled']
    list_filter = ['minimum_tier', 'is_active', 'is_default_enabled', 'requires_approval']
    search_fields = ['slug', 'display_name', 'description']
    prepopulated_fields = {'slug': ('display_name',)}


@admin.register(ToolCall)
class ToolCallAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'tool_name', 'status', 'created_at']
    list_filter = ['status', 'tool_name', 'created_at']
    search_fields = ['user__username', 'tool_name']
    readonly_fields = ['id', 'created_at', 'updated_at']


@admin.register(ToolResponse)
class ToolResponseAdmin(admin.ModelAdmin):
    list_display = ['id', 'tool_call', 'user', 'success', 'execution_time_ms', 'created_at']
    list_filter = ['success', 'created_at']
    search_fields = ['user__username', 'error_message']
    readonly_fields = ['id', 'created_at']


@admin.register(RecoveryCode)
class RecoveryCodeAdmin(admin.ModelAdmin):
    list_display = ['user', 'prefix', 'created_at', 'used_at']
    list_filter = ['used_at', 'created_at']
    search_fields = ['user__username', 'user__email', 'prefix']
    readonly_fields = ['code_hash', 'prefix', 'created_at', 'used_at']


@admin.register(AdminAuditEvent)
class AdminAuditEventAdmin(admin.ModelAdmin):
    """The ledger itself is strictly read-only in Django admin."""
    list_display = ['seq', 'action', 'actor_username', 'target_type', 'target_id', 'created_at']
    list_filter = ['action', 'target_type']
    search_fields = ['actor_username', 'actor_email', 'target_id', 'target_repr']
    ordering = ['-seq']

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
