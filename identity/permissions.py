"""Central permission classes for Shizuha ID admin surfaces."""

from rest_framework import permissions

from .security_events import emit_boundary_denial


class IsStaffAdmin(permissions.BasePermission):
    """Allow authenticated staff administrators."""

    message = 'Staff access required'

    def has_permission(self, request, view):
        user = getattr(request, 'user', None)
        allowed = bool(user and user.is_authenticated and user.is_staff)
        boundary_event = getattr(view, 'boundary_denial_event', None)
        if not allowed and user and user.is_authenticated and boundary_event:
            emit_boundary_denial(request=request, service='id', **boundary_event)
        return allowed


class IsSuperUserAdmin(permissions.BasePermission):
    """Allow authenticated superuser administrators."""

    message = 'Superuser access required'

    def has_permission(self, request, view):
        user = getattr(request, 'user', None)
        return bool(user and user.is_authenticated and user.is_superuser)


class IsStaffOrSuperUserAdmin(permissions.BasePermission):
    """Allow authenticated staff OR superuser administrators.

    Read gate for the admin-audit ledger (HLD ID-5 §4.5): a superuser that is
    not flagged ``is_staff`` must still be able to read the audit trail.
    """

    message = 'Staff or superuser access required'

    def has_permission(self, request, view):
        user = getattr(request, 'user', None)
        return bool(
            user
            and user.is_authenticated
            and (user.is_staff or user.is_superuser)
        )
