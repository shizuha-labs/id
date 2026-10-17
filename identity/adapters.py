"""
Custom social account adapter for Shizuha ID.

Applies the account approval workflow to OAuth registrations.
"""
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter


class ApprovalSocialAccountAdapter(DefaultSocialAccountAdapter):
    """
    Social account adapter that sets new OAuth users to pending approval.
    """

    def save_user(self, request, sociallogin, form=None):
        user = super().save_user(request, sociallogin, form)
        user.is_active = False
        user.save(update_fields=['is_active'])
        # Set profile approval status
        from .models import UserProfile
        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.approval_status = 'pending'
        profile.save(update_fields=['approval_status'])
        return user
