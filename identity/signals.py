"""
Signals for automatic profile creation and onboarding.
"""
import logging
import threading
import uuid as uuid_mod

from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .canonicalization import normalize_email, normalize_username
from .models import UserProfile
from .services import get_default_new_user_tools

User = get_user_model()
logger = logging.getLogger(__name__)

# Same namespace as shizuha-agent's user_id_to_uuid()
_USER_UUID_NAMESPACE = uuid_mod.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


def _user_id_to_uuid(user_id) -> str:
    """Convert integer user ID to UUID string (matches shizuha-agent convention)."""
    return str(uuid_mod.uuid5(_USER_UUID_NAMESPACE, f"shizuha-user-{user_id}"))


@receiver(pre_save, sender=User)
def canonicalize_user_identifiers(sender, instance, **kwargs):
    """Canonicalize auth.User identifiers before every write (ID-44)."""
    instance.email = normalize_email(instance.email)
    instance.username = normalize_username(instance.username)


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Create a UserProfile when a new User is created."""
    if created:
        # Determine default tier based on staff status
        default_tier = 'enterprise' if instance.is_staff else 'free'

        profile = UserProfile.objects.create(
            user=instance,
            subscription_tier=default_tier
        )

        # Enable only least-privilege defaults for new users: account self-management
        # plus the user-owned HIVE/claws surface. Do not trust broad catalog flags here.
        profile.enabled_tools.set(get_default_new_user_tools())


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """Save the UserProfile when the User is saved."""
    if hasattr(instance, 'profile'):
        instance.profile.save()


@receiver(pre_save, sender=UserProfile)
def remember_previous_lifecycle_state(sender, instance, **kwargs):
    """Capture the persisted lifecycle edge for the transactional post-save hook."""
    if not instance.pk:
        instance._previous_lifecycle_state = None
        return
    instance._previous_lifecycle_state = (
        sender.objects.filter(pk=instance.pk)
        .values_list('lifecycle_state', flat=True)
        .first()
    )


@receiver(post_save, sender=UserProfile)
def enqueue_activation_event(sender, instance, created, **kwargs):
    """Emit ``user.activated`` whenever a profile crosses into active.

    Signal execution is synchronous with ``save()`` and therefore participates
    in the caller's database transaction.  An outbox failure rolls the user
    mutation back instead of leaving an active identity without a mailbox.
    """
    previous = getattr(instance, '_previous_lifecycle_state', None)
    if instance.lifecycle_state != 'active' or previous == 'active':
        return
    from .lifecycle import enqueue_user_activated

    enqueue_user_activated(
        user=instance.user,
        from_state=previous or 'pending',
        reason='identity became active',
    )

