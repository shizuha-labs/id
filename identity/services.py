"""
Services for Shizuha ID, including email integration.
"""
import logging
import requests
from django.conf import settings

logger = logging.getLogger(__name__)


class EmailServiceError(Exception):
    """Exception for email service failures."""
    pass


def send_password_reset_email(user, reset_url):
    """
    Send password reset email via shizuha-mail service.

    Args:
        user: User object with email
        reset_url: Full URL for password reset

    Raises:
        EmailServiceError: If email sending fails
    """
    mail_service_url = getattr(settings, 'SHIZUHA_MAIL_API_URL', 'http://shizuha-mail:8014')

    subject = "Reset your Shizuha password"

    # Plain text version
    body_text = f"""Hi {user.first_name or user.username},

You requested to reset your password for your Shizuha account.

Click the link below to set a new password:
{reset_url}

This link will expire in 1 hour.

If you didn't request this, you can safely ignore this email.

- The Shizuha Team
"""

    # HTML version
    body_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">Shizuha ID</h1>
    </div>
    <div style="background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e5e7eb; border-top: none;">
        <h2 style="color: #1f2937; margin-top: 0;">Reset Your Password</h2>
        <p>Hi {user.first_name or user.username},</p>
        <p>You requested to reset your password. Click the button below to set a new one:</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{reset_url}" style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: 500;">Reset Password</a>
        </div>
        <p style="color: #6b7280; font-size: 14px;">This link will expire in 1 hour.</p>
        <p style="color: #6b7280; font-size: 14px;">If you didn't request this, you can safely ignore this email.</p>
        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
        <p style="color: #9ca3af; font-size: 12px; margin-bottom: 0;">- The Shizuha Team</p>
    </div>
</body>
</html>
"""

    try:
        response = requests.post(
            f"{mail_service_url}/api/internal/send/",
            json={
                "from_email": "noreply@shizuha.com",
                "to_addresses": [user.email],
                "subject": subject,
                "body_text": body_text,
                "body_html": body_html,
            },
            headers={"X-Internal-Service": "shizuha-id"},
            timeout=30.0
        )

        if response.status_code not in (200, 201):
            logger.error(f"Email service error: {response.text}")
            raise EmailServiceError(f"Failed to send email: {response.text}")

        logger.info("Password reset email sent")
        return True

    except requests.RequestException as e:
        logger.error(f"Email service connection error: {e}")
        raise EmailServiceError(f"Could not connect to email service: {e}")


def send_account_approved_email(user):
    """
    Send account approval notification email.

    Args:
        user: User object whose account was approved

    Raises:
        EmailServiceError: If email sending fails
    """
    mail_service_url = getattr(settings, 'SHIZUHA_MAIL_API_URL', 'http://shizuha-mail:8014')
    frontend_url = getattr(settings, 'FRONTEND_URL', 'https://erp.shizuha.com/id')
    login_url = f"{frontend_url}/login"

    subject = "Your Shizuha account has been approved"

    body_text = f"""Hi {user.first_name or user.username},

Your Shizuha account has been approved! You can now log in and start using the platform.

Click the link below to sign in:
{login_url}

- The Shizuha Team
"""

    body_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">Shizuha ID</h1>
    </div>
    <div style="background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e5e7eb; border-top: none;">
        <h2 style="color: #1f2937; margin-top: 0;">Account Approved</h2>
        <p>Hi {user.first_name or user.username},</p>
        <p>Your Shizuha account has been approved! You can now log in and start using the platform.</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{login_url}" style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: 500;">Sign In</a>
        </div>
        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
        <p style="color: #9ca3af; font-size: 12px; margin-bottom: 0;">- The Shizuha Team</p>
    </div>
</body>
</html>
"""

    try:
        response = requests.post(
            f"{mail_service_url}/api/internal/send/",
            json={
                "from_email": "noreply@shizuha.com",
                "to_addresses": [user.email],
                "subject": subject,
                "body_text": body_text,
                "body_html": body_html,
            },
            headers={"X-Internal-Service": "shizuha-id"},
            timeout=30.0
        )

        if response.status_code not in (200, 201):
            logger.error(f"Email service error: {response.text}")
            raise EmailServiceError(f"Failed to send email: {response.text}")

        logger.info(f"Account approved email sent to {user.email}")
        return True

    except requests.RequestException as e:
        logger.error(f"Email service connection error: {e}")
        raise EmailServiceError(f"Could not connect to email service: {e}")


def send_account_denied_email(user, reason=''):
    """
    Send account denial notification email.

    Args:
        user: User object whose account was denied
        reason: Optional reason for denial

    Raises:
        EmailServiceError: If email sending fails
    """
    mail_service_url = getattr(settings, 'SHIZUHA_MAIL_API_URL', 'http://shizuha-mail:8014')

    subject = "Your Shizuha account registration"

    reason_text = f"\n\nReason: {reason}" if reason else ""
    reason_html = f'<p style="color: #6b7280; font-size: 14px;">Reason: {reason}</p>' if reason else ""

    body_text = f"""Hi {user.first_name or user.username},

We've reviewed your registration for Shizuha, and unfortunately your account was not approved at this time.{reason_text}

If you believe this is a mistake, please contact support.

- The Shizuha Team
"""

    body_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">Shizuha ID</h1>
    </div>
    <div style="background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e5e7eb; border-top: none;">
        <h2 style="color: #1f2937; margin-top: 0;">Registration Not Approved</h2>
        <p>Hi {user.first_name or user.username},</p>
        <p>We've reviewed your registration for Shizuha, and unfortunately your account was not approved at this time.</p>
        {reason_html}
        <p style="color: #6b7280; font-size: 14px;">If you believe this is a mistake, please contact support.</p>
        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
        <p style="color: #9ca3af; font-size: 12px; margin-bottom: 0;">- The Shizuha Team</p>
    </div>
</body>
</html>
"""

    try:
        response = requests.post(
            f"{mail_service_url}/api/internal/send/",
            json={
                "from_email": "noreply@shizuha.com",
                "to_addresses": [user.email],
                "subject": subject,
                "body_text": body_text,
                "body_html": body_html,
            },
            headers={"X-Internal-Service": "shizuha-id"},
            timeout=30.0
        )

        if response.status_code not in (200, 201):
            logger.error(f"Email service error: {response.text}")
            raise EmailServiceError(f"Failed to send email: {response.text}")

        logger.info(f"Account denied email sent to {user.email}")
        return True

    except requests.RequestException as e:
        logger.error(f"Email service connection error: {e}")
        raise EmailServiceError(f"Could not connect to email service: {e}")


def send_account_creation_email(email, register_url):
    """
    Send account creation invitation email when password reset is requested
    for a non-existent account.

    Args:
        email: Email address to send to
        register_url: Full URL for account registration

    Raises:
        EmailServiceError: If email sending fails
    """
    mail_service_url = getattr(settings, 'SHIZUHA_MAIL_API_URL', 'http://shizuha-mail:8014')

    subject = "Create your Shizuha account"

    # Plain text version
    body_text = f"""Hi there,

Someone (hopefully you!) tried to reset a password for this email address on Shizuha, but we don't have an account with this email.

If you'd like to create an account, click the link below:
{register_url}

If you didn't request this, you can safely ignore this email.

- The Shizuha Team
"""

    # HTML version
    body_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">Shizuha ID</h1>
    </div>
    <div style="background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e5e7eb; border-top: none;">
        <h2 style="color: #1f2937; margin-top: 0;">No Account Found</h2>
        <p>Hi there,</p>
        <p>Someone tried to reset a password for this email address, but we don't have an account registered with it.</p>
        <p>If you'd like to create an account, click the button below:</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{register_url}" style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: 500;">Create Account</a>
        </div>
        <p style="color: #6b7280; font-size: 14px;">If you didn't request this, you can safely ignore this email.</p>
        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
        <p style="color: #9ca3af; font-size: 12px; margin-bottom: 0;">- The Shizuha Team</p>
    </div>
</body>
</html>
"""

    try:
        response = requests.post(
            f"{mail_service_url}/api/internal/send/",
            json={
                "from_email": "noreply@shizuha.com",
                "to_addresses": [email],
                "subject": subject,
                "body_text": body_text,
                "body_html": body_html,
            },
            headers={"X-Internal-Service": "shizuha-id"},
            timeout=30.0
        )

        if response.status_code not in (200, 201):
            logger.error(f"Email service error: {response.text}")
            raise EmailServiceError(f"Failed to send email: {response.text}")

        logger.info(f"Account creation email sent to {email}")
        return True

    except requests.RequestException as e:
        logger.error(f"Email service connection error: {e}")
        raise EmailServiceError(f"Could not connect to email service: {e}")


def _send_step_up_mail(to_email, subject, body_text):
    """Thin wrapper around the shizuha-mail internal send endpoint for step-up
    enrollment / notification emails (HLD §4.1). Mirrors the password-reset send
    path; raises EmailServiceError on failure so callers can degrade gracefully.
    """
    mail_service_url = getattr(settings, 'SHIZUHA_MAIL_API_URL', 'http://shizuha-mail:8014')
    try:
        response = requests.post(
            f"{mail_service_url}/api/internal/send/",
            json={
                "from_email": "noreply@shizuha.com",
                "to_addresses": [to_email],
                "subject": subject,
                "body_text": body_text,
            },
            headers={"X-Internal-Service": "shizuha-id"},
            timeout=30.0,
        )
        if response.status_code not in (200, 201):
            logger.error(f"Email service error: {response.text}")
            raise EmailServiceError(f"Failed to send email: {response.text}")
        return True
    except requests.RequestException as e:
        logger.error(f"Email service connection error: {e}")
        raise EmailServiceError(f"Could not connect to email service: {e}")


_STEP_UP_PURPOSE_BLURB = {
    'first_enroll': "confirm enrollment of a two-factor authenticator on your account",
    'reenroll': "confirm replacing the two-factor authenticator on your account",
    'recover': "recover access after a lost two-factor authenticator",
}


def send_step_up_enrollment_email(user, enroll_url, purpose='first_enroll'):
    """Send the §4.1 single-use email-OOB enrollment-confirmation link.

    This is the out-of-band leg a session-hijacker lacks; the TOTP secret stays
    provisional until this link is consumed.
    """
    blurb = _STEP_UP_PURPOSE_BLURB.get(purpose, _STEP_UP_PURPOSE_BLURB['first_enroll'])
    subject = "Confirm your Shizuha two-factor setup"
    body_text = f"""Hi {user.first_name or user.username},

We received a request to {blurb}.

Click the link below to confirm. It is single-use and expires shortly:
{enroll_url}

If you did not request this, do not click the link and contact support — your
account may be at risk.

- The Shizuha Team
"""
    return _send_step_up_mail(user.email, subject, body_text)


def send_step_up_notification_email(user, event='reset'):
    """Send the §4.1c out-of-band "your 2FA was reset/changed" notification.

    Detectability backstop for a TOFU bootstrap: every enroll/re-enroll/recover
    notifies the owner so a malicious change is visible and reversible.
    """
    verb = {
        'reset': "was reset",
        'reenroll': "was replaced",
        'first_enroll': "was set up",
    }.get(event, "was changed")
    subject = "Your Shizuha two-factor authenticator changed"
    body_text = f"""Hi {user.first_name or user.username},

The two-factor authenticator on your Shizuha account {verb}.

If this was you, no action is needed. If you did not do this, contact support
immediately — your account may be compromised.

- The Shizuha Team
"""
    return _send_step_up_mail(user.email, subject, body_text)


# Mail is an identity-owned default capability: every Shizuha user receives a
# managed @shizuha.com mailbox and must be able to exchange a token for it.
# Other application services remain explicit grant/approval.
DEFAULT_NEW_USER_SERVICE_SLUGS = ('id', 'hive', 'mail')


def get_default_new_user_tools():
    """Return the only tools a new non-staff user should receive by default.

    This intentionally filters by explicit slug instead of trusting
    Tool.is_default_enabled alone. The migration keeps the catalog flags aligned,
    but this helper is the runtime guardrail if a future service seed accidentally
    marks another service default-enabled.
    """
    from .models import Tool

    return Tool.objects.filter(
        slug__in=DEFAULT_NEW_USER_SERVICE_SLUGS,
        is_active=True,
        requires_approval=False,
        requires_superuser=False,
    )


def get_default_new_user_service_slugs():
    return list(get_default_new_user_tools().values_list('slug', flat=True))


def get_effective_services(user):
    """Canonical effective-service computation (INV-5 / ID-11).

    Single source of truth for enabled_services claims and admin reporting —
    every token emission site and admin report calls this instead of duplicating
    the logic. Returns a list of active tool slug strings.

    Rules:
    - staff or superuser: all active services (the audited admin-all path)
    - regular user: profile.enabled_tools filtered to active (written on grant approval)
      — if empty on first mint, auto-seeds the least-privilege defaults
    - no profile: least-privilege defaults only

    Logs safe identifiers/counts only (no profile payload or service-request details).
    """
    from .models import Tool, UserProfile
    if getattr(user, 'is_staff', False) or getattr(user, 'is_superuser', False):
        slugs = list(Tool.objects.filter(is_active=True).values_list('slug', flat=True))
        logger.debug('get_effective_services: staff/superuser user_id=%s count=%d', getattr(user, 'id', '?'), len(slugs))
        return slugs
    try:
        profile = user.profile
        slugs = list(profile.enabled_tools.filter(is_active=True).values_list('slug', flat=True))
        if not slugs:
            default_tools = get_default_new_user_tools()
            profile.enabled_tools.set(default_tools)
            slugs = list(default_tools.values_list('slug', flat=True))
            logger.info('get_effective_services: auto-seeded defaults for user_id=%s count=%d', getattr(user, 'id', '?'), len(slugs))
        return slugs
    except UserProfile.DoesNotExist:
        return list(get_default_new_user_tools().values_list('slug', flat=True))
