#!/usr/bin/env python3
"""
Shizuha ID MCP Server.

Identity and authentication service tools for AI agents.

Auth Tools (unauthenticated):
- login: Authenticate and get JWT tokens
- register_user: Register a new user account
- password_reset: Request a password reset email
- password_reset_confirm: Confirm password reset with token
- refresh_token: Refresh an expired JWT access token

Auth Tools (authenticated):
- logout: Invalidate the current session / refresh token
- get_my_identity: Get current user identity from JWT
- get_current_user: Get detailed info about the current user
- update_current_user: Update the current user's fields
- get_user_profile: Get the user's profile/preferences
- update_profile: Update profile settings
- change_password: Change the current user's password

Tools/Services:
- list_available_tools: List tools available to the user
- toggle_tool: Enable/disable a tool
- list_services: List services available to the user
- toggle_service: Enable/disable a service
- request_service: Request access to a service
- list_service_requests: List the user's service access requests

Push Notifications:
- register_push_token: Register a push notification token
- unregister_push_token: Unregister a push notification token

Internal User Lookup:
- list_users: List users (internal)
- get_user_by_id: Get a user by ID (internal)
- get_user_by_email: Find user by email (internal)

Admin - User Management (superuser only):
- admin_list_all_users: List all users with filters
- admin_create_user: Create a new user
- admin_update_user: Update an existing user
- admin_delete_user: Delete a user

Admin - Account Approval (staff):
- admin_list_pending_users: List users pending approval
- admin_pending_count: Get count of users pending approval
- admin_approve_user: Approve or reject a pending user

Admin - Service Management (staff):
- admin_list_services: List all services (admin view)
- admin_update_service: Update a service configuration
- admin_get_user_services: Get services enabled for a user
- admin_set_user_services: Set services for a user
- admin_list_service_requests: List all service access requests
- admin_handle_service_request: Approve or reject a service request

All Users (staff):
- list_all_users_staff: List all users (staff-level, non-internal)
"""

import argparse
import json
import os
import sys
from typing import Optional

from base import ShizuhaMCPServer

# Add parent directory for base module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from base import ShizuhaMCPBase, run_mcp_server


def parse_args():
    """Parse command-line arguments for CLI argument compatibility."""
    parser = argparse.ArgumentParser(description="Shizuha ID MCP Server")
    parser.add_argument(
        "--jwt-token",
        help="JWT token for authentication (overrides SHIZUHA_ID_JWT_TOKEN env var)",
    )
    parser.add_argument(
        "--api-url",
        help="ID API URL (overrides SHIZUHA_ID_URL env var)",
    )
    args, _ = parser.parse_known_args()
    return args


# Parse CLI args (for callers that don't pass env vars to MCP subprocesses)
_args = parse_args()

# Configuration priority: CLI args > environment > defaults
ID_API_URL = (
    _args.api_url
    or os.environ.get("SHIZUHA_ID_URL")
    or os.environ.get("ID_API_URL")
)
ID_JWT_TOKEN = (
    _args.jwt_token
    or os.environ.get("SHIZUHA_ID_JWT_TOKEN")
    or os.environ.get("ID_JWT_TOKEN")
    or ""
)

mcp = ShizuhaMCPServer("shizuha-id", stateless_http=True)

# Advertise OAuth 2.0 discovery metadata so MCP clients can discover the auth server.
from base import _register_oauth_discovery_routes as _reg_oauth_routes
_reg_oauth_routes(mcp, "id")
base = ShizuhaMCPBase("id", 8001, api_url=ID_API_URL, jwt_token=ID_JWT_TOKEN)


# ============================================================================
# Helper: format a user dict into markdown
# ============================================================================



def _identity_api_allows_jwt_fallback(result: dict) -> bool:
    """Return True only for transport/unavailable API failures.

    Auth/authz/not-found responses are canonical ID API decisions and must not
    be hidden by unsigned local JWT claims.
    """
    status_code = result.get("status_code")
    if status_code is None:
        return True
    try:
        return int(status_code) >= 500
    except (TypeError, ValueError):
        return False

def _format_user(user: dict, heading: str = "User") -> str:
    """Render a canonical user dict as a markdown block."""
    output = f"# {heading}\n\n"
    output += f"**ID**: {user.get('id')}\n"
    output += f"**Username**: {user.get('username')}\n"
    output += f"**Email**: {user.get('email')}\n"
    name = user.get('display_name') or f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
    if name:
        output += f"**Name**: {name}\n"
    output += f"**Staff**: {user.get('is_staff', False)}\n"
    output += f"**Superuser**: {user.get('is_superuser', False)}\n"
    output += f"**Active**: {user.get('is_active', True)}\n"
    if user.get('lifecycle_state'):
        output += f"**Lifecycle**: {user.get('lifecycle_state')}\n"
    if user.get('approval_status'):
        output += f"**Approval**: {user.get('approval_status')}\n"
    if user.get('account_type'):
        output += f"**Account Type**: {user.get('account_type')}\n"
    if user.get("date_joined"):
        output += f"**Joined**: {user['date_joined']}\n"
    return output


# ============================================================================
# Auth — Unauthenticated
# ============================================================================


@mcp.tool(name="id_register_user")
def register_user(
    username: str,
    email: str,
    password: str,
    password2: str,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
) -> str:
    """
    Register a new user account in Shizuha ID.

    Args:
        username: Unique username for the account
        email: Email address (must be unique)
        password: Password for the account
        password2: Password confirmation (must match password)
        first_name: Optional first name
        last_name: Optional last name

    Returns user information and JWT tokens on success.
    """
    data = {
        "username": username,
        "email": email,
        "password": password,
        "password2": password2,
    }
    if first_name:
        data["first_name"] = first_name
    if last_name:
        data["last_name"] = last_name

    result = base.api_request("POST", "/auth/register/", data=data, authenticated=False)
    if "error" in result:
        return base.format_error(result)

    user = result.get("user", {})
    tokens = result.get("tokens", {})

    output = "# Registration Successful!\n\n"
    output += f"**Username**: {user.get('username')}\n"
    output += f"**Email**: {user.get('email')}\n"
    output += f"**User ID**: {user.get('id')}\n"
    output += f"**Active**: {user.get('is_active', True)}\n\n"

    if tokens:
        output += "## Authentication Tokens\n"
        output += f"**Access Token**: {tokens.get('access', 'N/A')[:50]}...\n"
        output += f"**Refresh Token**: {tokens.get('refresh', 'N/A')[:50]}...\n"

    return output


@mcp.tool(name="id_login")
def login(username: str, password: str) -> str:
    """
    Authenticate a user and get JWT tokens.

    Args:
        username: User's username or email address
        password: User's password

    Returns JWT access and refresh tokens on success.
    """
    data = {
        "username": username,
        "password": password,
    }

    result = base.api_request("POST", "/auth/login/", data=data, authenticated=False)
    if "error" in result:
        return base.format_error(result)

    user = result.get("user", {})
    tokens = result.get("tokens", {})

    output = "# Login Successful!\n\n"
    output += f"**Username**: {user.get('username')}\n"
    output += f"**Email**: {user.get('email')}\n"
    output += f"**User ID**: {user.get('id')}\n\n"

    if tokens:
        output += "## Authentication Tokens\n"
        output += f"**Access Token**: {tokens.get('access', 'N/A')[:50]}...\n"
        output += f"**Refresh Token**: {tokens.get('refresh', 'N/A')[:50]}...\n"

    return output


@mcp.tool(name="id_password_reset")
def password_reset(email: str) -> str:
    """
    Request a password reset email.

    Args:
        email: The email address associated with the account

    Sends a password reset link to the email if the account exists.
    This endpoint does not reveal whether the email is registered.
    """
    data = {"email": email}
    result = base.api_request("POST", "/auth/password/reset/", data=data, authenticated=False)
    if "error" in result:
        return base.format_error(result)

    return "# Password Reset Requested\n\nIf an account with that email exists, a password reset link has been sent."


@mcp.tool(name="id_password_reset_confirm")
def password_reset_confirm(uid: str, token: str, new_password: str, new_password2: str) -> str:
    """
    Confirm a password reset using the token from the reset email.

    Args:
        uid: The user ID from the reset link (base64-encoded)
        token: The reset token from the reset link
        new_password: The new password
        new_password2: Password confirmation (must match new_password)

    Completes the password reset process.
    """
    data = {
        "uid": uid,
        "token": token,
        "new_password": new_password,
        "new_password2": new_password2,
    }
    result = base.api_request("POST", "/auth/password/reset/confirm/", data=data, authenticated=False)
    if "error" in result:
        return base.format_error(result)

    return "# Password Reset Complete\n\nYour password has been successfully changed. You can now log in with your new password."


@mcp.tool(name="id_refresh_token")
def refresh_token(refresh: str) -> str:
    """
    Refresh an expired JWT access token.

    Args:
        refresh: The refresh token from a previous login

    Returns a new access token (and possibly a new refresh token).
    """
    data = {"refresh": refresh}
    result = base.api_request("POST", "/auth/refresh/", data=data, authenticated=False)
    if "error" in result:
        return base.format_error(result)

    output = "# Token Refreshed\n\n"
    output += f"**Access Token**: {result.get('access', 'N/A')[:50]}...\n"
    if result.get("refresh"):
        output += f"**Refresh Token**: {result['refresh'][:50]}...\n"

    return output


# ============================================================================
# Auth — Authenticated
# ============================================================================


@mcp.tool(name="id_logout")
def logout(refresh: Optional[str] = None) -> str:
    """
    Log out the current user and invalidate tokens.

    Args:
        refresh: Optional refresh token to blacklist. If not provided, only the server session is invalidated.
    """
    data = {}
    if refresh:
        data["refresh"] = refresh

    result = base.api_request("POST", "/auth/logout/", data=data)
    if "error" in result:
        return base.format_error(result)

    return "# Logged Out\n\nSession has been invalidated."


@mcp.tool(name="id_get_my_identity")
def get_my_identity() -> str:
    """
    Get the authenticated user's identity.

    Returns canonical user ID, email, username, and profile/lifecycle fields
    from the ID API. Falls back to decoded JWT claims only if the API is unavailable.
    """
    result = base.api_request("GET", "/auth/user/")
    if "error" not in result:
        return json.dumps(result, indent=2)
    if not _identity_api_allows_jwt_fallback(result):
        return base.format_error(result)
    identity = base.get_identity()
    if "error" in identity:
        return base.format_error(result)
    return json.dumps(identity, indent=2)


@mcp.tool(name="id_get_current_user")
def get_current_user() -> str:
    """
    Get detailed information about the current authenticated user.

    Returns full user data including profile information via GET /auth/user/.
    """
    result = base.api_request("GET", "/auth/user/")
    if "error" in result:
        return base.format_error(result)

    user = result
    output = _format_user(user, heading=f"User: {user.get('username', 'Unknown')}")

    profile = user.get('profile', {})
    if profile:
        output += f"\n## Profile\n"
        output += f"**Subscription**: {profile.get('subscription_tier', 'free')}\n"
        output += f"**Timezone**: {profile.get('timezone', 'UTC')}\n"
        output += f"**Location**: {profile.get('city', '')}, {profile.get('country', '')}\n"

    return output


@mcp.tool(name="id_update_current_user")
def update_current_user(
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    email: Optional[str] = None,
) -> str:
    """
    Update the current authenticated user's basic fields.

    Args:
        first_name: New first name (optional)
        last_name: New last name (optional)
        email: New email address (optional)

    Only provided fields will be updated. Uses PATCH /auth/user/.
    """
    data = {}
    if first_name is not None:
        data["first_name"] = first_name
    if last_name is not None:
        data["last_name"] = last_name
    if email is not None:
        data["email"] = email

    if not data:
        return "Error: No fields provided to update."

    result = base.api_request("PATCH", "/auth/user/", data=data)
    if "error" in result:
        return base.format_error(result)

    return _format_user(result, heading="User Updated")


@mcp.tool(name="id_get_user_profile")
def get_user_profile(username: Optional[str] = None) -> str:
    """
    Get a canonical user profile.

    Args:
        username: Optional username to resolve via the internal canonical user lookup.
            If omitted, returns the current authenticated user's canonical record.
    """
    if username:
        result = base.api_request("GET", "/internal/users/by-username/", params={"username": username})
    else:
        result = base.api_request("GET", "/auth/user/")
    if "error" in result:
        return base.format_error(result)

    output = _format_user(result, heading="User Profile")
    profile = result.get('profile', {})
    if profile:
        output += f"\n## Profile\n"
        output += f"**Subscription Tier**: {profile.get('subscription_tier', 'free')}\n"
        output += f"**Timezone**: {profile.get('timezone', 'UTC')}\n"
        output += f"**Country**: {profile.get('country', 'N/A')}\n"
        output += f"**City**: {profile.get('city', 'N/A')}\n"
        enabled_tools = profile.get('enabled_tools', [])
        if enabled_tools:
            output += f"\n## Enabled Tools\n"
            for tool in enabled_tools:
                output += f"- {tool}\n"
    return output


@mcp.tool(name="id_update_profile")
def update_profile(
    timezone: Optional[str] = None,
    country: Optional[str] = None,
    city: Optional[str] = None,
    latitude: Optional[float] = None,
    longitude: Optional[float] = None,
) -> str:
    """
    Update the user's profile settings.

    Args:
        timezone: Timezone (e.g., 'America/New_York')
        country: Country name
        city: City name
        latitude: Geographic latitude
        longitude: Geographic longitude

    Only provided fields will be updated.
    """
    data = {}
    if timezone is not None:
        data["timezone"] = timezone
    if country is not None:
        data["country"] = country
    if city is not None:
        data["city"] = city
    if latitude is not None:
        data["latitude"] = latitude
    if longitude is not None:
        data["longitude"] = longitude

    if not data:
        return "Error: No fields provided to update."

    result = base.api_request("PATCH", "/auth/profile/", data=data)
    if "error" in result:
        return base.format_error(result)

    return f"Profile updated successfully!\n\n{json.dumps(result, indent=2)}"


@mcp.tool(name="id_change_password")
def change_password(old_password: str, new_password: str, new_password2: str) -> str:
    """
    Change the current user's password.

    Args:
        old_password: The current password
        new_password: The new password
        new_password2: New password confirmation (must match new_password)

    Requires the current password for verification.
    """
    data = {
        "old_password": old_password,
        "new_password": new_password,
        "new_password2": new_password2,
    }
    result = base.api_request("POST", "/auth/password/change/", data=data)
    if "error" in result:
        return base.format_error(result)

    return "# Password Changed\n\nYour password has been successfully updated."


# ============================================================================
# Tools & Services
# ============================================================================


@mcp.tool(name="id_list_available_tools")
def list_available_tools() -> str:
    """
    List all tools available to the current user.

    Tools are filtered by the user's subscription tier.
    """
    result = base.api_request("GET", "/auth/tools/")
    if "error" in result:
        return base.format_error(result)

    tools = result if isinstance(result, list) else result.get("results", [])
    if not tools:
        return "No tools available."

    output = f"# Available Tools ({len(tools)})\n\n"
    for tool in tools:
        status = "+" if tool.get("is_default_enabled") else "o"
        output += f"- [{status}] **{tool.get('display_name', tool.get('slug'))}**\n"
        output += f"  Slug: `{tool.get('slug')}`\n"
        if tool.get("description"):
            output += f"  {tool['description']}\n"
        output += f"  Min Tier: {tool.get('minimum_tier', 'free')}\n\n"

    return output


@mcp.tool(name="id_toggle_tool")
def toggle_tool(tool_slug: str, enable: bool) -> str:
    """
    Enable or disable a tool for the current user.

    Args:
        tool_slug: The tool's slug identifier
        enable: True to enable, False to disable
    """
    data = {"tool": tool_slug, "enable": enable}
    result = base.api_request("POST", "/auth/tools/toggle/", data=data)
    if "error" in result:
        return base.format_error(result)

    action = "enabled" if enable else "disabled"
    return f"Tool '{tool_slug}' has been {action}."


@mcp.tool(name="id_list_services")
def list_services() -> str:
    """
    List all services available to the current user.

    Returns services with their enabled/disabled status and descriptions.
    """
    result = base.api_request("GET", "/auth/services/")
    if "error" in result:
        return base.format_error(result)

    services = result if isinstance(result, list) else result.get("results", [])
    if not services:
        return "No services available."

    output = f"# Available Services ({len(services)})\n\n"
    for svc in services:
        status = "+" if svc.get("is_enabled") else "o"
        output += f"- [{status}] **{svc.get('display_name', svc.get('slug'))}**\n"
        output += f"  Slug: `{svc.get('slug')}`\n"
        if svc.get("description"):
            output += f"  {svc['description']}\n"
        output += "\n"

    return output


@mcp.tool(name="id_toggle_service")
def toggle_service(service_slug: str, enable: bool) -> str:
    """
    Enable or disable a service for the current user.

    Args:
        service_slug: The service's slug identifier
        enable: True to enable, False to disable
    """
    data = {"service": service_slug, "enable": enable}
    result = base.api_request("POST", "/auth/services/toggle/", data=data)
    if "error" in result:
        return base.format_error(result)

    action = "enabled" if enable else "disabled"
    return f"Service '{service_slug}' has been {action}."


@mcp.tool(name="id_request_service")
def request_service(service_slug: str, reason: Optional[str] = None) -> str:
    """
    Request access to a service that requires approval.

    Args:
        service_slug: The service's slug identifier
        reason: Optional reason for requesting access

    Creates a pending request that an admin must approve.
    """
    data = {"service": service_slug}
    if reason:
        data["reason"] = reason

    result = base.api_request("POST", "/auth/services/request/", data=data)
    if "error" in result:
        return base.format_error(result)

    output = "# Service Access Requested\n\n"
    output += f"**Service**: {service_slug}\n"
    output += f"**Status**: {result.get('status', 'pending')}\n"
    if result.get("id"):
        output += f"**Request ID**: {result['id']}\n"

    return output


@mcp.tool(name="id_list_service_requests")
def list_service_requests() -> str:
    """
    List the current user's service access requests.

    Returns all requests with their approval status.
    """
    result = base.api_request("GET", "/auth/services/requests/")
    if "error" in result:
        return base.format_error(result)

    requests_list = result if isinstance(result, list) else result.get("results", [])
    if not requests_list:
        return "No service requests found."

    output = f"# Service Requests ({len(requests_list)})\n\n"
    for req in requests_list:
        status = req.get("status", "unknown")
        output += f"- **{req.get('service', req.get('service_slug', 'Unknown'))}** "
        output += f"[{status}]\n"
        if req.get("reason"):
            output += f"  Reason: {req['reason']}\n"
        if req.get("created_at"):
            output += f"  Requested: {req['created_at']}\n"
        if req.get("reviewed_at"):
            output += f"  Reviewed: {req['reviewed_at']}\n"
        output += "\n"

    return output


# ============================================================================
# Push Notifications
# ============================================================================


@mcp.tool(name="id_register_push_token")
def register_push_token(token: str, platform: str = "android") -> str:
    """
    Register a push notification token for the current user.

    Args:
        token: The push notification token (FCM, APNs, or Expo)
        platform: Platform identifier (android, ios, web). Default: android.
    """
    data = {"token": token, "platform": platform}
    result = base.api_request("POST", "/auth/push-token/", data=data)
    if "error" in result:
        return base.format_error(result)

    return f"# Push Token Registered\n\n**Platform**: {platform}\n**Token**: {token[:30]}..."


@mcp.tool(name="id_unregister_push_token")
def unregister_push_token(token: str) -> str:
    """
    Unregister a push notification token.

    Args:
        token: The push notification token to remove
    """
    result = base.api_request("DELETE", "/auth/push-token/", data={"token": token})
    if "error" in result:
        return base.format_error(result)

    return "# Push Token Removed\n\nThe push notification token has been unregistered."


# ============================================================================
# Internal User Lookup
# ============================================================================


@mcp.tool(name="id_list_users")
def list_users(user_ids: Optional[str] = None, search: Optional[str] = None, limit: int = 20, offset: int = 0) -> str:
    """
    List users (internal API).

    Args:
        user_ids: Comma-separated list of user IDs to fetch
        search: Optional username/email/name search term
        limit: Maximum number of users to return
        offset: Pagination offset after server-side scoping

    Note: This uses the internal API and may require elevated permissions.
    """
    params = {"limit": min(limit, 100), "offset": max(offset, 0)}
    if user_ids:
        params["ids"] = user_ids
    if search:
        params["search"] = search

    result = base.api_request("GET", "/internal/users/", params=params)
    if "error" in result:
        return base.format_error(result)

    users = result if isinstance(result, list) else result.get("results", [])
    if not users:
        return "No users found."

    total = len(users) if isinstance(result, list) else result.get("count", len(users))
    output = f"# Users ({len(users)} of {total} visible)\n\n"
    for user in users:
        output += f"- **{user.get('username')}** ({user.get('email')})\n"
        output += f"  ID: {user.get('id')}\n"
        name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
        if name:
            output += f"  Name: {name}\n"

    return output


@mcp.tool(name="id_get_user_by_id")
def get_user_by_id(user_id: int) -> str:
    """
    Get a single user by their ID (internal API).

    Args:
        user_id: The ID of the user to retrieve

    Note: This uses the internal API and may require elevated permissions.
    """
    result = base.api_request("GET", f"/internal/users/{user_id}/")
    if "error" in result:
        return base.format_error(result)

    return _format_user(result, heading="User Found")


@mcp.tool(name="id_get_user_by_email")
def get_user_by_email(email: str) -> str:
    """
    Find a user by their email address.

    Args:
        email: The email address to search for

    Note: This uses the internal API and may require elevated permissions.
    """
    result = base.api_request("GET", "/internal/users/by-email/", params={"email": email})
    if "error" in result:
        return base.format_error(result)

    return _format_user(result, heading="User Found")


@mcp.tool(name="id_get_user_by_username")
def get_user_by_username(username: str) -> str:
    """
    Find a user by their username using the canonical internal lookup.

    Args:
        username: Username to search for (case-insensitive).
    """
    result = base.api_request("GET", "/internal/users/by-username/", params={"username": username})
    if "error" in result:
        return base.format_error(result)
    return _format_user(result, heading="User Found")


# ============================================================================
# All Users — Staff (non-internal)
# ============================================================================


@mcp.tool(name="id_list_all_users_staff")
def list_all_users_staff(
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> str:
    """
    List all users (staff-level endpoint, not internal admin).

    Args:
        search: Search in username, email, first/last name
        limit: Max results per page (1-100, default: 50)
        offset: Pagination offset (default: 0)

    Requires: Staff authentication. Uses GET /auth/users/all/.
    """
    params = {
        "limit": min(max(limit, 1), 100),
        "offset": max(offset, 0),
    }
    if search:
        params["search"] = search

    result = base.api_request("GET", "/auth/users/all/", params=params)
    if "error" in result:
        return base.format_error(result)

    count = result.get("count", 0) if isinstance(result, dict) else len(result)
    users = result.get("results", result) if isinstance(result, dict) else result
    if not isinstance(users, list):
        users = [users]

    if not users:
        return "No users found."

    output = f"# All Users ({len(users)} of {count})\n\n"
    for user in users:
        flags = []
        if user.get("is_superuser"):
            flags.append("superuser")
        if user.get("is_staff"):
            flags.append("staff")
        if not user.get("is_active", True):
            flags.append("inactive")
        flag_str = f" [{', '.join(flags)}]" if flags else ""
        output += f"- **{user.get('username')}** ({user.get('email')}){flag_str}\n"
        output += f"  ID: {user.get('id')}\n"
        name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
        if name:
            output += f"  Name: {name}\n"

    return output


# ============================================================================
# Admin — User Management (Superuser Only)
# ============================================================================


@mcp.tool(name="id_admin_create_user")
def admin_create_user(
    username: str,
    email: str,
    password: str,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    is_staff: bool = False,
    is_superuser: bool = False,
    is_active: bool = True,
) -> str:
    """
    Create a new user account (superuser only).

    Args:
        username: Unique username for the account
        email: Email address (must be unique)
        password: Password for the account
        first_name: Optional first name
        last_name: Optional last name
        is_staff: Whether user has staff access (default: False)
        is_superuser: Whether user has superuser access (default: False)
        is_active: Whether user account is active (default: True)

    Returns user information on success.
    Requires: Superuser authentication.
    """
    data = {
        "username": username,
        "email": email,
        "password": password,
        "is_staff": is_staff,
        "is_superuser": is_superuser,
        "is_active": is_active,
    }
    if first_name:
        data["first_name"] = first_name
    if last_name:
        data["last_name"] = last_name

    result = base.api_request("POST", "/internal/admin/users/create/", data=data)
    if "error" in result:
        return base.format_error(result)

    return _format_user(result, heading="User Created Successfully!")


@mcp.tool(name="id_admin_update_user")
def admin_update_user(
    user_id: int,
    username: Optional[str] = None,
    email: Optional[str] = None,
    password: Optional[str] = None,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    is_staff: Optional[bool] = None,
    is_superuser: Optional[bool] = None,
    is_active: Optional[bool] = None,
) -> str:
    """
    Update an existing user (superuser only).

    Args:
        user_id: The ID of the user to update
        username: New username (optional)
        email: New email address (optional)
        password: New password (optional)
        first_name: New first name (optional)
        last_name: New last name (optional)
        is_staff: New staff status (optional)
        is_superuser: New superuser status (optional)
        is_active: New active status (optional)

    Only provided fields will be updated.
    Requires: Superuser authentication.
    """
    data = {}
    if username is not None:
        data["username"] = username
    if email is not None:
        data["email"] = email
    if password is not None:
        data["password"] = password
    if first_name is not None:
        data["first_name"] = first_name
    if last_name is not None:
        data["last_name"] = last_name
    if is_staff is not None:
        data["is_staff"] = is_staff
    if is_superuser is not None:
        data["is_superuser"] = is_superuser
    if is_active is not None:
        data["is_active"] = is_active

    if not data:
        return "Error: No fields provided to update."

    result = base.api_request("PATCH", f"/internal/admin/users/{user_id}/", data=data)
    if "error" in result:
        return base.format_error(result)

    return _format_user(result, heading="User Updated Successfully!")


@mcp.tool(name="id_admin_delete_user")
def admin_delete_user(user_id: int) -> str:
    """
    Delete a user (superuser only).

    Args:
        user_id: The ID of the user to delete

    Warning: This permanently deletes the user account.
    Cannot delete your own account.
    Requires: Superuser authentication.
    """
    result = base.api_request("DELETE", f"/internal/admin/users/{user_id}/delete/")
    if "error" in result:
        return base.format_error(result)

    return f"# User Deleted\n\n{result.get('message', 'User deleted successfully.')}"


@mcp.tool(name="id_admin_list_all_users")
def admin_list_all_users(
    search: Optional[str] = None,
    is_staff: Optional[bool] = None,
    is_superuser: Optional[bool] = None,
    is_active: Optional[bool] = None,
    order_by: str = "-date_joined",
    limit: int = 50,
    offset: int = 0,
) -> str:
    """
    List all users with filtering (superuser only).

    Args:
        search: Search in username, email, first/last name
        is_staff: Filter by staff status
        is_superuser: Filter by superuser status
        is_active: Filter by active status
        order_by: Field to order by (default: -date_joined)
        limit: Max results per page (1-100, default: 50)
        offset: Pagination offset (default: 0)

    Requires: Superuser authentication.
    """
    params = {
        "order_by": order_by,
        "limit": min(max(limit, 1), 100),
        "offset": max(offset, 0),
    }
    if search:
        params["search"] = search
    if is_staff is not None:
        params["is_staff"] = "true" if is_staff else "false"
    if is_superuser is not None:
        params["is_superuser"] = "true" if is_superuser else "false"
    if is_active is not None:
        params["is_active"] = "true" if is_active else "false"

    result = base.api_request("GET", "/internal/admin/users/", params=params)
    if "error" in result:
        return base.format_error(result)

    count = result.get("count", 0)
    users = result.get("results", [])

    output = f"# Users ({len(users)} of {count})\n\n"
    output += f"*Page: {offset // limit + 1} | Limit: {limit} | Order: {order_by}*\n\n"

    if not users:
        output += "No users found.\n"
        return output

    for user in users:
        flags = []
        if user.get("is_superuser"):
            flags.append("superuser")
        if user.get("is_staff"):
            flags.append("staff")
        if not user.get("is_active", True):
            flags.append("inactive")

        flag_str = f" [{', '.join(flags)}]" if flags else ""
        output += f"- **{user.get('username')}** ({user.get('email')}){flag_str}\n"
        output += f"  ID: {user.get('id')}\n"
        name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
        if name:
            output += f"  Name: {name}\n"
        if user.get("date_joined"):
            output += f"  Joined: {user.get('date_joined')}\n"
        output += "\n"

    return output


# ============================================================================
# Admin — Account Approval (Staff)
# ============================================================================


@mcp.tool(name="id_admin_list_pending_users")
def admin_list_pending_users() -> str:
    """
    List users pending approval (staff only).

    Returns users whose accounts require admin approval before activation.
    Requires: Staff authentication.
    """
    result = base.api_request("GET", "/auth/admin/users/pending/")
    if "error" in result:
        return base.format_error(result)

    users = result if isinstance(result, list) else result.get("results", [])
    if not users:
        return "No users pending approval."

    output = f"# Pending Users ({len(users)})\n\n"
    for user in users:
        output += f"- **{user.get('username')}** ({user.get('email')})\n"
        output += f"  ID: {user.get('id')}\n"
        name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
        if name:
            output += f"  Name: {name}\n"
        if user.get("date_joined"):
            output += f"  Registered: {user['date_joined']}\n"
        output += "\n"

    return output


@mcp.tool(name="id_admin_pending_count")
def admin_pending_count() -> str:
    """
    Get the count of users pending approval (staff only).

    Returns just the count for dashboard/badge display.
    Requires: Staff authentication.
    """
    result = base.api_request("GET", "/auth/admin/users/pending/count/")
    if "error" in result:
        return base.format_error(result)

    count = result.get("count", 0)
    return f"# Pending Approvals\n\n**Count**: {count}"


@mcp.tool(name="id_admin_approve_user")
def admin_approve_user(user_id: int, approved: bool, reason: Optional[str] = None) -> str:
    """
    Approve or reject a pending user account (staff only).

    Args:
        user_id: The ID of the user to approve/reject
        approved: True to approve, False to reject
        reason: Optional reason for the decision

    Requires: Staff authentication.
    """
    # ID-38: the approve endpoint's UserApprovalReviewSerializer requires
    # `status` ('approved'|'denied') + optional `review_note` (ID-32/ID-34
    # lifecycle work changed the contract). Sending the legacy `approved` bool /
    # `reason` was silently dropped and 400'd ("status: This field is required").
    data = {"status": "approved" if approved else "denied"}
    if reason:
        data["review_note"] = reason

    result = base.api_request("PATCH", f"/auth/admin/users/{user_id}/approve/", data=data)
    if "error" in result:
        return base.format_error(result)

    action = "approved" if approved else "rejected"
    output = f"# User {action.title()}\n\n"
    output += f"**User ID**: {user_id}\n"
    output += f"**Decision**: {action}\n"
    if reason:
        output += f"**Reason**: {reason}\n"

    return output


# ============================================================================
# Admin — Service Management (Staff)
# ============================================================================


@mcp.tool(name="id_admin_list_services")
def admin_list_services() -> str:
    """
    List all services with admin details (staff only).

    Returns all services with configuration, quotas, and usage info.
    Requires: Staff authentication.
    """
    result = base.api_request("GET", "/auth/admin/services/")
    if "error" in result:
        return base.format_error(result)

    services = result if isinstance(result, list) else result.get("results", [])
    if not services:
        return "No services found."

    output = f"# Services (Admin) ({len(services)})\n\n"
    for svc in services:
        output += f"## {svc.get('display_name', svc.get('slug'))}\n"
        output += f"**Slug**: `{svc.get('slug')}`\n"
        if svc.get("description"):
            output += f"**Description**: {svc['description']}\n"
        output += f"**Active**: {svc.get('is_active', True)}\n"
        if svc.get("requires_approval"):
            output += f"**Requires Approval**: Yes\n"
        if svc.get("minimum_tier"):
            output += f"**Min Tier**: {svc['minimum_tier']}\n"
        output += "\n"

    return output


@mcp.tool(name="id_admin_update_service")
def admin_update_service(
    slug: str,
    display_name: Optional[str] = None,
    description: Optional[str] = None,
    is_active: Optional[bool] = None,
    requires_approval: Optional[bool] = None,
    minimum_tier: Optional[str] = None,
) -> str:
    """
    Update a service configuration (staff only).

    Args:
        slug: The service slug to update
        display_name: New display name (optional)
        description: New description (optional)
        is_active: Enable/disable the service (optional)
        requires_approval: Whether the service requires admin approval (optional)
        minimum_tier: Minimum subscription tier (optional)

    Only provided fields will be updated.
    Requires: Staff authentication.
    """
    data = {}
    if display_name is not None:
        data["display_name"] = display_name
    if description is not None:
        data["description"] = description
    if is_active is not None:
        data["is_active"] = is_active
    if requires_approval is not None:
        data["requires_approval"] = requires_approval
    if minimum_tier is not None:
        data["minimum_tier"] = minimum_tier

    if not data:
        return "Error: No fields provided to update."

    result = base.api_request("PATCH", f"/auth/admin/services/{slug}/", data=data)
    if "error" in result:
        return base.format_error(result)

    output = "# Service Updated\n\n"
    output += f"**Slug**: `{slug}`\n"
    output += json.dumps(result, indent=2)
    return output


@mcp.tool(name="id_admin_get_user_services")
def admin_get_user_services(user_id: int) -> str:
    """
    Get the services enabled for a specific user (staff only).

    Args:
        user_id: The ID of the user to check

    Returns the list of services and their status for that user.
    Requires: Staff authentication.
    """
    result = base.api_request("GET", f"/auth/admin/users/{user_id}/services/")
    if "error" in result:
        return base.format_error(result)

    services = result if isinstance(result, list) else result.get("results", result.get("services", []))
    if not services:
        return f"No services found for user {user_id}."

    output = f"# Services for User {user_id}\n\n"
    if isinstance(services, list):
        for svc in services:
            if isinstance(svc, dict):
                status = "+" if svc.get("is_enabled") else "o"
                output += f"- [{status}] **{svc.get('display_name', svc.get('slug'))}**\n"
                output += f"  Slug: `{svc.get('slug')}`\n"
            else:
                output += f"- {svc}\n"
    else:
        output += json.dumps(services, indent=2)

    return output


@mcp.tool(name="id_admin_set_user_services")
def admin_set_user_services(user_id: int, services: str) -> str:
    """
    Set the services for a specific user (staff only).

    Args:
        user_id: The ID of the user to update
        services: JSON string of service configurations. Example: [{"slug": "notes", "enabled": true}]

    Requires: Staff authentication.
    """
    try:
        services_data = json.loads(services)
    except json.JSONDecodeError:
        return "Error: 'services' must be a valid JSON string."

    data = {"services": services_data} if isinstance(services_data, list) else services_data

    result = base.api_request("POST", f"/auth/admin/users/{user_id}/services/", data=data)
    if "error" in result:
        return base.format_error(result)

    return f"# User Services Updated\n\n**User ID**: {user_id}\n\nServices have been updated successfully."


@mcp.tool(name="id_admin_list_service_requests")
def admin_list_service_requests(
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> str:
    """
    List all service access requests across users (staff only).

    Args:
        status: Filter by status (pending, approved, rejected). Default: all.
        limit: Max results per page (default: 50)
        offset: Pagination offset (default: 0)

    Requires: Staff authentication.
    """
    params = {
        "limit": min(max(limit, 1), 100),
        "offset": max(offset, 0),
    }
    if status:
        params["status"] = status

    result = base.api_request("GET", "/auth/admin/requests/", params=params)
    if "error" in result:
        return base.format_error(result)

    count = result.get("count", 0) if isinstance(result, dict) else len(result)
    requests_list = result.get("results", result) if isinstance(result, dict) else result
    if not isinstance(requests_list, list):
        requests_list = []

    if not requests_list:
        return "No service requests found."

    output = f"# Service Requests ({len(requests_list)} of {count})\n\n"
    for req in requests_list:
        output += f"- **Request #{req.get('id', 'N/A')}**\n"
        output += f"  User: {req.get('username', req.get('user', 'N/A'))}\n"
        output += f"  Service: {req.get('service', req.get('service_slug', 'N/A'))}\n"
        output += f"  Status: {req.get('status', 'unknown')}\n"
        if req.get("reason"):
            output += f"  Reason: {req['reason']}\n"
        if req.get("created_at"):
            output += f"  Requested: {req['created_at']}\n"
        output += "\n"

    return output


@mcp.tool(name="id_admin_handle_service_request")
def admin_handle_service_request(request_id: int, approved: bool, reason: Optional[str] = None) -> str:
    """
    Approve or reject a service access request (staff only).

    Args:
        request_id: The ID of the service request to handle
        approved: True to approve, False to reject
        reason: Optional reason for the decision

    Requires: Staff authentication.
    """
    data = {"approved": approved}
    if reason:
        data["reason"] = reason

    result = base.api_request("PATCH", f"/auth/admin/requests/{request_id}/", data=data)
    if "error" in result:
        return base.format_error(result)

    action = "approved" if approved else "rejected"
    output = f"# Service Request {action.title()}\n\n"
    output += f"**Request ID**: {request_id}\n"
    output += f"**Decision**: {action}\n"
    if reason:
        output += f"**Reason**: {reason}\n"

    return output


# ============================================================================
# Entry Point
# ============================================================================


def main():
    """Run the MCP server."""
    run_mcp_server(mcp, base)


if __name__ == "__main__":
    main()
