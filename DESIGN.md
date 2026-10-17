# DESIGN.md - Shizuha ID

Current architecture and implementation of the Identity service.

## Tech Stack

- **Backend**: Django 4.2+ + DRF 3.14+ + PostgreSQL + Redis
- **Frontend**: React 18 + Vite 5 + Tailwind CSS
- **Authentication**: JWT (simplejwt) + OAuth2 (AllAuth)
- **OAuth Providers**: Google, GitHub

## Project Structure

```
shizuha-id/
├── identity/              # Django project settings
├── authentication/        # Main Django app
│   ├── models.py          # UserProfile, Tool, ToolCall
│   ├── views.py           # Auth endpoints
│   ├── serializers.py     # DRF serializers
│   ├── signals.py         # Profile creation on signup
│   └── urls.py            # URL routing
├── frontend/              # React Vite app (login UI)
└── docker-compose.yml
```

## Data Models

### User & Profile

- **User**: Django built-in (username, email, password)
- **UserProfile**: Extended profile
  - Google OAuth (google_id, profile_picture)
  - Location (timezone, country, city, coordinates)
  - Subscription tier (free, basic, premium, enterprise)
  - Tool preferences

### Feature Access Control

- **Tool**: Platform feature/tool definitions
  - Minimum tier requirement
  - Approval requirement flag
  - Superuser-only flag
  - Default enablement
- **ToolCall**: Audit trail for tool executions
- **ToolResponse**: Tool execution responses

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `/api/auth/login/` | Username/email + password login |
| `/api/auth/logout/` | Logout with token blacklist |
| `/api/auth/register/` | User registration |
| `/api/auth/refresh/` | JWT token refresh |
| `/api/auth/user/` | Current user info |
| `/api/auth/profile/` | User profile management |
| `/api/auth/password/change/` | Password change |
| `/api/auth/social/google/` | Google OAuth login |
| `/api/auth/social/github/` | GitHub OAuth login |
| `/api/auth/oauth/status/` | OAuth provider status |
| `/id/api/oauth/revoke` | OAuth token revocation; accepts RFC7009 `token` or PLAT-47 authenticated `client_id` revocation |
| `/id/api/oauth/revocation-status` | Resource-server liveness check for OAuth access-token client/agent revocation cutoffs |
| `/api/auth/tools/` | Available tools list |
| `/api/auth/tools/toggle/` | Enable/disable tools |

## Authentication Flow

```
1. User submits credentials (or OAuth)
         ↓
2. Shizuha ID validates
         ↓
3. JWT access + refresh tokens issued
         ↓
4. Access token used for all API calls
         ↓
5. Refresh token used to get new access token
         ↓
6. Logout blacklists refresh token
```

## JWT Structure

```json
{
  "user_id": 123,
  "username": "john",
  "email": "john@example.com",
  "exp": 1234567890,
  "iat": 1234567800
}
```

All services validate JWT using shared `JWT_SECRET_KEY`.

## OAuth Client Emergency Revocation (PLAT-47)

`POST /id/api/oauth/revoke` keeps its RFC 7009 token-string behavior and also accepts an authenticated emergency revoke body:

```json
{
  "client_id": "mcp-auth-proxy",
  "agent_id": "ryo",
  "reason": "compromise-drill"
}
```

The `client_id` path requires staff/superuser authority, a deliberately privileged revoke token (`oauth_client_revoke: true` claim or `oauth:revoke` / `admin:oauth-revoke` scope), or an OAuth access token minted for the same `client_id` (self-revoke). Ordinary `OAuthClient.owner` users and ordinary `enabled_services` values (including the default-enabled `admin` tool slug) are not revoke authority unless they also satisfy staff/superuser, privileged revoke claim/scope, or same-client OAuth self-auth. It synchronously revokes active refresh tokens for that client (optionally narrowed to `agent_id`). Unscoped revokes update `OAuthClient.access_revoked_before`; agent-scoped revokes upsert an `OAuthClientAgentRevocationCutoff` row so access-token invalidation is scoped to matching token `username`/`email` rather than every user under the same client. DRF authentication rejects OAuth access tokens minted at or before the applicable cutoff; MCP resource servers call `/id/api/oauth/revocation-status` with a short local cache (default 30s) so locally verified OAuth JWTs are also rejected within the PLAT-47 ≤60s propagation window. The revoke endpoint emits an `oauth_client_revocation` audit signal with `(ts, revoked_client_id, revoked_agent_id_or_null, revoker_identity, reason)`.

Success returns `200 {"revoked_tokens": <count>, "revoked_at": <iso8601>}`; unauthenticated, forbidden, and unknown-client cases return `401`, `403`, and `404` respectively.

## Platform Integration

- Issues JWT tokens trusted by all services
- Tool definitions shared across platform
- UserProfile synced to other services via FederatedUser pattern
