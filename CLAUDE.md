# CLAUDE.md - Shizuha ID

## Overview

**Shizuha ID** is the identity and authentication service for the Shizuha platform. All other services validate JWT tokens issued by this service.

| Setting | Value |
|---------|-------|
| Backend Port | 8001 |
| Frontend Port | 5174 |
| Database | shizuha_id |
| URL Path | `/id/` |

## Access

| URL | Description |
|-----|-------------|
| `/id/` | Login/Register UI |
| `/id/api/` | REST API |
| `/id/admin/` | Django Admin |
| `/id/api/docs/` | API Documentation |

## API Endpoints

### Authentication
```
POST /id/api/auth/login/          # Login with email/password
POST /id/api/auth/register/       # Create new account
POST /id/api/auth/refresh/        # Refresh access token
POST /id/api/auth/logout/         # Invalidate tokens
POST /id/api/auth/password/reset/ # Request password reset
```

### User Management
```
GET  /id/api/users/me/            # Current user profile
PATCH /id/api/users/me/           # Update profile
GET  /id/api/users/{id}/          # Get user by ID
```

### OAuth
```
GET  /id/api/oauth/google/        # Google OAuth login
GET  /id/api/oauth/github/        # GitHub OAuth login
```

## Authentication Flow

```
Client                    Shizuha ID                Other Services
  │                           │                           │
  │─── POST /auth/login/ ────►│                           │
  │◄── {access, refresh} ─────│                           │
  │                           │                           │
  │─── GET /pulse/api/ ──────────────────────────────────►│
  │    Authorization: Bearer <access_token>               │
  │                           │◄─── Validate JWT ─────────│
  │◄────────────────────────────── Response ──────────────│
```

## Key Models

- **User** - Django's built-in User model
- **UserProfile** - Extended profile (avatar, bio, subscription tier)
- **Tool** - Feature flags controlling access across platform
- **RefreshToken** - JWT refresh token tracking

## Commands

All development commands run from the `compose/` directory using the master docker-compose.yaml:

```bash
# Start service with frontend
cd compose && docker compose up -d shizuha-id shizuha-id-frontend

# Run migrations
cd compose && docker compose exec shizuha-id python manage.py migrate

# Create superuser
cd compose && docker compose exec shizuha-id python manage.py createsuperuser

# Run tests
cd compose && docker compose exec shizuha-id python manage.py test

# View logs
cd compose && docker compose logs -f shizuha-id

```

## Security Notes

- **JWT Secret** must be shared across all services via `JWT_SECRET_KEY` env var
- Passwords are hashed using Django's PBKDF2
- Access tokens expire in 15 minutes, refresh tokens in 7 days
- Never log or expose tokens in error messages

## Project Structure

```
shizuha-id/
├── shizuha_id/           # Django project settings
├── users/                # Main app
│   ├── models.py         # User, UserProfile, Tool
│   ├── views.py          # Auth views
│   ├── serializers.py    # DRF serializers
│   └── authentication.py # JWT authentication
└── frontend/             # React login/register UI
```

Also reference [../CLAUDE.md](../CLAUDE.md) for platform-wide rules.
