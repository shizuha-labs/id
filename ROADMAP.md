# ROADMAP.md - Shizuha ID

Planned features and technical debt for the Identity service.

## Current Focus

<!-- Update as priorities change -->

- Federated authentication stabilization
- Account deletion flow

## Planned Features

### High Priority

- [ ] Password reset via email
- [ ] Email verification on signup
- [ ] Two-factor authentication (TOTP)

### Medium Priority

- [ ] Session management UI (view/revoke sessions)
- [ ] API key management for service accounts
- [ ] Additional OAuth providers (Microsoft, Apple)

### Future Considerations

- [ ] SAML/SSO for enterprise
- [ ] Passkey/WebAuthn support
- [ ] Audit log viewer

## Technical Debt

<!-- Track items needing refactoring -->

- [ ] Add rate limiting to login endpoint
- [ ] Improve token refresh logic
- [ ] Add email templates

## Recently Completed

<!-- Move items here when done, with date -->

- [x] Federated JWT authentication
- [x] Google OAuth integration
- [x] GitHub OAuth integration
- [x] User profile with location tracking
- [x] Tier-based tool access control
- [x] Account deletion support

## Notes

<!-- Context about priorities or decisions -->

JWT chosen over session-based auth for stateless microservice communication.
