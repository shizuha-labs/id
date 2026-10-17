"""
Declarative role → Shizuha-ID service allow-list (ID-12 / ID-2 P3).

This is the single source of truth for default role-based service grants.
The ``reconcile_service_grants`` management command uses it to apply grants
idempotently. It is STRICTLY ADDITIVE: reconciliation never removes an
existing approved grant — only the explicit admin revoke path may do that.

Design mirrors the SCLI-45 MCP-server access-matrix (wiki 288f65e8):
- Default-deny: an agent/user gets only what their role requires.
- Unknown role → base only (fail-closed).
- Agent base = {pulse, connect, wiki, id, mail} — the operating substrate
  every task-driven agent needs.
- Human default = {id, hive, mail}; Mail is provisioned for every active
  identity and is therefore an identity-owned baseline capability.

PLAT-317 durability guarantee:
  A consolidation roll (migration, bulk tool update) MUST NOT silently drop
  grants. Any operation that removes a service slug from the catalog must go
  through the audited admin revoke path (AdminUserServicesView POST action=revoke
  or a data migration that removes only explicitly-named slugs and logs counts).
  This matrix is the reference for "what should exist"; the reconcile command
  is the recovery mechanism if drift is detected post-roll.
"""
from __future__ import annotations

# Every task-driven agent needs the Shizuha operating substrate:
# pulse (tasks), connect (messaging), wiki (consult/document), id (self-auth).
AGENT_BASE_SERVICES: frozenset[str] = frozenset(['pulse', 'connect', 'wiki', 'id', 'mail'])

# Per-role additions on top of the agent base. Role strings are lowercase and
# match the 'role' field in the agent identity config (same convention as SCLI-45).
# Unknown/missing role → no additions (fail-closed → base only).
ROLE_ADDITIONAL_SERVICES: dict[str, frozenset[str]] = {
    'engineer':   frozenset(),
    'reviewer':   frozenset(),
    'qa':         frozenset(),
    'social':     frozenset(['drive']),
    'docs':       frozenset(['drive']),
    'architect':  frozenset(['admin']),
    'security':   frozenset(['admin']),
    'devops':     frozenset(['admin']),
    'analytics':  frozenset(['finance', 'books', 'inventory', 'time']),
    # Singleton/CoS roles (per PLAT-309 singleton override policy):
    # These carry per-agent overrides in their config; the matrix defines
    # their floor only.
    'assistant':  frozenset(['admin', 'id']),  # CoS / General Assistant
    'deputy':     frozenset(['admin', 'id']),  # Deputy CoS
    # Human accounts use a separate entry — NOT added to agent_base.
    'human':      frozenset(['hive']),
}

# Default for human accounts (PLAT-496 / ID-8).
# Separate from agent_base so a human never inherits pulse/connect/wiki by default.
HUMAN_DEFAULT_SERVICES: frozenset[str] = frozenset(['id', 'hive', 'mail'])


def get_default_services_for_role(
    role: str | None,
    *,
    account_type: str = 'human',
) -> frozenset[str]:
    """Return the declarative default service set for a role/account_type pair.

    For agent accounts (account_type='agent'):
        AGENT_BASE_SERVICES ∪ ROLE_ADDITIONAL_SERVICES.get(role, frozenset())
        Unknown/None role → AGENT_BASE_SERVICES only (fail-closed).

    For human accounts (account_type='human' or anything else):
        HUMAN_DEFAULT_SERVICES (role is ignored for humans).

    This function is the contract that reconcile_service_grants enforces.
    """
    if account_type == 'agent':
        norm = role.lower().strip() if role else ''
        additional = ROLE_ADDITIONAL_SERVICES.get(norm, frozenset())
        return AGENT_BASE_SERVICES | additional
    return HUMAN_DEFAULT_SERVICES


# Catalogue of slugs that have been intentionally removed/renamed.
# The reconcile command will not attempt to grant these (they no longer exist
# in the Tool catalog) and will log a warning if found in existing grants.
# Update this list whenever a Tool slug is retired in a data migration.
RETIRED_SERVICE_SLUGS: frozenset[str] = frozenset([
    'agent',  # Removed in migration 0023 (PLAT-496): replaced by 'hive'
])
