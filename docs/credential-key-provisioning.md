# AgentCredential payload key provisioning

ADR-PLAT-001 S2b requires AgentCredential payload encryption to use a dedicated MultiFernet key file, not Django `SECRET_KEY`.

## Active key

Provision the active key on the daemon host as the daemon user (or as root with explicit ownership):

```bash
python manage.py provision_credential_key --path /etc/shizuha/credential.key
# or, when run by root/systemd:
python manage.py provision_credential_key --path /etc/shizuha/credential.key --owner-uid <daemon-uid> --owner-gid <daemon-gid>
```

The command is idempotent. It creates the file only if absent, tightens the key to `0600`, tightens the parent directory to `0700`, and never prints the generated key material. When `--owner-uid/--owner-gid` are supplied, both `/etc/shizuha` and `/etc/shizuha/credential.key` are chowned to the daemon user/group so a daemon-owned key is reachable on fresh hosts.

## Rotation-ready file pair

Runtime code loads:

1. `/etc/shizuha/credential.key` as the primary active key (all new writes use this key), and
2. `/etc/shizuha/credential.key.next` when present as an additional decrypt-only rotation-window key.

Both files must be regular non-symlink files with no group/other permissions (`0600`). The key material is independent of Django `SECRET_KEY`; rotating one does not rotate the other.

Suggested rotation sequence:

1. Generate the candidate key into `/etc/shizuha/credential.key.next` with mode `0600`, daemon-owned. Do not log or paste the key.
2. Deploy/restart code that can read both files and verify existing payload decrypts still work.
3. Promote the candidate by replacing `/etc/shizuha/credential.key` with the new key during a maintenance window, keeping the previous active key available as `.next` only for the rollback/decrypt grace period.
4. Re-encrypt stored credential payloads after promotion, so new writes use the promoted primary key.
5. After all payloads are verified under the promoted primary and rollback is no longer needed, remove `.next`.

Never derive this key from `SECRET_KEY`, JWT secrets, or any checked-in config.
