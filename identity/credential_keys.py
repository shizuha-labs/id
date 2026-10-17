"""Credential payload key provisioning and MultiFernet loading.

ADR-PLAT-001 S2b keeps credential-payload encryption keys independent from
Django's SECRET_KEY. This module owns only key-file provisioning/loading; callers
handle model storage and grant/derivation policy.
"""
from __future__ import annotations

from dataclasses import dataclass
import errno
import os
from pathlib import Path
import stat
from cryptography.fernet import Fernet, MultiFernet


DEFAULT_CREDENTIAL_KEY_PATH = Path("/etc/shizuha/credential.key")
DEFAULT_CREDENTIAL_KEY_NEXT_PATH = Path("/etc/shizuha/credential.key.next")
SECURE_KEY_FILE_MODE = 0o600
SECURE_KEY_DIR_MODE = 0o700


class CredentialKeyError(RuntimeError):
    """Raised when credential key material cannot be provisioned or loaded."""


@dataclass(frozen=True)
class CredentialKeyProvisionResult:
    """Metadata-only provisioning result.

    Deliberately excludes the generated key material so callers cannot
    accidentally log or return the credential-encryption master key.
    """

    path: Path
    created: bool
    mode: int
    uid: int
    gid: int


@dataclass(frozen=True)
class CredentialMultiFernet:
    """Loaded MultiFernet plus metadata safe to log."""

    fernet: MultiFernet
    primary_path: Path
    loaded_paths: tuple[Path, ...]


def provision_credential_key(
    path: str | os.PathLike[str] = DEFAULT_CREDENTIAL_KEY_PATH,
    *,
    owner_uid: int | None = None,
    owner_gid: int | None = None,
) -> CredentialKeyProvisionResult:
    """Ensure the active credential key exists with 0600 permissions.

    The function is idempotent: an existing regular key file is never overwritten
    or printed; its mode is tightened back to 0600. New keys are created with
    Fernet.generate_key() using an exclusive create and are written only to disk.
    If owner_uid/owner_gid are supplied (for root/systemd provisioning), both the
    key file and its containing directory are chowned after creation/tightening;
    otherwise the current owner is kept. The containing directory is always
    tightened to 0700 so a daemon-owned key is reachable on fresh hosts where
    /etc/shizuha did not previously exist.

    Ownership/mode changes for the key file are fd-based (fchown/fchmod) after
    opening with O_NOFOLLOW. This avoids following a symlink if a daemon-writable
    parent is raced during root-run provisioning.
    """

    key_path = Path(path)
    parent = key_path.parent
    parent.mkdir(mode=SECURE_KEY_DIR_MODE, parents=True, exist_ok=True)

    parent_fd = _open_directory_no_follow(parent)
    try:
        fd, created = _open_or_create_key_file(parent_fd, key_path.name)
        try:
            stat_result = os.fstat(fd)
            if not stat.S_ISREG(stat_result.st_mode):
                raise CredentialKeyError(f"credential key file {key_path} must be a regular file")
            if created:
                os.write(fd, Fernet.generate_key() + b"\n")
                os.fsync(fd)
            _validate_key_fd(fd, key_path)

            if owner_uid is not None or owner_gid is not None:
                stat_result = os.fstat(fd)
                os.fchown(
                    fd,
                    stat_result.st_uid if owner_uid is None else owner_uid,
                    stat_result.st_gid if owner_gid is None else owner_gid,
                )
            os.fchmod(fd, SECURE_KEY_FILE_MODE)

            if owner_uid is not None or owner_gid is not None:
                parent_stat = os.fstat(parent_fd)
                os.fchown(
                    parent_fd,
                    parent_stat.st_uid if owner_uid is None else owner_uid,
                    parent_stat.st_gid if owner_gid is None else owner_gid,
                )
            os.fchmod(parent_fd, SECURE_KEY_DIR_MODE)

            stat_result = os.fstat(fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)

    return CredentialKeyProvisionResult(
        path=key_path,
        created=created,
        mode=stat_result.st_mode & 0o777,
        uid=stat_result.st_uid,
        gid=stat_result.st_gid,
    )


def load_credential_multifernet(
    primary_path: str | os.PathLike[str] = DEFAULT_CREDENTIAL_KEY_PATH,
    *,
    next_path: str | os.PathLike[str] | None = DEFAULT_CREDENTIAL_KEY_NEXT_PATH,
    require_secure_permissions: bool = True,
) -> CredentialMultiFernet:
    """Load active + optional next key files as a rotation-ready MultiFernet.

    The active key is always first, so encryption writes with the active primary.
    The optional ``credential.key.next`` is accepted for decryption during a
    rotation window. Both files must be Fernet keys; when permission checks are
    enabled, group/other permissions are rejected instead of silently accepting a
    leaked master key file.
    """

    paths = [Path(primary_path)]
    if next_path is not None and Path(next_path).exists():
        paths.append(Path(next_path))

    fernets = [Fernet(_read_key_file(path, require_secure_permissions=require_secure_permissions)) for path in paths]
    if not fernets:
        raise CredentialKeyError("no credential keys loaded")
    return CredentialMultiFernet(fernet=MultiFernet(fernets), primary_path=paths[0], loaded_paths=tuple(paths))


def encrypt_credential_payload(payload: bytes, keyring: CredentialMultiFernet) -> bytes:
    """Encrypt a credential payload with the primary active key."""

    return keyring.fernet.encrypt(payload)


def decrypt_credential_payload(token: bytes, keyring: CredentialMultiFernet) -> bytes:
    """Decrypt a credential payload with any active rotation-window key."""

    return keyring.fernet.decrypt(token)


def _open_directory_no_follow(parent: Path) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(parent, flags)
    except OSError as exc:
        raise CredentialKeyError(f"credential key directory {parent} must be a real directory") from exc
    stat_result = os.fstat(fd)
    if not stat.S_ISDIR(stat_result.st_mode):
        os.close(fd)
        raise CredentialKeyError(f"credential key directory {parent} must be a directory")
    return fd


def _open_or_create_key_file(parent_fd: int, filename: str) -> tuple[int, bool]:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(filename, flags, SECURE_KEY_FILE_MODE, dir_fd=parent_fd), True
    except FileExistsError:
        existing_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            existing_flags |= os.O_NOFOLLOW
        try:
            return os.open(filename, existing_flags, dir_fd=parent_fd), False
        except OSError as exc:
            raise CredentialKeyError(f"credential key file {filename} must be a regular non-symlink file") from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise CredentialKeyError(f"credential key file {filename} must not be a symlink") from exc
        raise


def _validate_key_fd(fd: int, path: Path) -> None:
    current_offset = os.lseek(fd, 0, os.SEEK_CUR)
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        data = os.read(fd, 4096).strip()
        if not data:
            raise CredentialKeyError(f"credential key file {path} is empty")
        try:
            Fernet(data)
        except (ValueError, TypeError) as exc:
            raise CredentialKeyError(f"credential key file {path} does not contain a valid Fernet key") from exc
    finally:
        os.lseek(fd, current_offset, os.SEEK_SET)


def _read_key_file(path: Path, *, require_secure_permissions: bool) -> bytes:
    _ensure_regular_non_symlink(path)
    stat_result = path.stat()
    if require_secure_permissions and stat_result.st_mode & 0o077:
        raise CredentialKeyError(f"credential key file {path} must be mode 0600")
    data = path.read_bytes().strip()
    if not data:
        raise CredentialKeyError(f"credential key file {path} is empty")
    return data


def _ensure_regular_non_symlink(path: Path) -> None:
    try:
        stat_result = path.lstat()
    except FileNotFoundError as exc:
        raise CredentialKeyError(f"credential key file {path} does not exist") from exc
    if path.is_symlink():
        raise CredentialKeyError(f"credential key file {path} must not be a symlink")
    if not stat.S_ISREG(stat_result.st_mode):
        raise CredentialKeyError(f"credential key file {path} must be a regular file")
