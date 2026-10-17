import os
from pathlib import Path
from unittest import mock
from tempfile import TemporaryDirectory
from io import StringIO

from cryptography.fernet import Fernet
from django.core.management import call_command
from django.test import SimpleTestCase

from identity.credential_keys import (
    CredentialKeyError,
    decrypt_credential_payload,
    encrypt_credential_payload,
    load_credential_multifernet,
    provision_credential_key,
)


class CredentialKeyProvisioningTests(SimpleTestCase):
    def test_provision_creates_fernet_key_with_0600_without_returning_material(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credential.key"
            result = provision_credential_key(path)

            self.assertTrue(result.created)
            self.assertEqual(result.mode, 0o600)
            self.assertNotIn("key", result.__dict__)
            data = path.read_bytes().strip()
            Fernet(data)  # validates format

    def test_provision_existing_key_is_idempotent_and_tightens_mode(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credential.key"
            original = Fernet.generate_key() + b"\n"
            path.write_bytes(original)
            os.chmod(path, 0o644)

            result = provision_credential_key(path)

            self.assertFalse(result.created)
            self.assertEqual(result.mode, 0o600)
            self.assertEqual(path.read_bytes(), original)

    def test_provision_existing_readonly_valid_key_is_tightened_without_rewrite(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credential.key"
            original = Fernet.generate_key() + b"\n"
            path.write_bytes(original)
            os.chmod(path, 0o400)

            result = provision_credential_key(path)

            self.assertFalse(result.created)
            self.assertEqual(result.mode, 0o600)
            self.assertEqual(path.read_bytes(), original)

    def test_provision_existing_empty_key_fails_without_false_success(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credential.key"
            path.write_bytes(b"")
            os.chmod(path, 0o600)

            with self.assertRaises(CredentialKeyError) as ctx:
                provision_credential_key(path)

            self.assertIn("is empty", str(ctx.exception))

    def test_provision_existing_invalid_key_fails_without_false_success(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credential.key"
            path.write_bytes(b"not-a-fernet-key\n")
            os.chmod(path, 0o600)

            with self.assertRaises(CredentialKeyError) as ctx:
                provision_credential_key(path)

            self.assertIn("valid Fernet key", str(ctx.exception))
            self.assertNotIn("not-a-fernet-key", str(ctx.exception))

    def test_root_style_owner_provisioning_chowns_parent_and_key_file(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "shizuha" / "credential.key"
            owner_uid = 1234
            owner_gid = 5678

            with mock.patch("identity.credential_keys.os.fchown") as fchown_mock:
                result = provision_credential_key(path, owner_uid=owner_uid, owner_gid=owner_gid)

            self.assertTrue(result.created)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(fchown_mock.call_count, 2)
            self.assertEqual(fchown_mock.call_args_list[0].args[1:], (owner_uid, owner_gid))
            self.assertEqual(fchown_mock.call_args_list[1].args[1:], (owner_uid, owner_gid))

    def test_owner_provisioning_rejects_existing_symlink_key(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "shizuha" / "credential.key"
            path.parent.mkdir()
            target = Path(tmp) / "target"
            target.write_bytes(b"target")
            os.symlink(target, path)

            with self.assertRaises(CredentialKeyError):
                provision_credential_key(path, owner_uid=1234, owner_gid=5678)

            self.assertEqual(target.read_bytes(), b"target")

    def test_load_multifernet_reads_active_and_next_but_writes_with_active(self):
        with TemporaryDirectory() as tmp:
            active_key = Fernet.generate_key()
            next_key = Fernet.generate_key()
            active_path = Path(tmp) / "credential.key"
            next_path = Path(tmp) / "credential.key.next"
            active_path.write_bytes(active_key + b"\n")
            next_path.write_bytes(next_key + b"\n")
            os.chmod(active_path, 0o600)
            os.chmod(next_path, 0o600)

            keyring = load_credential_multifernet(active_path, next_path=next_path)
            old_token = Fernet(next_key).encrypt(b"old-payload")
            new_token = encrypt_credential_payload(b"new-payload", keyring)

            self.assertEqual(decrypt_credential_payload(old_token, keyring), b"old-payload")
            self.assertEqual(Fernet(active_key).decrypt(new_token), b"new-payload")
            with self.assertRaises(Exception):
                Fernet(next_key).decrypt(new_token)

    def test_load_rejects_group_or_other_readable_key_file(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credential.key"
            path.write_bytes(Fernet.generate_key() + b"\n")
            os.chmod(path, 0o640)

            with self.assertRaises(CredentialKeyError):
                load_credential_multifernet(path)

    def test_management_command_does_not_print_key_material(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credential.key"
            out = StringIO()

            call_command("provision_credential_key", "--path", str(path), stdout=out)

            output = out.getvalue()
            key_material = path.read_text().strip()
            self.assertIn("credential key created", output)
            self.assertIn(str(path), output)
            self.assertNotIn(key_material, output)
