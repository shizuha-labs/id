"""Settings imports require explicit effective signing and database credentials."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import unittest

SETTINGS_FILE = 'shizuha_id/settings.py'


class ExplicitRuntimeCredentialsTests(unittest.TestCase):
    def settings_import(self, change=None):
        root = Path(__file__).resolve().parents[1]
        values = {name: '  ' + secrets.token_urlsafe(32) + '  '
                  for name in ('SECRET_KEY', 'JWT_SECRET_KEY', 'POSTGRES_PASSWORD')}
        env = {key: os.environ[key] for key in ('PATH', 'HOME', 'LANG') if key in os.environ}
        env.update(values, DEBUG='False')
        if change:
            change(env)
        script = ("import json,runpy; "
                  f"s=runpy.run_path({str(root / SETTINGS_FILE)!r}); "
                  "print(json.dumps({'secret':s['SECRET_KEY'], "
                  "'password':s['DATABASES']['default']['PASSWORD'], "
                  "'signing_key':s['SIMPLE_JWT']['SIGNING_KEY']}))")
        result = subprocess.run([sys.executable, '-c', script], cwd=root, env=env,
                                capture_output=True, text=True, timeout=30)
        return result, values

    def test_missing_effective_credentials_refuse_with_debug_false(self):
        def missing_signing(env):
            env.pop('JWT_SECRET_KEY')
            env.pop('SECRET_KEY')
        for name, change in (('SECRET_KEY', missing_signing),
                             ('POSTGRES_PASSWORD', lambda env: env.pop('POSTGRES_PASSWORD'))):
            with self.subTest(setting=name):
                result, _ = self.settings_import(change)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(name + ' must be configured', result.stderr)

    def test_blank_selected_credentials_refuse(self):
        for name in ('JWT_SECRET_KEY', 'SECRET_KEY', 'POSTGRES_PASSWORD'):
            for value in ('', ' \t\n '):
                def blank(env):
                    if name == 'SECRET_KEY':
                        env.pop('JWT_SECRET_KEY')
                    env[name] = value
                with self.subTest(setting=name, empty=value == ''):
                    result, _ = self.settings_import(blank)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(name + ' must be configured', result.stderr)

    def assert_configured(self, change=None, selected='JWT_SECRET_KEY'):
        result, values = self.settings_import(change)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data['secret'], values[selected])
        self.assertEqual(data['signing_key'], values[selected])
        self.assertEqual(data['password'], values['POSTGRES_PASSWORD'])

    def test_jwt_key_only_preserves_existing_configuration(self):
        self.assert_configured(lambda env: env.pop('SECRET_KEY'))

    def test_secret_key_only_preserves_existing_configuration(self):
        self.assert_configured(lambda env: env.pop('JWT_SECRET_KEY'), selected='SECRET_KEY')

    def test_jwt_key_keeps_precedence_and_exact_configured_bytes(self):
        self.assert_configured()
