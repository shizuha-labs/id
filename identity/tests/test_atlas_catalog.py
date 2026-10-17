"""The migrated Atlas catalog entry supports explicit, authorized grants."""
import importlib

from django.apps import apps
from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from rest_framework.test import APIClient

from identity.models import Tool, UserProfile


class AtlasCatalogTests(TestCase):
    def test_fresh_migrations_register_optional_atlas(self):
        atlas = Tool.objects.get(slug='atlas')
        self.assertTrue(atlas.is_active)
        self.assertFalse(atlas.is_default_enabled)
        self.assertFalse(atlas.requires_superuser)
        user = get_user_model().objects.create_user('atlas-default-test', email='atlas-default-test@example.com', password=None)
        self.assertFalse(UserProfile.objects.get(user=user).enabled_tools.filter(slug='atlas').exists())

    def test_seed_preserves_existing_configuration_and_grants(self):
        atlas = Tool.objects.get(slug='atlas')
        atlas.display_name = 'Configured architecture catalog'
        atlas.is_active = False
        atlas.requires_approval = True
        atlas.save()
        user = get_user_model().objects.create_user('atlas-existing-test', email='atlas-existing-test@example.com', password=None)
        profile = UserProfile.objects.get(user=user)
        profile.enabled_tools.add(atlas)
        before = set(profile.enabled_tools.values_list('pk', flat=True))
        migration = importlib.import_module('identity.migrations.0046_seed_atlas_tool')
        with connection.schema_editor(atomic=False) as editor:
            migration.seed_atlas_tool(apps, editor)
        atlas.refresh_from_db()
        self.assertEqual(atlas.display_name, 'Configured architecture catalog')
        self.assertFalse(atlas.is_active)
        self.assertTrue(atlas.requires_approval)
        self.assertEqual(set(profile.enabled_tools.values_list('pk', flat=True)), before)

    def test_real_staff_grant_endpoint_can_grant_atlas(self):
        User = get_user_model()
        target = User.objects.create_user('atlas-grant-target', email='atlas-grant-target@example.com', password=None)
        staff = User.objects.create_user('atlas-grant-staff', email='atlas-grant-staff@example.com', password=None, is_staff=True)
        profile = UserProfile.objects.get(user=target)
        before = set(profile.enabled_tools.values_list('slug', flat=True))
        client = APIClient()
        path = f'/api/auth/admin/users/{target.pk}/services/'
        payload = {'service_slugs': ['atlas'], 'action': 'grant'}
        client.force_authenticate(target)
        self.assertEqual(client.post(path, payload, format='json').status_code, 403)
        self.assertFalse(profile.enabled_tools.filter(slug='atlas').exists())
        client.force_authenticate(staff)
        self.assertEqual(client.post(path, payload, format='json').status_code, 200)
        self.assertEqual(set(profile.enabled_tools.values_list('slug', flat=True)), before | {'atlas'})
