"""
ID-42: the service enable/request endpoints must accept the product-facing
`service` / `service_slug` body key that the `id_toggle_service` /
`id_request_service` MCP tools (and the Services UI) send — not only the legacy
`tool` / `tool_slug`. Previously both 400'd with "Tool slug is required" because
the toggle view read `request.data.get('tool')` and the request serializer
required `tool_slug`, while the MCP tools POST `{"service": <slug>}`.
"""
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from identity.models import ServiceAccessRequest, Tool, UserProfile

User = get_user_model()


def _make_tool(slug, *, requires_approval=False, requires_superuser=False):
    return Tool.objects.get_or_create(
        slug=slug,
        defaults={
            'display_name': slug.title(),
            'description': '',
            'minimum_tier': 'free',
            'is_active': True,
            'is_default_enabled': False,
            'requires_approval': requires_approval,
            'requires_superuser': requires_superuser,
        },
    )[0]


class Id42ToggleServiceSlugTests(TestCase):
    """POST services/toggle/ — accept service / service_slug / legacy tool."""

    def setUp(self):
        self.user = User.objects.create_user(username='id42a', email='id42a@x.com', password='pw')
        UserProfile.objects.get_or_create(user=self.user)
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        _make_tool('id42togglesvc')  # unique free-tier, no-approval tool (avoid seeded 'drive')
        self.url = reverse('service-toggle')

    def _enabled(self):
        return UserProfile.objects.get(user=self.user).enabled_tools.filter(slug='id42togglesvc').exists()

    def test_accepts_service_key(self):
        resp = self.client.post(self.url, {'service': 'id42togglesvc', 'enable': True}, format='json')
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertTrue(self._enabled())

    def test_accepts_service_slug_key(self):
        resp = self.client.post(self.url, {'service_slug': 'id42togglesvc', 'enable': True}, format='json')
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertTrue(self._enabled())

    def test_still_accepts_legacy_tool_key(self):
        resp = self.client.post(self.url, {'tool': 'id42togglesvc', 'enable': True}, format='json')
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertTrue(self._enabled())

    def test_missing_slug_returns_400_mentioning_service(self):
        resp = self.client.post(self.url, {'enable': True}, format='json')
        self.assertEqual(resp.status_code, 400)
        self.assertIn('service', resp.content.decode().lower())


class Id42RequestServiceSlugTests(TestCase):
    """POST services/request/ — accept service / service_slug / legacy tool_slug."""

    def setUp(self):
        self.user = User.objects.create_user(username='id42b', email='id42b@x.com', password='pw')
        UserProfile.objects.get_or_create(user=self.user)
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.tool = _make_tool('id42reqsvc', requires_approval=True)  # approval-gated → request path
        self.url = reverse('service-request')

    def test_accepts_service_key(self):
        resp = self.client.post(self.url, {'service': 'id42reqsvc', 'reason': 'need it'}, format='json')
        self.assertIn(resp.status_code, (200, 201), resp.content)
        self.assertTrue(ServiceAccessRequest.objects.filter(user=self.user, tool=self.tool).exists())

    def test_still_accepts_legacy_tool_slug(self):
        resp = self.client.post(self.url, {'tool_slug': 'id42reqsvc', 'reason': 'x'}, format='json')
        self.assertIn(resp.status_code, (200, 201), resp.content)
        self.assertTrue(ServiceAccessRequest.objects.filter(user=self.user, tool=self.tool).exists())

    def test_missing_slug_returns_400(self):
        resp = self.client.post(self.url, {'reason': 'x'}, format='json')
        self.assertEqual(resp.status_code, 400)
        self.assertIn('service', resp.content.decode().lower())
