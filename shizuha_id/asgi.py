"""
ASGI config for Shizuha ID project.
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'shizuha_id.settings')

application = get_asgi_application()
