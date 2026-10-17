"""
Celery configuration for Shizuha ID.
"""
import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'shizuha_id.settings')

app = Celery('shizuha_id')
app.config_from_object('django.conf:settings', namespace='CELERY')

app.conf.update(
    task_default_queue='shizuha_id',
    task_default_exchange='shizuha_id',
    task_default_routing_key='shizuha_id',
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)

app.autodiscover_tasks()


@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
