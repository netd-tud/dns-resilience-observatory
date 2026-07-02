"""Celery app for active measurement tasks."""

from __future__ import annotations

import os
from importlib import import_module

from celery import Celery
from dotenv import dotenv_values, load_dotenv


load_dotenv()
env = {**dotenv_values(), **os.environ}

BROKER_URL = env.get("CELERY_BROKER_URL", "amqp://guest:guest@rabbitmq:5672//")
TIMEZONE = env.get("CELERY_TIMEZONE", "UTC")

app = Celery("measurements", broker=BROKER_URL)
app.conf.update(
    timezone=TIMEZONE,
    task_track_started=True,
    task_default_queue="measurements",
    task_routes={
        "measurements.tasks.*": {"queue": "measurements"},
    },
)

for module_path in [
    "measurements.tasks.verify_resolvers.verify_resolvers",
    "measurements.tasks.metainformation_resolvers.metainformation_resolvers",
]:
    import_module(module_path)
