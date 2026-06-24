"""Celery app configuration for data-gathering tasks."""

from __future__ import annotations

import os
from importlib import import_module

from celery import Celery
from celery.schedules import crontab
from dotenv import dotenv_values, load_dotenv

from data_gathering.tasks import task_modules


load_dotenv()
env = {**dotenv_values(), **os.environ}

BROKER_URL = env.get("CELERY_BROKER_URL", "amqp://guest:guest@rabbitmq:5672//")
TIMEZONE = env.get("CELERY_TIMEZONE", "UTC")

app = Celery("data_gathering", broker=BROKER_URL)
app.conf.update(
    timezone=TIMEZONE,
    task_track_started=True,
)

def _parse_cron(spec: str) -> crontab:
    parts = spec.split()
    if len(parts) != 5:
        raise ValueError("CELERY_SCHEDULE_CRON must have 5 fields")
    minute, hour, day_of_month, month, day_of_week = parts
    return crontab(
        minute=minute,
        hour=hour,
        day_of_month=day_of_month,
        month_of_year=month,
        day_of_week=day_of_week,
    )


scheduled_task = env.get("CELERY_SCHEDULED_TASK", "data_gathering.tasks.dispatch.run_all").strip()
cron_spec = env.get("CELERY_SCHEDULE_CRON", "0 0 * * *").strip()

if scheduled_task:
    app.conf.beat_schedule = {
        "data-gathering-schedule": {
            "task": scheduled_task,
            "schedule": _parse_cron(cron_spec),
        }
    }

for module_path in ["data_gathering.tasks.dispatch", *task_modules()]:
    import_module(module_path)
