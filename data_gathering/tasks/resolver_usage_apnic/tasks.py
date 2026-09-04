"""Celery entry point for APNIC resolver usage refreshes."""

from __future__ import annotations

from data_gathering.celery_app import app
from data_gathering.task_lock import advisory_task_lock
from data_gathering.tasks.resolver_usage_apnic.script_config import script_logger
from data_gathering.tasks.resolver_usage_apnic.update_resolver_usage import update_resolver_usage


logger = script_logger(__file__)
TASK_NAME = "data_gathering.tasks.resolver_usage_apnic.refresh"
TASK_NAMES = [TASK_NAME]


@app.task(name=TASK_NAME)
def refresh() -> dict[str, object]:
    with advisory_task_lock(TASK_NAME) as acquired:
        if not acquired:
            logger.info("APNIC resolver usage: refresh already running; skipping")
            return {"skipped": True, "reason": "already_running"}
        logger.info("APNIC resolver usage: refreshing world and country observations")
        result = update_resolver_usage()
        logger.info("APNIC resolver usage: refresh complete: {}", result)
        return result
