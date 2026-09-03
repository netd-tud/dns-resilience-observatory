"""Celery entry point for MANRS readiness refreshes."""

from __future__ import annotations

from data_gathering.celery_app import app
from data_gathering.task_lock import advisory_task_lock
from data_gathering.tasks.manrs.script_config import script_logger
from data_gathering.tasks.manrs.update_manrs_tables import normalize_scope, update_manrs_tables


logger = script_logger(__file__)

TASK_NAME = "data_gathering.tasks.manrs.refresh"
TASK_NAMES = [TASK_NAME]


@app.task(name=TASK_NAME)
def refresh(scope: str = "both") -> dict[str, int | str | bool]:
    selected_scope = normalize_scope(scope)
    with advisory_task_lock(TASK_NAME) as acquired:
        if not acquired:
            logger.info("MANRS: refresh already running; skipping overlapping task")
            return {"scope": selected_scope, "skipped": True, "reason": "already_running"}
        logger.info("MANRS: refreshing resolver-linked {} readiness", selected_scope)
        result = update_manrs_tables(selected_scope)
        logger.info("MANRS: refresh complete: {}", result)
        return result
