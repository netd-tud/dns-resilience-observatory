"""Celery entry point for RIPEstat RPKI refreshes."""

from __future__ import annotations

from data_gathering.celery_app import app
from data_gathering.task_lock import advisory_task_lock
from data_gathering.tasks.rpki.script_config import script_logger
from data_gathering.tasks.rpki.update_rpki_table import update_rpki_table


logger = script_logger(__file__)

TASK_NAME = "data_gathering.tasks.rpki.refresh"
TASK_NAMES = [TASK_NAME]


@app.task(name=TASK_NAME)
def refresh() -> dict[str, int | str | bool]:
    with advisory_task_lock(TASK_NAME) as acquired:
        if not acquired:
            logger.info("RIPEstat RPKI: refresh already running; skipping overlapping task")
            return {"skipped": True, "reason": "already_running"}
        logger.info("RIPEstat RPKI: refreshing resolver prefix/origin-ASN states")
        result = update_rpki_table()
        logger.info("RIPEstat RPKI: refresh complete: {}", result)
        return result
