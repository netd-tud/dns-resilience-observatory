"""Celery entry point for IPv6 Hitlist Service refreshes."""

from __future__ import annotations

from data_gathering.celery_app import app
from data_gathering.task_lock import advisory_task_lock
from data_gathering.tasks.ipv6_hitlist.script_config import script_logger
from data_gathering.tasks.ipv6_hitlist.update_ipv6_hitlist import update_ipv6_hitlist


logger = script_logger(__file__)

TASK_NAME = "data_gathering.tasks.ipv6_hitlist.refresh"
TASK_NAMES = [TASK_NAME]


@app.task(name=TASK_NAME)
def refresh() -> dict[str, object]:
    with advisory_task_lock(TASK_NAME) as acquired:
        if not acquired:
            logger.info("IPv6 Hitlist: refresh already running; skipping overlapping task")
            return {"skipped": True, "reason": "already_running"}
        logger.info("IPv6 Hitlist: refreshing UDP/53 resolver addresses")
        report = update_ipv6_hitlist()
        logger.info("IPv6 Hitlist: refresh complete: {}", report)
        return report
