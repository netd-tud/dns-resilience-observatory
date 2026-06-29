"""Webpage resolver data-gathering task implementation."""

from __future__ import annotations

from data_gathering.celery_app import app
from data_gathering.tasks.webpage_resolver.script_config import script_logger
from data_gathering.tasks.webpage_resolver.update_webpage_resolvers import update_webpage_resolvers


logger = script_logger(__file__)

TASK_NAMES = ["data_gathering.tasks.webpage_resolver.refresh"]


@app.task(name="data_gathering.tasks.webpage_resolver.refresh")
def refresh() -> dict[str, object]:
    logger.info("Webpage resolver: downloading and importing configured resolver lists")
    report = update_webpage_resolvers()
    logger.info("Webpage resolver: import complete: {}", report)
    return report
