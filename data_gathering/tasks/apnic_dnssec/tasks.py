"""APNIC DNSSEC data-gathering task implementation."""

from __future__ import annotations

from data_gathering.celery_app import app
from data_gathering.tasks.apnic_dnssec.script_config import script_logger
from data_gathering.tasks.apnic_dnssec.update_dnssec_table import update_dnssec_table


logger = script_logger(__file__)

TASK_NAMES = ["data_gathering.tasks.apnic_dnssec.refresh"]


@app.task(name="data_gathering.tasks.apnic_dnssec.refresh")
def refresh() -> dict[str, int | str]:
    logger.info("APNIC DNSSEC: refreshing country table")
    result = update_dnssec_table()
    logger.info("APNIC DNSSEC: refresh complete with {} country rows", result["country_rows"])
    return result
