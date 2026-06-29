"""CAIDA Spoofer data-gathering task implementation."""

from __future__ import annotations

from data_gathering.celery_app import app
from data_gathering.tasks.caida_spoofer.script_config import script_logger
from data_gathering.tasks.caida_spoofer.update_spoofing_table import update_spoofing_table


logger = script_logger(__file__)

TASK_NAMES = ["data_gathering.tasks.caida_spoofer.refresh"]


@app.task(name="data_gathering.tasks.caida_spoofer.refresh")
def refresh() -> dict[str, int | str]:
    frame = update_spoofing_table()
    logger.info("CAIDA Spoofer: imported {} spoofing prefixes", frame.height)
    return {"rows": frame.height}
