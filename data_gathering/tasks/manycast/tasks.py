"""Manycast data-gathering task implementation."""

from __future__ import annotations

from pathlib import Path

from data_gathering.celery_app import app
from data_gathering.external_sources.config import external_data_dir
from data_gathering.tasks.manycast.script_config import required_config_value, script_logger


logger = script_logger(__file__)

TASK_NAMES = ["data_gathering.tasks.manycast.refresh"]


def _data_dir() -> Path:
    return Path(required_config_value(__file__, "data_dir"))


def _external_data_dir() -> Path:
    return external_data_dir()


@app.task(name="data_gathering.tasks.manycast.refresh")
def refresh() -> dict[str, int]:
    from data_gathering.tasks.manycast.load_anycast_table import load_anycast_table

    data_dir = _external_data_dir()
    logger.info("Manycast: loading prefix data from {}", data_dir)
    report = load_anycast_table(data_dir=data_dir)
    logger.info("Manycast: load complete: {}", report)
    return report
