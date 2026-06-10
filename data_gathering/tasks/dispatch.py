"""Dispatcher task for running all registered data-gathering tasks."""

from __future__ import annotations

import os

from loguru import logger
from dotenv import dotenv_values, load_dotenv

from data_gathering.celery_app import app
from data_gathering.tasks import collect_task_names, filter_tasks


@app.task
def run_all() -> dict[str, int]:
    load_dotenv()
    env = {**dotenv_values(), **os.environ}
    allow_list = env.get("DATA_GATHERING_TASKS", "").strip() or None
    task_names = filter_tasks(collect_task_names(), allow_list)

    if not task_names:
        logger.info("No data-gathering tasks registered")
        return {"tasks": 0}

    for task_name in task_names:
        logger.info("Dispatching task: {task}", task=task_name)
        app.send_task(task_name)

    return {"tasks": len(task_names)}
