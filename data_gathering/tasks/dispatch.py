"""Dispatcher task for running all registered data-gathering tasks."""

from __future__ import annotations

import os

from celery import chain
from loguru import logger
from dotenv import dotenv_values, load_dotenv

from data_gathering.celery_app import app
from data_gathering.config.db_connection import close_db_connection, connect_to_db
from data_gathering.tasks import collect_task_names, filter_tasks


FIRST_BOOTSTRAP_TASKS = [
    "data_gathering.tasks.manycast.refresh",
    "data_gathering.tasks.caida_spoofer.refresh",
    "data_gathering.tasks.odns.refresh",
    "data_gathering.tasks.apnic_dnssec.refresh",
    "data_gathering.tasks.webpage_resolver.refresh",
]

BOOTSTRAP_CONTENT_TABLES = [
    "anycast",
    "spoofing",
    "resolver",
    "forwarder",
    "dnssec_country",
    "dnssec_asn",
]


def _table_count(cursor, table_name: str) -> int:
    cursor.execute("SELECT to_regclass(%s)", (f"public.{table_name}",))
    if cursor.fetchone()[0] is None:
        return 0
    cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
    return int(cursor.fetchone()[0])


def database_has_imported_content() -> bool:
    cursor = connect_to_db()
    try:
        counts = {table: _table_count(cursor, table) for table in BOOTSTRAP_CONTENT_TABLES}
    finally:
        close_db_connection(cursor)

    logger.info("Bootstrap content table counts: {counts}", counts=counts)
    return any(count > 0 for count in counts.values())


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


@app.task(name="data_gathering.tasks.dispatch.bootstrap_if_empty")
def bootstrap_if_empty() -> dict[str, object]:
    if database_has_imported_content():
        logger.info("Database already contains imported content; skipping first-start bootstrap")
        return {"dispatched": 0, "skipped": True, "reason": "database_not_empty"}

    workflow = chain(*(app.signature(task_name, immutable=True) for task_name in FIRST_BOOTSTRAP_TASKS))
    async_result = workflow.apply_async()
    logger.info("Dispatched first-start bootstrap chain: {tasks}", tasks=FIRST_BOOTSTRAP_TASKS)
    return {"dispatched": len(FIRST_BOOTSTRAP_TASKS), "skipped": False, "root_task_id": async_result.id}
