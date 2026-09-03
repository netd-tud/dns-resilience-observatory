"""PostgreSQL-backed locks for preventing overlapping Celery task runs."""

from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator

import psycopg

from db.apply_schema import build_dsn


@contextmanager
def advisory_task_lock(task_name: str) -> Iterator[bool]:
    """Hold a session advisory lock for ``task_name`` while the context is active."""

    with psycopg.connect(build_dsn(), autocommit=True) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_try_advisory_lock(hashtextextended(%s, 0))",
                (task_name,),
            )
            acquired = bool(cursor.fetchone()[0])
        try:
            yield acquired
        finally:
            if acquired:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT pg_advisory_unlock(hashtextextended(%s, 0))",
                        (task_name,),
                    )
