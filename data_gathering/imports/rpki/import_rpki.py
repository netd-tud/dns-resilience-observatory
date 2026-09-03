"""Upsert current prefix/origin-ASN RPKI states."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

import psycopg

from db.apply_schema import build_dsn


def import_rpki(
    rows: Iterable[Mapping[str, Any]],
    *,
    source: str = "ripe-stat-rpki",
) -> int:
    prepared = [{**row, "source": source} for row in rows]
    if not prepared:
        return 0
    with psycopg.connect(build_dsn()) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM data_source WHERE source = %s", (source,))
            if cursor.fetchone() is None:
                raise ValueError(f"Missing data_source row for {source!r}; run db/data_source.py first")
            cursor.executemany(
                """
                INSERT INTO rpki_prefix (
                    prefix, asn, rpki_status, last_update_ts, source
                )
                VALUES (
                    %(prefix)s::CIDR, %(asn)s, %(rpki_status)s,
                    %(last_update_ts)s, %(source)s
                )
                ON CONFLICT (prefix, asn) DO UPDATE SET
                    rpki_status = EXCLUDED.rpki_status,
                    last_update_ts = EXCLUDED.last_update_ts,
                    source = EXCLUDED.source
                WHERE EXCLUDED.last_update_ts >= rpki_prefix.last_update_ts
                """,
                prepared,
            )
            affected = cursor.rowcount
        connection.commit()
    return affected
