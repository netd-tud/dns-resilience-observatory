"""Upsert current MANRS ASN and country readiness rows."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

import psycopg

from db.apply_schema import build_dsn


METRICS = (
    "anti_spoofing",
    "coordination",
    "filtering",
    "routing_information_irr",
    "routing_information_rpki",
)


def _source_exists(cursor: psycopg.Cursor, source: str) -> None:
    cursor.execute("SELECT 1 FROM data_source WHERE source = %s", (source,))
    if cursor.fetchone() is None:
        raise ValueError(f"Missing data_source row for {source!r}; run db/data_source.py first")


def _upsert_asns(cursor: psycopg.Cursor, rows: list[Mapping[str, Any]]) -> int:
    if not rows:
        return 0
    assignments = []
    columns = ["asn"]
    for metric in METRICS:
        columns.extend((f"{metric}_score", f"{metric}_trend", f"{metric}_readiness"))
        assignments.extend(
            (
                f"{metric}_score = EXCLUDED.{metric}_score",
                f"{metric}_trend = EXCLUDED.{metric}_trend",
                f"{metric}_readiness = EXCLUDED.{metric}_readiness",
            )
        )
    columns.extend(("last_update_ts", "source"))
    assignments.extend(
        (
            "last_update_ts = EXCLUDED.last_update_ts",
            "source = EXCLUDED.source",
        )
    )
    placeholders = ", ".join(f"%({column})s" for column in columns)
    cursor.executemany(
        f"""
        INSERT INTO manrs_asn ({', '.join(columns)})
        VALUES ({placeholders})
        ON CONFLICT (asn) DO UPDATE SET {', '.join(assignments)}
        WHERE EXCLUDED.last_update_ts >= manrs_asn.last_update_ts
        """,
        rows,
    )
    return cursor.rowcount


def _upsert_countries(cursor: psycopg.Cursor, rows: list[Mapping[str, Any]]) -> int:
    if not rows:
        return 0
    assignments = []
    columns = ["country"]
    for metric in METRICS:
        columns.extend((f"{metric}_score", f"{metric}_trend", f"{metric}_ready_share"))
        assignments.extend(
            (
                f"{metric}_score = EXCLUDED.{metric}_score",
                f"{metric}_trend = EXCLUDED.{metric}_trend",
                f"{metric}_ready_share = EXCLUDED.{metric}_ready_share",
            )
        )
    columns.extend(("last_update_ts", "source"))
    assignments.extend(
        (
            "last_update_ts = EXCLUDED.last_update_ts",
            "source = EXCLUDED.source",
        )
    )
    placeholders = ", ".join(f"%({column})s" for column in columns)
    cursor.executemany(
        f"""
        INSERT INTO manrs_country ({', '.join(columns)})
        VALUES ({placeholders})
        ON CONFLICT (country) DO UPDATE SET {', '.join(assignments)}
        WHERE EXCLUDED.last_update_ts >= manrs_country.last_update_ts
        """,
        rows,
    )
    return cursor.rowcount


def import_manrs(
    *,
    asn_rows: Iterable[Mapping[str, Any]] = (),
    country_rows: Iterable[Mapping[str, Any]] = (),
    source: str = "manrs-observatory",
) -> dict[str, int]:
    prepared_asns = [{**row, "source": source} for row in asn_rows]
    prepared_countries = [{**row, "source": source} for row in country_rows]
    with psycopg.connect(build_dsn()) as connection:
        with connection.cursor() as cursor:
            _source_exists(cursor, source)
            asn_count = _upsert_asns(cursor, prepared_asns)
            country_count = _upsert_countries(cursor, prepared_countries)
        connection.commit()
    return {"upserted_asns": asn_count, "upserted_countries": country_count}
