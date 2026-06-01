"""Load forwarder records from data/all_forwarder.pq into PostgreSQL."""

from __future__ import annotations

from pathlib import Path

import psycopg
from dotenv import load_dotenv
from loguru import logger
from pyarrow import parquet as pq

from apply_schema import build_dsn


DATA_FILE = Path(__file__).resolve().parents[1] / "data" / "all_forwarder.pq"

FORWARDER_COLUMNS = [
    "ipv4",
    "ipv6",
    "resolver_id",
    "asn",
    "bgp_prefix",
    "org",
    "org_short",
    "country",
    "city",
    "latitude",
    "longitude",
    "last_observation_ts",
    "source",
]


def load_rows() -> list[dict[str, object]]:
    table = pq.read_table(DATA_FILE)
    rows = table.to_pylist()

    normalized: list[dict[str, object]] = []
    skipped = 0
    for row in rows:
        row_data = {column: row.get(column) for column in FORWARDER_COLUMNS}
        row_data["resolver_ip"] = row.get("resolver_ip")

        if row_data.get("ipv4") is None and row_data.get("ipv6") is None:
            skipped += 1
            continue

        normalized.append(row_data)

    if skipped:
        logger.warning("Skipped {count} rows without ipv4/ipv6", count=skipped)

    return normalized


def fetch_resolver_id_map(connection: psycopg.Connection, ips: list[str]) -> dict[str, int]:
    if not ips:
        return {}

    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT id, ipv4 FROM resolver WHERE ipv4 = ANY(%s)",
            (ips,),
        )
        return {row[1]: row[0] for row in cursor.fetchall() if row[1] is not None}


def insert_rows(rows: list[dict[str, object]]) -> None:
    if not rows:
        logger.info("No rows to insert")
        return

    dsn = build_dsn()
    with psycopg.connect(dsn) as connection:
        resolver_ips = sorted({row["resolver_ip"] for row in rows if row.get("resolver_ip")})
        resolver_map = fetch_resolver_id_map(connection, resolver_ips)

        missing = 0
        ready_rows: list[dict[str, object]] = []
        for row in rows:
            resolver_ip = row.get("resolver_ip")
            resolver_id = resolver_map.get(resolver_ip) if resolver_ip else None
            if resolver_id is None:
                missing += 1
                continue
            row["resolver_id"] = resolver_id
            row.pop("resolver_ip", None)
            ready_rows.append(row)

        if missing:
            logger.warning("Skipped {count} rows without resolver_id", count=missing)

        if not ready_rows:
            logger.info("No rows to insert after resolver_id mapping")
            return

        logger.info("Sample rows: {rows}", rows=ready_rows[:5])

        placeholders = ", ".join([f"%({col})s" for col in FORWARDER_COLUMNS])
        columns = ", ".join(FORWARDER_COLUMNS)
        query = f"INSERT INTO forwarder ({columns}) VALUES ({placeholders})"

        with connection.cursor() as cursor:
            cursor.executemany(query, ready_rows)
        connection.commit()

    logger.info("Inserted {count} forwarder rows", count=len(ready_rows))


def main() -> None:
    load_dotenv()
    logger.info("Loading forwarders from {path}", path=DATA_FILE)
    rows = load_rows()
    insert_rows(rows)


if __name__ == "__main__":
    main()
