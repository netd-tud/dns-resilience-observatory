"""Load resolver records from data/public_resolver.pq into PostgreSQL."""

from __future__ import annotations

from pathlib import Path

import psycopg
from dotenv import load_dotenv
from loguru import logger
from pyarrow import parquet as pq

from apply_schema import build_dsn


DATA_DIR = Path(__file__).resolve().parents[1] / "data"
DATA_FILES = ["public_resolver.pq", "closed_resolver.pq"]

RESOLVER_COLUMNS = [
    "ipv4",
    "ipv6",
    "asn",
    "bgp_prefix",
    "org",
    "org_short",
    "country",
    "city",
    "latitude",
    "longitude",
    "is_public",
    "last_observation_ts",
    "source",
]


def load_rows(data_file: Path) -> list[dict[str, object]]:
    table = pq.read_table(data_file)
    rows = table.to_pylist()

    normalized: list[dict[str, object]] = []
    skipped = 0
    for row in rows:
        row_data = {column: row.get(column) for column in RESOLVER_COLUMNS}
        if row_data.get("ipv4") is None and row_data.get("ipv6") is None:
            skipped += 1
            continue
        normalized.append(row_data)

    if skipped:
        logger.warning("Skipped {count} rows without ipv4/ipv6", count=skipped)

    return normalized


def insert_rows(rows: list[dict[str, object]], source_file: Path) -> None:
    if not rows:
        logger.info("No rows to insert for {path}", path=source_file)
        return

    placeholders = ", ".join([f"%({col})s" for col in RESOLVER_COLUMNS])
    columns = ", ".join(RESOLVER_COLUMNS)
    query = f"INSERT INTO resolver ({columns}) VALUES ({placeholders})"

    dsn = build_dsn()
    logger.info("Inserting resolver rows from {path}", path=source_file)
    with psycopg.connect(dsn) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(query, rows)
        connection.commit()

    logger.info("Inserted {count} resolver rows", count=len(rows))


def main() -> None:
    load_dotenv()
    data_files = [DATA_DIR / name for name in DATA_FILES]
    data_files = [path for path in data_files if path.exists()]
    if not data_files:
        logger.warning("No resolver files found in {path}", path=DATA_DIR)
        return

    for data_file in data_files:
        logger.info("Loading resolvers from {path}", path=data_file)
        rows = load_rows(data_file)
        insert_rows(rows, data_file)


if __name__ == "__main__":
    main()
