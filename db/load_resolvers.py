"""Load resolver records from data/public_resolver.pq into PostgreSQL."""

from __future__ import annotations

import ipaddress
from pathlib import Path
import sys

import psycopg
from dotenv import load_dotenv
from loguru import logger
from pyarrow import parquet as pq

from apply_schema import build_dsn


DATA_DIR = Path(__file__).resolve().parents[1] / "data"
OBSERVATORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(OBSERVATORY_ROOT))

from data_gathering.imports.country.country_locations import ensure_country_locations, normalize_country
from resolver_identity import attach_resolver_identities

DATA_FILES = ["public_resolver.pq", "closed_resolver.pq"]

RESOLVER_COLUMNS = [
    "resolver_identity_id",
    "ip",
    "asn",
    "bgp_prefix",
    "org",
    "org_short",
    "country",
    "is_public",
    "last_observation_ts",
    "source",
]


def _normalize_ip(value: object) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def load_rows(data_file: Path) -> list[dict[str, object]]:
    table = pq.read_table(data_file)
    rows = table.to_pylist()

    normalized: list[dict[str, object]] = []
    skipped = 0
    for row in rows:
        row_data = {column: row.get(column) for column in RESOLVER_COLUMNS}
        row_data["resolver_name"] = row.get("resolver_name") or row.get("identity_name") or row.get("name")
        row_data["resolver_operator"] = row.get("resolver_operator") or row.get("operator")
        row_data["resolver_domain"] = row.get("resolver_domain") or row.get("domain")
        row_data["ip"] = _normalize_ip(row.get("ip") or row.get("ipv4") or row.get("ipv6"))
        row_data["country"] = normalize_country(row_data.get("country"))
        if row_data["ip"] is None:
            skipped += 1
            continue
        normalized.append(row_data)

    if skipped:
        logger.warning("Skipped {count} rows without ip", count=skipped)

    return normalized


def _fetch_existing_ids(
    connection: psycopg.Connection,
    ips: list[str],
) -> dict[str, int]:
    if not ips:
        return {}

    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT id, ip::text FROM resolver WHERE ip = ANY(%s::inet[])",
            (ips,),
        )
        rows = cursor.fetchall()

    lookup: dict[str, int] = {}
    for resolver_id, ip in rows:
        if ip:
            lookup[ip] = resolver_id
    return lookup


def insert_rows(rows: list[dict[str, object]], source_file: Path) -> None:
    if not rows:
        logger.info("No rows to insert for {path}", path=source_file)
        return

    dsn = build_dsn()
    logger.info("Inserting resolver rows from {path}", path=source_file)
    with psycopg.connect(dsn) as connection:
        ensure_country_locations(
            connection,
            {str(row["country"]) for row in rows if row.get("country")},
            logger,
        )
        ips = sorted({str(row["ip"]) for row in rows if row.get("ip")})
        existing = _fetch_existing_ids(connection, ips)
        attach_resolver_identities(connection, rows)

        update_rows: list[dict[str, object]] = []
        insert_rows_list: list[dict[str, object]] = []
        for row in rows:
            resolver_id = existing.get(str(row["ip"]))

            if resolver_id is None:
                insert_rows_list.append(row)
            else:
                row["id"] = resolver_id
                update_rows.append(row)

        update_query = (
            "UPDATE resolver SET "
            "resolver_identity_id = COALESCE(%(resolver_identity_id)s, resolver_identity_id), "
            "ip = COALESCE(%(ip)s::inet, ip), "
            "asn = COALESCE(%(asn)s, asn), "
            "bgp_prefix = COALESCE(%(bgp_prefix)s, bgp_prefix), "
            "org = COALESCE(%(org)s, org), "
            "org_short = COALESCE(%(org_short)s, org_short), "
            "country = COALESCE(%(country)s, country), "
            "is_public = COALESCE(%(is_public)s, is_public), "
            "last_observation_ts = GREATEST(last_observation_ts, COALESCE(%(last_observation_ts)s, last_observation_ts)), "
            "source = COALESCE(%(source)s, source) "
            "WHERE id = %(id)s"
        )

        insert_placeholders = ", ".join([f"%({col})s" for col in RESOLVER_COLUMNS])
        insert_columns = ", ".join(RESOLVER_COLUMNS)
        insert_query = f"INSERT INTO resolver ({insert_columns}) VALUES ({insert_placeholders})"

        with connection.cursor() as cursor:
            if update_rows:
                cursor.executemany(update_query, update_rows)
            if insert_rows_list:
                cursor.executemany(insert_query, insert_rows_list)
        connection.commit()

    logger.info(
        "Applied resolver updates: {updated} updated, {inserted} inserted",
        updated=len(update_rows),
        inserted=len(insert_rows_list),
    )


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
