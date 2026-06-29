"""Load forwarder records from data/all_forwarder.pq into PostgreSQL."""

from __future__ import annotations

import ipaddress
from pathlib import Path
import sys

import psycopg
from dotenv import load_dotenv
from loguru import logger
from pyarrow import parquet as pq

from apply_schema import build_dsn


DATA_FILE = Path(__file__).resolve().parents[1] / "data" / "all_forwarder.pq"
OBSERVATORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(OBSERVATORY_ROOT))

from data_gathering.imports.country.country_locations import ensure_country_locations, normalize_country


FORWARDER_COLUMNS = [
    "ip",
    "resolver_id",
    "type",
    "is_public",
    "supported_protocols",
    "asn",
    "bgp_prefix",
    "org",
    "org_short",
    "country",
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


def load_rows() -> list[dict[str, object]]:
    table = pq.read_table(DATA_FILE)
    rows = table.to_pylist()

    normalized: list[dict[str, object]] = []
    skipped = 0
    for row in rows:
        row_data = {column: row.get(column) for column in FORWARDER_COLUMNS}
        row_data["ip"] = _normalize_ip(row.get("ip") or row.get("ipv4") or row.get("ipv6"))
        row_data["resolver_ip"] = _normalize_ip(row.get("resolver_ip"))
        row_data["country"] = normalize_country(row_data.get("country"))
        if isinstance(row_data.get("supported_protocols"), (list, tuple, set)):
            row_data["supported_protocols"] = ",".join(
                str(item) for item in row_data["supported_protocols"] if item is not None
            )

        if row_data["ip"] is None or row_data.get("type") is None:
            skipped += 1
            continue

        normalized.append(row_data)

    if skipped:
        logger.warning("Skipped {count} rows without ip or type", count=skipped)

    return normalized


def fetch_resolver_id_map(connection: psycopg.Connection, ips: list[str]) -> dict[str, int]:
    if not ips:
        return {}

    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT id, ip::text FROM resolver WHERE ip = ANY(%s::inet[])",
            (ips,),
        )
        return {row[1]: row[0] for row in cursor.fetchall() if row[1] is not None}


def _fetch_existing_forwarders(
    connection: psycopg.Connection,
    ips: list[str],
) -> dict[str, int]:
    if not ips:
        return {}

    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT id, ip::text FROM forwarder WHERE ip = ANY(%s::inet[])",
            (ips,),
        )
        rows = cursor.fetchall()

    lookup: dict[str, int] = {}
    for forwarder_id, ip in rows:
        if ip:
            lookup[ip] = forwarder_id
    return lookup


def insert_rows(rows: list[dict[str, object]]) -> None:
    if not rows:
        logger.info("No rows to insert")
        return

    dsn = build_dsn()
    with psycopg.connect(dsn) as connection:
        ensure_country_locations(
            connection,
            {str(row["country"]) for row in rows if row.get("country")},
            logger,
        )
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

        ips = sorted({str(row["ip"]) for row in ready_rows if row.get("ip")})
        existing = _fetch_existing_forwarders(connection, ips)

        update_rows: list[dict[str, object]] = []
        insert_rows_list: list[dict[str, object]] = []
        for row in ready_rows:
            forwarder_id = existing.get(str(row["ip"]))

            if forwarder_id is None:
                insert_rows_list.append(row)
            else:
                row["id"] = forwarder_id
                update_rows.append(row)

        update_query = (
            "UPDATE forwarder SET "
            "ip = COALESCE(%(ip)s::inet, ip), "
            "resolver_id = COALESCE(%(resolver_id)s, resolver_id), "
            "type = COALESCE(%(type)s, type), "
            "is_public = COALESCE(%(is_public)s, is_public), "
            "supported_protocols = COALESCE(%(supported_protocols)s, supported_protocols), "
            "asn = COALESCE(%(asn)s, asn), "
            "bgp_prefix = COALESCE(%(bgp_prefix)s, bgp_prefix), "
            "org = COALESCE(%(org)s, org), "
            "org_short = COALESCE(%(org_short)s, org_short), "
            "country = COALESCE(%(country)s, country), "
            "last_observation_ts = GREATEST(last_observation_ts, COALESCE(%(last_observation_ts)s, last_observation_ts)), "
            "source = COALESCE(%(source)s, source) "
            "WHERE id = %(id)s"
        )

        insert_placeholders = ", ".join([f"%({col})s" for col in FORWARDER_COLUMNS])
        insert_columns = ", ".join(FORWARDER_COLUMNS)
        insert_query = f"INSERT INTO forwarder ({insert_columns}) VALUES ({insert_placeholders})"

        with connection.cursor() as cursor:
            if update_rows:
                cursor.executemany(update_query, update_rows)
            if insert_rows_list:
                cursor.executemany(insert_query, insert_rows_list)
        connection.commit()

    logger.info(
        "Applied forwarder updates: {updated} updated, {inserted} inserted",
        updated=len(update_rows),
        inserted=len(insert_rows_list),
    )


def main() -> None:
    load_dotenv()
    logger.info("Loading forwarders from {path}", path=DATA_FILE)
    rows = load_rows()
    insert_rows(rows)


if __name__ == "__main__":
    main()
