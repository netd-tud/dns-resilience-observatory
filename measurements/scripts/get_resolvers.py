"""Export resolver IPs from the database with common filters."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Iterable

from loguru import logger


def _parse_bool(value: str | bool | None) -> bool | None:
    if value is None or isinstance(value, bool):
        return value
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y"}:
        return True
    if normalized in {"0", "false", "no", "n"}:
        return False
    raise argparse.ArgumentTypeError(f"Invalid boolean value: {value}")


def query_resolvers(
    *,
    verified: bool | None = None,
    is_public: bool | None = None,
    source: str | None = None,
    country: str | None = None,
    asn: int | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    where = []
    params: list[Any] = []

    if verified is not None:
        where.append("ri.verified = %s")
        params.append(verified)
    if is_public is not None:
        where.append("r.is_public = %s")
        params.append(is_public)
    if source:
        where.append("r.source = %s")
        params.append(source)
    if country:
        where.append("rl.country = %s")
        params.append(country.strip().upper())
    if asn is not None:
        where.append("ra.asn = %s")
        params.append(asn)

    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    limit_sql = "LIMIT %s" if limit is not None else ""
    if limit is not None:
        params.append(limit)

    sql = f"""
        SELECT
            r.ip::TEXT AS resolver_ip,
            r.resolver_id,
            ri.verified,
            r.is_public,
            r.source,
            ra.asn,
            rl.country
        FROM resolver r
        JOIN resolver_id ri ON ri.id = r.resolver_id
        LEFT JOIN resolver_asn ra ON ra.resolver_id = r.resolver_id
        LEFT JOIN resolver_location rl ON rl.resolver_id = r.resolver_id
        {where_sql}
        ORDER BY r.ip
        {limit_sql}
    """

    from measurements.db import connect

    logger.info(
        "Loading resolvers from database with filters verified={verified}, is_public={is_public}, source={source}, country={country}, asn={asn}, limit={limit}",
        verified=verified,
        is_public=is_public,
        source=source or "*",
        country=country or "*",
        asn=asn if asn is not None else "*",
        limit=limit if limit is not None else "*",
    )
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql, params)
            columns = [column[0] for column in cursor.description]
            rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
    logger.info("Loaded {count} resolver rows from database", count=len(rows))
    return rows


def resolver_ips(**filters: Any) -> list[str]:
    return [row["resolver_ip"] for row in query_resolvers(**filters)]


def write_rows(rows: Iterable[dict[str, Any]], output: Path | None, fmt: str) -> None:
    handle = output.open("w", newline="") if output else sys.stdout
    try:
        if fmt == "txt":
            for row in rows:
                handle.write(f"{row['resolver_ip']}\n")
        elif fmt == "jsonl":
            for row in rows:
                handle.write(json.dumps(row, default=str) + "\n")
        else:
            rows = list(rows)
            writer = csv.DictWriter(
                handle,
                fieldnames=["resolver_ip", "resolver_id", "verified", "is_public", "source", "asn", "country"],
            )
            writer.writeheader()
            writer.writerows(rows)
    finally:
        if output:
            handle.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export resolvers from the database.")
    parser.add_argument("--verified", type=_parse_bool, default=None, help="Filter resolver_id.verified")
    parser.add_argument("--is-public", type=_parse_bool, default=None, help="Filter resolver.is_public")
    parser.add_argument("--source", help="Filter resolver.source")
    parser.add_argument("--country", help="Filter resolver_location.country")
    parser.add_argument("--asn", type=int, help="Filter resolver_asn.asn")
    parser.add_argument("--limit", type=int, help="Maximum number of rows")
    parser.add_argument("--format", choices=("txt", "csv", "jsonl"), default="txt")
    parser.add_argument("--output", type=Path, help="Output path. Defaults to stdout.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rows = query_resolvers(
        verified=args.verified,
        is_public=args.is_public,
        source=args.source,
        country=args.country,
        asn=args.asn,
        limit=args.limit,
    )
    write_rows(rows, args.output, args.format)


if __name__ == "__main__":
    main()
