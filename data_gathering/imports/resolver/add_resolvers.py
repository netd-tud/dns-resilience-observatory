"""Import new resolver IPs into the resolver schema."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

try:
    from loguru import logger
except ModuleNotFoundError:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    logger = logging.getLogger(__name__)


OBSERVATORY_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(OBSERVATORY_ROOT))


DEFAULT_MAPPING = {"ip": "ip"}
SUPPORTED_RESOLVER_COLUMNS = {"ip", "is_public", "last_update_ts", "source"}


def parse_column_mapping(mapping_values: Iterable[str] | None) -> dict[str, str]:
    if not mapping_values:
        return DEFAULT_MAPPING.copy()

    mapping: dict[str, str] = {}
    for value in mapping_values:
        for item in value.split(","):
            item = item.strip()
            if not item:
                continue
            if ":" not in item:
                raise ValueError(f"Invalid mapping {item!r}; expected db_column:file_column")
            db_column, file_column = [part.strip() for part in item.split(":", 1)]
            if db_column not in SUPPORTED_RESOLVER_COLUMNS:
                supported = ", ".join(sorted(SUPPORTED_RESOLVER_COLUMNS))
                raise ValueError(f"Unsupported resolver column {db_column!r}; supported columns: {supported}")
            if not file_column:
                raise ValueError(f"Missing file column in mapping {item!r}")
            mapping[db_column] = file_column

    if "ip" not in mapping:
        raise ValueError("Column mapping must include ip:<file_column>")
    return mapping


def read_input_file(path: Path):
    import polars as pl

    suffix = path.suffix.lower()
    if suffix in {".parquet", ".pq"}:
        return pl.read_parquet(path)
    if suffix == ".csv":
        return pl.read_csv(path)
    if suffix in {".json", ".ndjson"}:
        return pl.read_ndjson(path) if suffix == ".ndjson" else pl.read_json(path)
    raise ValueError(f"Unsupported input file type {suffix!r}; use CSV, Parquet, JSON, or NDJSON")


def normalize_ip(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def normalize_bool(value: object, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "t", "yes", "y"}:
        return True
    if text in {"0", "false", "f", "no", "n"}:
        return False
    return default


def normalize_timestamp(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def load_resolver_rows(path: Path, mapping: dict[str, str]) -> tuple[int, list[dict[str, object]], int]:
    frame = read_input_file(path)
    total_rows = frame.height

    missing_columns = sorted({column for column in mapping.values() if column not in frame.columns})
    if missing_columns:
        raise ValueError(f"Input file is missing mapped columns: {', '.join(missing_columns)}")

    rows: list[dict[str, object]] = []
    invalid_ip_count = 0
    for record in frame.select(list(mapping.values())).to_dicts():
        ip = normalize_ip(record.get(mapping["ip"]))
        if ip is None:
            invalid_ip_count += 1
            continue

        is_public = normalize_bool(record.get(mapping["is_public"]), default=False) if "is_public" in mapping else False
        source = str(record.get(mapping["source"])).strip() if "source" in mapping else path.name
        timestamp = normalize_timestamp(record.get(mapping["last_update_ts"])) if "last_update_ts" in mapping else None
        rows.append(
            {
                "ip": ip,
                "is_public": is_public,
                "source": source or path.name,
                "last_update_ts": timestamp,
            }
        )

    return total_rows, rows, invalid_ip_count


def percent(part: int, whole: int) -> float:
    return round((part / whole) * 100, 2) if whole else 0.0


def add_resolvers(path: Path, mapping: dict[str, str], dry_run: bool = False, verified: bool = False) -> None:
    from data_gathering.config.db_connection import close_db_connection, connect_to_db

    total_rows, rows, invalid_ip_count = load_resolver_rows(path, mapping)
    total_candidate_rows = len(rows)

    logger.info("Read {count} rows from {path}", count=total_rows, path=path)
    if invalid_ip_count:
        logger.warning(
            "Skipped {count} rows with missing or invalid IP addresses ({percent}%)",
            count=invalid_ip_count,
            percent=percent(invalid_ip_count, total_rows),
        )

    if dry_run:
        logger.info("Running resolver import in dry-run mode; database contents will not be changed")

    cursor = connect_to_db()
    connection = cursor.connection
    try:
        cursor.execute("SELECT COUNT(*) FROM resolver")
        before_count = cursor.fetchone()[0]

        added_count = 0
        skipped_count = invalid_ip_count
        timestamp_update_count = 0
        verified_update_count = 0
        verification_insert_count = 0
        seen_in_file: set[str] = set()

        for row in rows:
            ip = str(row["ip"])
            if ip in seen_in_file:
                skipped_count += 1
                continue
            seen_in_file.add(ip)

            cursor.execute(
                """
                SELECT r.resolver_id, r.last_update_ts, ri.verified
                FROM resolver r
                JOIN resolver_id ri ON ri.id = r.resolver_id
                WHERE r.ip = %s::inet
                """,
                (ip,),
            )
            existing_resolver = cursor.fetchone()
            if existing_resolver is not None:
                resolver_id, current_last_update_ts, is_verified = existing_resolver
                if row["last_update_ts"] is not None and row["last_update_ts"] > current_last_update_ts:
                    timestamp_update_count += 1
                    if not dry_run:
                        cursor.execute(
                            """
                            UPDATE resolver
                            SET last_update_ts = %s
                            WHERE ip = %s::inet
                            """,
                            (row["last_update_ts"], ip),
                        )
                if verified and not is_verified:
                    verified_update_count += 1
                    if not dry_run:
                        cursor.execute(
                            """
                            UPDATE resolver_id
                            SET
                                verified = TRUE,
                                total_measurements = CASE
                                    WHEN total_measurements = 0 THEN 1
                                    ELSE total_measurements
                                END,
                                seen_measurements = CASE
                                    WHEN seen_measurements = 0 THEN 1
                                    ELSE seen_measurements
                                END
                            WHERE id = %s
                            """,
                            (resolver_id,),
                        )
                if verified and not dry_run and row["source"]:
                    cursor.execute(
                        """
                        INSERT INTO resolver_verification (resolver_id, verifying_source)
                        VALUES (%s, %s)
                        ON CONFLICT DO NOTHING
                        """,
                        (resolver_id, row["source"]),
                    )
                    verification_insert_count += cursor.rowcount
                skipped_count += 1
                continue

            if dry_run:
                added_count += 1
                continue

            cursor.execute(
                """
                INSERT INTO resolver_id (
                    last_update_ts, total_measurements, seen_measurements, verified
                )
                VALUES (
                    COALESCE(%s, NOW()),
                    CASE WHEN %s THEN 1 ELSE 0 END,
                    CASE WHEN %s THEN 1 ELSE 0 END,
                    %s
                )
                RETURNING id
                """,
                (row["last_update_ts"], verified, verified, verified),
            )
            resolver_id = cursor.fetchone()[0]

            cursor.execute(
                """
                INSERT INTO resolver (
                    ip, resolver_id, is_public, last_update_ts, source
                )
                VALUES (%s::inet, %s, %s, COALESCE(%s, NOW()), %s)
                """,
                (ip, resolver_id, row["is_public"], row["last_update_ts"], row["source"]),
            )
            added_count += 1
            if verified and row["source"]:
                cursor.execute(
                    """
                    INSERT INTO resolver_verification (resolver_id, verifying_source)
                    VALUES (%s, %s)
                    ON CONFLICT DO NOTHING
                    """,
                    (resolver_id, row["source"]),
                )
                verification_insert_count += cursor.rowcount

        if dry_run:
            after_count = before_count
            connection.rollback()
        else:
            cursor.execute("SELECT COUNT(*) FROM resolver")
            after_count = cursor.fetchone()[0]
            connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        close_db_connection(cursor)

    growth = added_count if dry_run else after_count - before_count
    summary_label = "Resolver import dry-run summary" if dry_run else "Resolver import summary"
    logger.info(
        "{summary_label} for {path}: file rows={total}, candidates={candidates}, "
        "added={added} ({added_percent}%), skipped={skipped} ({skipped_percent}%)",
        summary_label=summary_label,
        path=path,
        total=total_rows,
        candidates=total_candidate_rows,
        added=added_count,
        added_percent=percent(added_count, total_rows),
        skipped=skipped_count,
        skipped_percent=percent(skipped_count, total_rows),
    )
    if verified:
        logger.info(
            "Resolver identities marked verified: {count}",
            count=verified_update_count,
        )
        logger.info(
            "Resolver verification entries inserted: {count}",
            count=verification_insert_count,
        )
    logger.info(
        "Resolver table size: before={before}, after={after}, growth={growth} ({growth_percent}%)",
        before=before_count,
        after=after_count,
        growth=growth,
        growth_percent=percent(growth, before_count),
    )
    logger.info(
        "Resolver timestamp updates: {count}",
        count=timestamp_update_count,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Add new resolver IPs from a data file.")
    parser.add_argument("file", type=Path, help="Input file path: CSV, Parquet, JSON, or NDJSON")
    parser.add_argument(
        "--mapping",
        "-m",
        action="append",
        help="Column mapping as db_column:file_column. Can be repeated or comma-separated. Example: ip:resolver_ip",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report how many resolvers would be inserted without changing the database",
    )
    parser.add_argument(
        "--verified",
        action="store_true",
        help="Set verified=true for newly created and existing resolver_id rows",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    mapping = parse_column_mapping(args.mapping)
    add_resolvers(args.file, mapping, dry_run=args.dry_run, verified=args.verified)


if __name__ == "__main__":
    main()
