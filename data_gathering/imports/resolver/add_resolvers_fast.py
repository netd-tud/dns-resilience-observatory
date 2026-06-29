"""Bulk import new resolver IPs into the resolver schema using a temp table."""

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
STAGE_COLUMNS = ["ip", "is_public", "source", "last_update_ts"]


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


def load_stage_rows(path: Path, mapping: dict[str, str]) -> tuple[int, list[dict[str, object]], int]:
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


def add_resolvers_fast(path: Path, mapping: dict[str, str], dry_run: bool = False, verified: bool = False) -> None:
    from data_gathering.config.db_connection import close_db_connection, connect_to_db

    total_rows, rows, invalid_ip_count = load_stage_rows(path, mapping)
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

        cursor.execute(
            """
            CREATE TEMP TABLE resolver_import_stage (
                ip INET NOT NULL,
                is_public BOOLEAN NOT NULL,
                source TEXT NOT NULL,
                last_update_ts TIMESTAMPTZ
            ) ON COMMIT DROP
            """
        )
        with cursor.copy(
            "COPY resolver_import_stage (ip, is_public, source, last_update_ts) FROM STDIN"
        ) as copy:
            for row in rows:
                copy.write_row([row[column] for column in STAGE_COLUMNS])

        cursor.execute("SELECT COUNT(*) FROM resolver_import_stage")
        valid_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(DISTINCT ip) FROM resolver_import_stage")
        unique_count = cursor.fetchone()[0]
        duplicate_count = valid_count - unique_count

        cursor.execute(
            """
            CREATE TEMP TABLE resolver_import_unique AS
            SELECT DISTINCT ON (ip)
                ip,
                is_public,
                source,
                last_update_ts
            FROM resolver_import_stage
            ORDER BY ip, last_update_ts DESC NULLS LAST, source
            """
        )
        cursor.execute("CREATE INDEX resolver_import_unique_ip_idx ON resolver_import_unique (ip)")

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM resolver_import_unique u
            JOIN resolver r ON r.ip = u.ip
            """
        )
        existing_count = cursor.fetchone()[0]
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM resolver_import_unique u
            JOIN resolver r ON r.ip = u.ip
            WHERE u.last_update_ts IS NOT NULL
              AND u.last_update_ts > r.last_update_ts
            """
        )
        timestamp_update_count = cursor.fetchone()[0]
        if not dry_run:
            cursor.execute(
                """
                UPDATE resolver r
                SET last_update_ts = u.last_update_ts
                FROM resolver_import_unique u
                WHERE r.ip = u.ip
                  AND u.last_update_ts IS NOT NULL
                  AND u.last_update_ts > r.last_update_ts
                """
            )

        verified_update_count = 0
        verification_insert_count = 0
        if verified:
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM resolver_import_unique u
                JOIN resolver r ON r.ip = u.ip
                JOIN resolver_id ri ON ri.id = r.resolver_id
                WHERE ri.verified = FALSE
                """
            )
            verified_update_count = cursor.fetchone()[0]
            if not dry_run:
                cursor.execute(
                    """
                    UPDATE resolver_id ri
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
                    FROM resolver r
                    JOIN resolver_import_unique u ON u.ip = r.ip
                    WHERE ri.id = r.resolver_id
                      AND ri.verified = FALSE
                    """
                )
                cursor.execute(
                    """
                    INSERT INTO resolver_verification (resolver_id, verifying_source)
                    SELECT
                        r.resolver_id,
                        u.source
                    FROM resolver_import_unique u
                    JOIN resolver r ON r.ip = u.ip
                    WHERE TRIM(u.source) <> ''
                    ON CONFLICT DO NOTHING
                    """
                )
                verification_insert_count += cursor.rowcount

        if dry_run:
            cursor.execute(
                """
                CREATE TEMP TABLE resolver_import_pending AS
                SELECT
                    NULL::BIGINT AS resolver_id,
                    u.ip,
                    u.is_public,
                    u.source,
                    u.last_update_ts
                FROM resolver_import_unique u
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM resolver r
                    WHERE r.ip = u.ip
                )
                """
            )
        else:
            cursor.execute(
                """
                CREATE TEMP TABLE resolver_import_pending AS
                SELECT
                    nextval(pg_get_serial_sequence('resolver_id', 'id')) AS resolver_id,
                    u.ip,
                    u.is_public,
                    u.source,
                    u.last_update_ts
                FROM resolver_import_unique u
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM resolver r
                    WHERE r.ip = u.ip
                )
                """
            )
        cursor.execute("SELECT COUNT(*) FROM resolver_import_pending")
        added_count = cursor.fetchone()[0]

        if dry_run:
            after_count = before_count
            connection.rollback()
        else:
            cursor.execute(
                """
                INSERT INTO resolver_id (
                    id, last_update_ts, total_measurements, seen_measurements, verified
                )
                SELECT
                    resolver_id,
                    COALESCE(last_update_ts, NOW()),
                    CASE WHEN %s THEN 1 ELSE 0 END,
                    CASE WHEN %s THEN 1 ELSE 0 END,
                    %s
                FROM resolver_import_pending
                """,
                (verified, verified, verified),
            )
            cursor.execute(
                """
                INSERT INTO resolver (
                    ip, resolver_id, is_public, last_update_ts, source
                )
                SELECT
                    ip,
                    resolver_id,
                    is_public,
                    COALESCE(last_update_ts, NOW()),
                    source
                FROM resolver_import_pending
                """
            )
            if verified:
                cursor.execute(
                    """
                    INSERT INTO resolver_verification (resolver_id, verifying_source)
                    SELECT
                        resolver_id,
                        source
                    FROM resolver_import_pending
                    WHERE TRIM(source) <> ''
                    ON CONFLICT DO NOTHING
                    """
                )
                verification_insert_count += cursor.rowcount
            cursor.execute("SELECT COUNT(*) FROM resolver")
            after_count = cursor.fetchone()[0]
            connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        close_db_connection(cursor)

    skipped_count = invalid_ip_count + duplicate_count + existing_count
    growth = added_count if dry_run else after_count - before_count
    summary_label = "Resolver fast import dry-run summary" if dry_run else "Resolver fast import summary"
    logger.info(
        "{summary_label} for {path}: file rows={total}, candidates={candidates}, "
        "added={added} ({added_percent}%), skipped={skipped} ({skipped_percent}%)",
        summary_label=summary_label,
        path=path,
        total=total_rows,
        candidates=valid_count,
        added=added_count,
        added_percent=percent(added_count, total_rows),
        skipped=skipped_count,
        skipped_percent=percent(skipped_count, total_rows),
    )
    logger.info(
        "Skipped detail: invalid_ip={invalid}, duplicate_in_file={duplicates}, already_existing={existing}",
        invalid=invalid_ip_count,
        duplicates=duplicate_count,
        existing=existing_count,
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
    parser = argparse.ArgumentParser(description="Bulk add new resolver IPs from a data file.")
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
    add_resolvers_fast(args.file, mapping, dry_run=args.dry_run, verified=args.verified)


if __name__ == "__main__":
    main()
