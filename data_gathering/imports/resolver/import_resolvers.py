"""General fast resolver importer with optional resolver attribute modules."""

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

from data_gathering.imports.country.country_locations import ensure_country_locations, normalize_country


MODULES = {"resolver", "asn", "prefix", "location", "protocol", "endpoint", "org", "domain"}
MODULE_REQUIRED_COLUMNS = {
    "resolver": {"ip"},
    "asn": {"ip", "asn"},
    "prefix": {"ip", "prefix"},
    "location": {"ip", "country"},
    "protocol": {"ip", "protocol"},
    "endpoint": {"ip", "endpoint"},
    "org": {"ip", "org"},
    "domain": {"ip", "domain"},
}
SUPPORTED_COLUMNS = set().union(*MODULE_REQUIRED_COLUMNS.values()) | {
    "city",
    "is_public",
    "last_update_ts",
    "source",
    "verified",
}
ATTRIBUTE_MODULES = ("asn", "prefix", "location", "protocol", "endpoint", "org", "domain")


def parse_column_mapping(mapping_values: Iterable[str] | None) -> dict[str, str]:
    if not mapping_values:
        raise ValueError("Column mapping is required")
    if isinstance(mapping_values, str):
        mapping_values = [mapping_values]

    mapping: dict[str, str] = {}
    for value in mapping_values:
        for item in value.split(","):
            item = item.strip()
            if not item:
                continue
            if ":" not in item:
                raise ValueError(f"Invalid mapping {item!r}; expected db_column:file_column")
            db_column, file_column = [part.strip() for part in item.split(":", 1)]
            if db_column not in SUPPORTED_COLUMNS:
                supported = ", ".join(sorted(SUPPORTED_COLUMNS))
                raise ValueError(f"Unsupported mapped column {db_column!r}; supported columns: {supported}")
            if not file_column:
                raise ValueError(f"Missing file column in mapping {item!r}")
            mapping[db_column] = file_column
    return mapping


def parse_modules(value: str | Iterable[str]) -> list[str]:
    if isinstance(value, str):
        modules = [item.strip().lower() for item in value.split(",") if item.strip()]
    else:
        modules = [item.strip().lower() for item in value if item.strip()]
    unknown = sorted(set(modules) - MODULES)
    if unknown:
        raise ValueError(f"Unsupported modules: {', '.join(unknown)}")
    ordered = ["resolver"]
    ordered.extend(module for module in ATTRIBUTE_MODULES if module in modules)
    return ordered


def parse_headers(value: str | Iterable[str] | None) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        headers = [item.strip() for item in value.split(",")]
    else:
        headers = [str(item).strip() for item in value]
    headers = [header for header in headers if header]
    return headers or None


def parse_separator(value: str) -> str:
    if value == r"\t":
        return "\t"
    if len(value) != 1:
        raise ValueError("--separator must be a single character, or '\\t' for tab")
    return value


def read_input_file(
    path: Path,
    *,
    has_header: bool = True,
    headers: list[str] | None = None,
    separator: str = ",",
):
    import polars as pl

    suffix = path.suffix.lower()
    if suffix in {".parquet", ".pq"}:
        return pl.read_parquet(path)
    if suffix == ".csv":
        if not has_header and not headers:
            raise ValueError("--headers is required when --no-header is used for CSV input")
        return pl.read_csv(
            path,
            has_header=has_header,
            new_columns=headers,
            separator=separator,
        )
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


def default_import_ts() -> datetime:
    now = datetime.now(timezone.utc)
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


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


def normalize_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def normalize_asn(value: object) -> int | None:
    text = normalize_text(value)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def normalize_prefix(value: object) -> str | None:
    text = normalize_text(value)
    if text is None:
        return None
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return None


def validate_mapping(frame, mapping: dict[str, str], modules: list[str]) -> None:
    required_columns = set().union(*(MODULE_REQUIRED_COLUMNS[module] for module in modules))
    if "location" in modules:
        required_columns.add("country")

    missing_mapped_columns = sorted(required_columns - set(mapping))
    if missing_mapped_columns:
        raise ValueError(f"Mapping is missing required database columns: {', '.join(missing_mapped_columns)}")

    missing_file_columns = sorted({file_column for file_column in mapping.values() if file_column not in frame.columns})
    if missing_file_columns:
        raise ValueError(f"Input file is missing mapped columns: {', '.join(missing_file_columns)}")


def load_rows(
    path: Path,
    mapping: dict[str, str],
    modules: list[str],
    *,
    has_header: bool = True,
    headers: list[str] | None = None,
    separator: str = ",",
    source: str | None = None,
    verified: bool = False,
):
    frame = read_input_file(path, has_header=has_header, headers=headers, separator=separator)
    logger.info("Loaded resolver import dataframe head:\n{head}", head=frame.head())
    validate_mapping(frame, mapping, modules)

    selected_columns = list(dict.fromkeys(mapping.values()))
    rows = []
    invalid_ip_count = 0
    import_ts = default_import_ts()
    for record in frame.select(selected_columns).to_dicts():
        ip = normalize_ip(record.get(mapping["ip"]))
        if ip is None:
            invalid_ip_count += 1
            continue

        row = {
            "ip": ip,
            "is_public": normalize_bool(record.get(mapping["is_public"]), default=False)
            if "is_public" in mapping
            else False,
            "source": normalize_text(record.get(mapping["source"])) if "source" in mapping else source or path.name,
            "last_update_ts": normalize_timestamp(record.get(mapping["last_update_ts"]))
            if "last_update_ts" in mapping
            else import_ts,
            "verified": normalize_bool(record.get(mapping["verified"]), default=False)
            if "verified" in mapping
            else verified,
        }
        row["source"] = row["source"] or source or path.name

        row["asn"] = normalize_asn(record.get(mapping["asn"])) if "asn" in mapping else None
        row["prefix"] = normalize_prefix(record.get(mapping["prefix"])) if "prefix" in mapping else None
        row["country"] = normalize_country(record.get(mapping["country"])) if "country" in mapping else None
        for column in ("city", "protocol", "endpoint", "org", "domain"):
            row[column] = normalize_text(record.get(mapping[column])) if column in mapping else None
        rows.append(row)

    return frame.height, rows, invalid_ip_count


def percent(part: int, whole: int) -> float:
    return round((part / whole) * 100, 2) if whole else 0.0


def create_base_stage(cursor, rows: list[dict[str, object]]) -> None:
    cursor.execute(
        """
        CREATE TEMP TABLE resolver_import_stage (
            ip INET NOT NULL,
            is_public BOOLEAN NOT NULL,
            source TEXT NOT NULL,
            last_update_ts TIMESTAMPTZ,
            verified BOOLEAN NOT NULL,
            asn INTEGER,
            prefix CIDR,
            country TEXT,
            city TEXT,
            protocol TEXT,
            endpoint TEXT,
            org TEXT,
            domain TEXT
        ) ON COMMIT DROP
        """
    )
    with cursor.copy(
        """
        COPY resolver_import_stage (
            ip, is_public, source, last_update_ts, verified, asn, prefix, country,
            city, protocol, endpoint, org, domain
        ) FROM STDIN
        """
    ) as copy:
        for row in rows:
            copy.write_row(
                [
                    row["ip"],
                    row["is_public"],
                    row["source"],
                    row["last_update_ts"],
                    row["verified"],
                    row["asn"],
                    row["prefix"],
                    row["country"],
                    row["city"],
                    row["protocol"],
                    row["endpoint"],
                    row["org"],
                    row["domain"],
                ]
            )

    cursor.execute(
        """
        CREATE TEMP TABLE resolver_import_unique AS
        SELECT DISTINCT ON (ip)
            ip, is_public, source, last_update_ts, verified, asn, prefix, country,
            city, protocol, endpoint, org, domain
        FROM resolver_import_stage
        ORDER BY ip, last_update_ts DESC NULLS LAST, source
        """
    )
    cursor.execute("CREATE INDEX resolver_import_unique_ip_idx ON resolver_import_unique (ip)")


def import_resolver_module(cursor, dry_run: bool, verified: bool, force: bool) -> dict[str, int]:
    cursor.execute("SELECT COUNT(*) FROM resolver")
    before_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM resolver_import_stage")
    valid_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM resolver_import_unique")
    unique_count = cursor.fetchone()[0]
    duplicate_count = valid_count - unique_count
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
        WHERE %s
           OR (
               u.last_update_ts IS NOT NULL
               AND u.last_update_ts > r.last_update_ts
           )
        """,
        (force,),
    )
    timestamp_update_count = cursor.fetchone()[0]
    if not dry_run:
        cursor.execute(
            """
            UPDATE resolver r
            SET
                is_public = CASE
                    WHEN %s THEN u.is_public
                    ELSE r.is_public OR u.is_public
                END,
                last_update_ts = COALESCE(u.last_update_ts, NOW()),
                source = u.source
            FROM resolver_import_unique u
            WHERE r.ip = u.ip
              AND (
                  %s
                  OR (
                      u.last_update_ts IS NOT NULL
                      AND u.last_update_ts > r.last_update_ts
                  )
              )
            """,
            (force, force),
        )

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM resolver_import_unique u
        JOIN resolver r ON r.ip = u.ip
        JOIN resolver_id ri ON ri.id = r.resolver_id
        WHERE (%s AND ri.verified IS DISTINCT FROM u.verified)
           OR (u.verified = TRUE AND ri.verified = FALSE)
        """,
        (force,),
    )
    verified_update_count = cursor.fetchone()[0]
    verification_insert_count = 0
    if not dry_run:
        cursor.execute(
            """
            UPDATE resolver_id ri
            SET
                last_update_ts = CASE
                    WHEN %s THEN COALESCE(u.last_update_ts, ri.last_update_ts)
                    WHEN u.last_update_ts IS NOT NULL AND u.last_update_ts > ri.last_update_ts THEN u.last_update_ts
                    ELSE ri.last_update_ts
                END,
                verified = CASE
                    WHEN %s THEN u.verified
                    ELSE ri.verified OR u.verified
                END,
                total_measurements = CASE
                    WHEN u.verified AND total_measurements = 0 THEN 1
                    ELSE total_measurements
                END,
                seen_measurements = CASE
                    WHEN u.verified AND seen_measurements = 0 THEN 1
                    ELSE seen_measurements
                END
            FROM resolver r
            JOIN resolver_import_unique u ON u.ip = r.ip
            WHERE ri.id = r.resolver_id
              AND (
                  %s
                  OR (u.last_update_ts IS NOT NULL AND u.last_update_ts > ri.last_update_ts)
                  OR (u.verified = TRUE AND ri.verified = FALSE)
              )
            """,
            (force, force, force),
        )
        cursor.execute(
            """
            INSERT INTO resolver_verification (resolver_id, verifying_source)
            SELECT r.resolver_id, u.source
            FROM resolver_import_unique u
            JOIN resolver r ON r.ip = u.ip
            WHERE u.verified = TRUE
              AND TRIM(u.source) <> ''
            ON CONFLICT DO NOTHING
            """
        )
        verification_insert_count += cursor.rowcount

    if dry_run:
        cursor.execute(
            """
            CREATE TEMP TABLE resolver_import_pending AS
            SELECT
                (-(ROW_NUMBER() OVER (ORDER BY u.ip)))::BIGINT AS resolver_id,
                u.*
            FROM resolver_import_unique u
            WHERE NOT EXISTS (SELECT 1 FROM resolver r WHERE r.ip = u.ip)
            """
        )
    else:
        cursor.execute(
            """
            CREATE TEMP TABLE resolver_import_pending AS
            SELECT nextval(pg_get_serial_sequence('resolver_id', 'id')) AS resolver_id, u.*
            FROM resolver_import_unique u
            WHERE NOT EXISTS (SELECT 1 FROM resolver r WHERE r.ip = u.ip)
            """
        )
    cursor.execute("SELECT COUNT(*) FROM resolver_import_pending")
    insert_count = cursor.fetchone()[0]

    if dry_run:
        after_count = before_count
    else:
        cursor.execute(
            """
            INSERT INTO resolver_id (id, last_update_ts, total_measurements, seen_measurements, verified)
            SELECT
                resolver_id,
                COALESCE(last_update_ts, NOW()),
                CASE WHEN verified THEN 1 ELSE 0 END,
                CASE WHEN verified THEN 1 ELSE 0 END,
                verified
            FROM resolver_import_pending
            """,
        )
        cursor.execute(
            """
            INSERT INTO resolver (ip, resolver_id, is_public, last_update_ts, source)
            SELECT ip, resolver_id, is_public, COALESCE(last_update_ts, NOW()), source
            FROM resolver_import_pending
            """
        )
        cursor.execute(
            """
            INSERT INTO resolver_verification (resolver_id, verifying_source)
            SELECT resolver_id, source
            FROM resolver_import_pending
            WHERE verified = TRUE
              AND TRIM(source) <> ''
            ON CONFLICT DO NOTHING
            """
        )
        verification_insert_count += cursor.rowcount
        cursor.execute("SELECT COUNT(*) FROM resolver")
        after_count = cursor.fetchone()[0]

    cursor.execute(
        """
        CREATE TEMP TABLE resolver_import_all AS
        SELECT
            COALESCE(r.resolver_id, p.resolver_id) AS resolver_id,
            u.*
        FROM resolver_import_unique u
        LEFT JOIN resolver r ON r.ip = u.ip
        LEFT JOIN resolver_import_pending p ON p.ip = u.ip
        """
    )
    cursor.execute("CREATE INDEX resolver_import_all_resolver_id_idx ON resolver_import_all (resolver_id)")

    return {
        "candidates": valid_count,
        "inserted": insert_count,
        "updated": timestamp_update_count,
        "skipped": duplicate_count + existing_count - timestamp_update_count,
        "duplicate": duplicate_count,
        "existing": existing_count,
        "growth": insert_count if dry_run else after_count - before_count,
        "verified_updates": verified_update_count,
        "verification_inserts": verification_insert_count,
    }


MODULE_SQL = {
    "asn": {
        "table": "resolver_asn",
        "column": "asn",
        "condition": "asn IS NOT NULL",
        "value": "asn",
        "distinct": "resolver_id, asn",
        "create": "resolver_id, asn, last_update_ts",
    },
    "prefix": {
        "table": "resolver_prefix",
        "column": "prefix",
        "condition": "prefix IS NOT NULL",
        "value": "prefix",
        "distinct": "resolver_id, prefix",
        "create": "resolver_id, prefix, last_update_ts",
    },
    "endpoint": {
        "table": "resolver_endpoint",
        "column": "endpoint",
        "condition": "endpoint IS NOT NULL",
        "value": "endpoint",
        "distinct": "resolver_id, endpoint",
        "create": "resolver_id, endpoint, last_update_ts",
    },
    "org": {
        "table": "resolver_org",
        "column": "org",
        "condition": "org IS NOT NULL",
        "value": "org",
        "distinct": "resolver_id, org",
        "create": "resolver_id, org, last_update_ts",
    },
    "domain": {
        "table": "resolver_domain",
        "column": "domain",
        "condition": "domain IS NOT NULL",
        "value": "domain",
        "distinct": "resolver_id, domain",
        "create": "resolver_id, domain, last_update_ts",
    },
}


def import_simple_module(cursor, module: str, dry_run: bool, force: bool) -> dict[str, int]:
    config = MODULE_SQL[module]
    stage_table = f"resolver_{module}_stage"
    table = config["table"]
    column = config["column"]
    value = config["value"]
    condition = config["condition"]

    cursor.execute(
        f"""
        CREATE TEMP TABLE {stage_table} AS
        SELECT DISTINCT ON (resolver_id)
            resolver_id,
            {value} AS value,
            last_update_ts
        FROM resolver_import_all
        WHERE resolver_id IS NOT NULL
          AND {condition}
        ORDER BY resolver_id, last_update_ts DESC NULLS LAST
        """
    )
    cursor.execute(f"SELECT COUNT(*) FROM {stage_table}")
    candidates = cursor.fetchone()[0]
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM resolver_import_all
        WHERE resolver_id IS NOT NULL
        """
    )
    resolver_candidates = cursor.fetchone()[0]

    cursor.execute(
        f"""
        SELECT COUNT(*)
        FROM {stage_table} s
        LEFT JOIN {table} t ON t.resolver_id = s.resolver_id
        WHERE t.resolver_id IS NULL
        """
    )
    insert_count = cursor.fetchone()[0]
    cursor.execute(
        f"""
        SELECT COUNT(*)
        FROM {stage_table} s
        JOIN {table} t ON t.resolver_id = s.resolver_id
        WHERE %s
           OR t.{column} IS DISTINCT FROM s.value
           OR (
               s.last_update_ts IS NOT NULL
               AND s.last_update_ts > t.last_update_ts
           )
        """,
        (force,),
    )
    update_count = cursor.fetchone()[0]

    if not dry_run:
        cursor.execute(
            f"""
            INSERT INTO {table} (resolver_id, {column}, last_update_ts)
            SELECT s.resolver_id, s.value, COALESCE(s.last_update_ts, NOW())
            FROM {stage_table} s
            LEFT JOIN {table} t ON t.resolver_id = s.resolver_id
            WHERE t.resolver_id IS NULL
            """
        )
        cursor.execute(
            f"""
            UPDATE {table} t
            SET {column} = s.value,
                last_update_ts = CASE
                    WHEN %s THEN COALESCE(s.last_update_ts, NOW())
                    WHEN s.last_update_ts IS NOT NULL AND s.last_update_ts > t.last_update_ts THEN s.last_update_ts
                    WHEN t.{column} IS DISTINCT FROM s.value THEN COALESCE(s.last_update_ts, NOW())
                    ELSE t.last_update_ts
                END
            FROM {stage_table} s
            WHERE t.resolver_id = s.resolver_id
              AND (
                  %s
                  OR t.{column} IS DISTINCT FROM s.value
                  OR (
                      s.last_update_ts IS NOT NULL
                      AND s.last_update_ts > t.last_update_ts
                  )
              )
            """,
            (force, force),
        )

    return {
        "candidates": candidates,
        "inserted": insert_count,
        "updated": update_count,
        "skipped": max(resolver_candidates - insert_count - update_count, 0),
    }


def import_protocol_module(cursor, dry_run: bool, force: bool) -> dict[str, int]:
    cursor.execute(
        """
        CREATE TEMP TABLE resolver_protocol_stage AS
        SELECT DISTINCT ON (resolver_id, protocol)
            resolver_id,
            protocol,
            last_update_ts
        FROM (
            SELECT
                resolver_id,
                LOWER(TRIM(protocol_part)) AS protocol,
                last_update_ts
            FROM resolver_import_all
            CROSS JOIN LATERAL regexp_split_to_table(protocol, ',') AS protocol_part
            WHERE resolver_id IS NOT NULL
              AND protocol IS NOT NULL
        ) split_protocols
        WHERE protocol <> ''
        ORDER BY resolver_id, protocol, last_update_ts DESC NULLS LAST
        """
    )
    cursor.execute("SELECT COUNT(*) FROM resolver_protocol_stage")
    candidates = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM resolver_protocol_stage s
        LEFT JOIN resolver_protocol t
          ON t.resolver_id = s.resolver_id
         AND t.protocol = s.protocol
        WHERE t.resolver_id IS NULL
        """
    )
    insert_count = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM resolver_protocol_stage s
        JOIN resolver_protocol t
          ON t.resolver_id = s.resolver_id
         AND t.protocol = s.protocol
        WHERE %s
           OR (
               s.last_update_ts IS NOT NULL
               AND s.last_update_ts > t.last_update_ts
           )
        """,
        (force,),
    )
    update_count = cursor.fetchone()[0]

    if not dry_run:
        cursor.execute(
            """
            INSERT INTO resolver_protocol (resolver_id, protocol, last_update_ts)
            SELECT
                s.resolver_id,
                s.protocol,
                COALESCE(s.last_update_ts, NOW())
            FROM resolver_protocol_stage s
            LEFT JOIN resolver_protocol t
              ON t.resolver_id = s.resolver_id
             AND t.protocol = s.protocol
            WHERE t.resolver_id IS NULL
            """
        )
        cursor.execute(
            """
            UPDATE resolver_protocol t
            SET last_update_ts = COALESCE(s.last_update_ts, NOW())
            FROM resolver_protocol_stage s
            WHERE t.resolver_id = s.resolver_id
              AND t.protocol = s.protocol
              AND (
                  %s
                  OR (
                      s.last_update_ts IS NOT NULL
                      AND s.last_update_ts > t.last_update_ts
                  )
              )
            """,
            (force,),
        )

    return {
        "candidates": candidates,
        "inserted": insert_count,
        "updated": update_count,
        "skipped": max(candidates - insert_count - update_count, 0),
    }


def import_location_module(cursor, dry_run: bool, force: bool) -> dict[str, int]:
    cursor.execute(
        """
        CREATE TEMP TABLE resolver_location_stage AS
        SELECT DISTINCT ON (resolver_id)
            resolver_id,
            country,
            city,
            last_update_ts
        FROM resolver_import_all
        WHERE resolver_id IS NOT NULL
          AND country IS NOT NULL
        ORDER BY resolver_id, last_update_ts DESC NULLS LAST
        """
    )
    cursor.execute("SELECT COUNT(*) FROM resolver_location_stage")
    candidates = cursor.fetchone()[0]
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM resolver_import_all
        WHERE resolver_id IS NOT NULL
        """
    )
    resolver_candidates = cursor.fetchone()[0]
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM resolver_location_stage s
        LEFT JOIN resolver_location t ON t.resolver_id = s.resolver_id
        WHERE t.resolver_id IS NULL
        """
    )
    insert_count = cursor.fetchone()[0]
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM resolver_location_stage s
        JOIN resolver_location t ON t.resolver_id = s.resolver_id
        WHERE %s
           OR t.country IS DISTINCT FROM s.country
           OR t.city IS DISTINCT FROM s.city
           OR (
               s.last_update_ts IS NOT NULL
               AND s.last_update_ts > t.last_update_ts
           )
        """,
        (force,),
    )
    update_count = cursor.fetchone()[0]

    if candidates:
        cursor.execute("SELECT DISTINCT country FROM resolver_location_stage WHERE country IS NOT NULL")
        ensure_country_locations(cursor.connection, {row[0] for row in cursor.fetchall()}, logger)

    if not dry_run:
        cursor.execute(
            """
            INSERT INTO resolver_location (resolver_id, country, city, last_update_ts)
            SELECT s.resolver_id, s.country, s.city, COALESCE(s.last_update_ts, NOW())
            FROM resolver_location_stage s
            LEFT JOIN resolver_location t ON t.resolver_id = s.resolver_id
            WHERE t.resolver_id IS NULL
            """
        )
        cursor.execute(
            """
            UPDATE resolver_location t
            SET country = s.country,
                city = s.city,
                last_update_ts = CASE
                    WHEN %s THEN COALESCE(s.last_update_ts, NOW())
                    WHEN s.last_update_ts IS NOT NULL AND s.last_update_ts > t.last_update_ts THEN s.last_update_ts
                    WHEN t.country IS DISTINCT FROM s.country OR t.city IS DISTINCT FROM s.city THEN COALESCE(s.last_update_ts, NOW())
                    ELSE t.last_update_ts
                END
            FROM resolver_location_stage s
            WHERE t.resolver_id = s.resolver_id
              AND (
                  %s
                  OR t.country IS DISTINCT FROM s.country
                  OR t.city IS DISTINCT FROM s.city
                  OR (
                      s.last_update_ts IS NOT NULL
                      AND s.last_update_ts > t.last_update_ts
                  )
              )
            """,
            (force, force),
        )

    return {
        "candidates": candidates,
        "inserted": insert_count,
        "updated": update_count,
        "skipped": max(resolver_candidates - insert_count - update_count, 0),
    }


def import_resolvers(
    path: Path,
    mapping: dict[str, str] | str | Iterable[str],
    modules: list[str] | str,
    dry_run: bool = True,
    verified: bool = False,
    force: bool = False,
    has_header: bool = True,
    headers: list[str] | str | Iterable[str] | None = None,
    separator: str = ",",
    source: str | None = None,
) -> dict[str, dict[str, int]]:
    from data_gathering.config.db_connection import close_db_connection, connect_to_db

    if not isinstance(mapping, dict):
        mapping = parse_column_mapping(mapping)
    modules = parse_modules(modules)
    parsed_headers = parse_headers(headers)
    parsed_separator = parse_separator(separator)

    total_rows, rows, invalid_ip_count = load_rows(
        path,
        mapping,
        modules,
        has_header=has_header,
        headers=parsed_headers,
        separator=parsed_separator,
        source=source,
        verified=verified,
    )
    logger.info("Read {count} rows from {path}", count=total_rows, path=path)
    logger.info("Mapping validation passed for modules: {modules}", modules=", ".join(modules))
    if dry_run:
        logger.info("Dry-run mode is active; use --no-dry-run to write changes")
    if invalid_ip_count:
        logger.warning(
            "Skipped {count} rows with missing or invalid IP addresses ({percent}%)",
            count=invalid_ip_count,
            percent=percent(invalid_ip_count, total_rows),
        )

    cursor = connect_to_db()
    connection = cursor.connection
    try:
        create_base_stage(cursor, rows)
        reports = {"resolver": import_resolver_module(cursor, dry_run=dry_run, verified=verified, force=force)}
        for module in modules:
            if module == "resolver":
                continue
            if module == "location":
                reports[module] = import_location_module(cursor, dry_run=dry_run, force=force)
            elif module == "protocol":
                reports[module] = import_protocol_module(cursor, dry_run=dry_run, force=force)
            else:
                reports[module] = import_simple_module(cursor, module=module, dry_run=dry_run, force=force)

        if dry_run:
            connection.rollback()
        else:
            connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        close_db_connection(cursor)

    for module, report in reports.items():
        logger.info(
            "{module}: candidates={candidates}, inserted={inserted}, updated={updated}, "
            "skipped={skipped}, growth={growth}",
            module=module,
            candidates=report.get("candidates", 0),
            inserted=report.get("inserted", 0),
            updated=report.get("updated", 0),
            skipped=report.get("skipped", 0),
            growth=report.get("growth", report.get("inserted", 0)),
        )
        if module == "resolver" and (
            report.get("verified_updates", 0) or report.get("verification_inserts", 0)
        ):
            logger.info(
                "resolver: verified_updates={updates}, verification_inserts={inserts}",
                updates=report["verified_updates"],
                inserts=report["verification_inserts"],
            )
    return reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="General fast resolver importer.")
    parser.add_argument("file", type=Path, help="Input file path: CSV, Parquet, JSON, or NDJSON")
    parser.add_argument(
        "--mapping",
        "-m",
        action="append",
        required=True,
        help="Required column mapping as db_column:file_column. Can be repeated or comma-separated.",
    )
    parser.add_argument(
        "--modules",
        required=True,
        help="Comma-separated modules from: resolver,asn,prefix,location,protocol,endpoint,org,domain",
    )
    parser.add_argument(
        "--no-dry-run",
        action="store_true",
        help="Write changes to the database. By default the script only reports what would happen.",
    )
    parser.add_argument(
        "--verified",
        action="store_true",
        help="Set verified=true for newly created and existing resolver_id rows.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing resolver rows and attributes regardless of timestamp comparisons.",
    )
    parser.add_argument(
        "--no-header",
        action="store_true",
        help="Read CSV input without a header row. Requires --headers.",
    )
    parser.add_argument(
        "--headers",
        help="Comma-separated CSV column names to use with --no-header.",
    )
    parser.add_argument(
        "--separator",
        default=",",
        help="CSV separator character. Use '\\t' for tab. Default: ','.",
    )
    parser.add_argument(
        "--source",
        help="Default source value when no source column is mapped. Defaults to the input filename.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    mapping = parse_column_mapping(args.mapping)
    modules = parse_modules(args.modules)
    import_resolvers(
        args.file,
        mapping,
        modules=modules,
        dry_run=not args.no_dry_run,
        verified=args.verified,
        force=args.force,
        has_header=not args.no_header,
        headers=args.headers,
        separator=args.separator,
        source=args.source,
    )


if __name__ == "__main__":
    main()
