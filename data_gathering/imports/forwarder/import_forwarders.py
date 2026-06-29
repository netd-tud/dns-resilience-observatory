"""General fast forwarder importer with optional attribute and upstream modules."""

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


MODULES = {"forwarder", "asn", "prefix", "location", "protocol", "endpoint", "org", "domain", "upstream"}
MODULE_REQUIRED_COLUMNS = {
    "forwarder": {"ip"},
    "asn": {"ip", "asn"},
    "prefix": {"ip", "prefix"},
    "location": {"ip", "country"},
    "protocol": {"ip", "protocol"},
    "endpoint": {"ip", "endpoint"},
    "org": {"ip", "org"},
    "domain": {"ip", "domain"},
    "upstream": {"ip", "upstream_ip"},
}
SUPPORTED_COLUMNS = set().union(*MODULE_REQUIRED_COLUMNS.values()) | {
    "city",
    "is_public",
    "last_update_ts",
    "source",
    "type",
}
ATTRIBUTE_MODULES = ("asn", "prefix", "location", "protocol", "endpoint", "org", "domain", "upstream")


def parse_column_mapping(mapping_values: Iterable[str] | str | None) -> dict[str, str]:
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
    ordered = ["forwarder"]
    ordered.extend(module for module in ATTRIBUTE_MODULES if module in modules)
    return ordered


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


def normalize_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def normalize_forwarder_type(value: object) -> str:
    text = normalize_text(value)
    if text is None:
        return "recursive"
    normalized = text.lower()
    if normalized in {"transparent", "transparent forwarder"}:
        return "transparent"
    if normalized in {"recursive", "forwarder"}:
        return "recursive"
    return normalized


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
    missing_mapped_columns = sorted(required_columns - set(mapping))
    if missing_mapped_columns:
        raise ValueError(f"Mapping is missing required database columns: {', '.join(missing_mapped_columns)}")

    missing_file_columns = sorted({file_column for file_column in mapping.values() if file_column not in frame.columns})
    if missing_file_columns:
        raise ValueError(f"Input file is missing mapped columns: {', '.join(missing_file_columns)}")


def load_rows(path: Path, mapping: dict[str, str], modules: list[str]):
    frame = read_input_file(path)
    validate_mapping(frame, mapping, modules)

    selected_columns = list(dict.fromkeys(mapping.values()))
    rows = []
    invalid_ip_count = 0
    import_ts = datetime.now(timezone.utc)
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
            "source": normalize_text(record.get(mapping["source"])) if "source" in mapping else path.name,
            "last_update_ts": normalize_timestamp(record.get(mapping["last_update_ts"]))
            if "last_update_ts" in mapping
            else import_ts,
            "type": normalize_forwarder_type(record.get(mapping["type"])) if "type" in mapping else "recursive",
            "upstream_ip": normalize_ip(record.get(mapping["upstream_ip"])) if "upstream_ip" in mapping else None,
        }
        row["source"] = row["source"] or path.name
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
        CREATE TEMP TABLE forwarder_import_stage (
            ip INET NOT NULL,
            is_public BOOLEAN NOT NULL,
            source TEXT NOT NULL,
            last_update_ts TIMESTAMPTZ,
            type TEXT NOT NULL,
            asn INTEGER,
            prefix CIDR,
            country TEXT,
            city TEXT,
            protocol TEXT,
            endpoint TEXT,
            org TEXT,
            domain TEXT,
            upstream_ip INET
        ) ON COMMIT DROP
        """
    )
    with cursor.copy(
        """
        COPY forwarder_import_stage (
            ip, is_public, source, last_update_ts, asn, prefix, country,
            city, protocol, endpoint, org, domain, upstream_ip, type
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
                    row["asn"],
                    row["prefix"],
                    row["country"],
                    row["city"],
                    row["protocol"],
                    row["endpoint"],
                    row["org"],
                    row["domain"],
                    row["upstream_ip"],
                    row["type"],
                ]
            )

    cursor.execute(
        """
        CREATE TEMP TABLE forwarder_import_unique AS
        SELECT DISTINCT ON (ip)
            ip, is_public, source, last_update_ts, asn, prefix, country,
            city, protocol, endpoint, org, domain, upstream_ip, type
        FROM forwarder_import_stage
        ORDER BY ip, last_update_ts DESC NULLS LAST, source
        """
    )
    cursor.execute("CREATE INDEX forwarder_import_unique_ip_idx ON forwarder_import_unique (ip)")


def import_forwarder_module(cursor, dry_run: bool, force: bool) -> dict[str, int]:
    cursor.execute("SELECT COUNT(*) FROM forwarder")
    before_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM forwarder_import_stage")
    valid_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM forwarder_import_unique")
    unique_count = cursor.fetchone()[0]
    duplicate_count = valid_count - unique_count
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM forwarder_import_unique u
        JOIN forwarder f ON f.ip = u.ip
        """
    )
    existing_count = cursor.fetchone()[0]
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM forwarder_import_unique u
        JOIN forwarder f ON f.ip = u.ip
        WHERE %s
           OR f.type IS DISTINCT FROM u.type
           OR (
               u.last_update_ts IS NOT NULL
               AND u.last_update_ts > f.last_update_ts
           )
        """,
        (force,),
    )
    changed_existing_count = cursor.fetchone()[0]
    if not dry_run:
        cursor.execute(
            """
            UPDATE forwarder f
            SET
                is_public = u.is_public,
                type = u.type,
                transparent_count = COALESCE(f.transparent_count, 0) + CASE
                    WHEN u.type = 'transparent' AND u.last_update_ts IS NOT NULL AND u.last_update_ts > f.last_update_ts THEN 1
                    ELSE 0
                END,
                recursive_count = COALESCE(f.recursive_count, 0) + CASE
                    WHEN u.type = 'recursive' AND u.last_update_ts IS NOT NULL AND u.last_update_ts > f.last_update_ts THEN 1
                    ELSE 0
                END,
                last_observed_as_transparent = CASE
                    WHEN u.type = 'transparent' AND u.last_update_ts IS NOT NULL AND u.last_update_ts > f.last_update_ts THEN u.last_update_ts
                    ELSE f.last_observed_as_transparent
                END,
                last_observed_as_recursive = CASE
                    WHEN u.type = 'recursive' AND u.last_update_ts IS NOT NULL AND u.last_update_ts > f.last_update_ts THEN u.last_update_ts
                    ELSE f.last_observed_as_recursive
                END,
                last_update_ts = CASE
                    WHEN %s OR (u.last_update_ts IS NOT NULL AND u.last_update_ts > f.last_update_ts) THEN COALESCE(u.last_update_ts, NOW())
                    ELSE f.last_update_ts
                END,
                source = u.source
            FROM forwarder_import_unique u
            WHERE f.ip = u.ip
            """,
            (force,),
        )

    if dry_run:
        cursor.execute(
            """
            CREATE TEMP TABLE forwarder_import_pending AS
            SELECT (-(ROW_NUMBER() OVER (ORDER BY u.ip)))::BIGINT AS forwarder_id, u.*
            FROM forwarder_import_unique u
            WHERE NOT EXISTS (SELECT 1 FROM forwarder f WHERE f.ip = u.ip)
            """
        )
        cursor.execute("CREATE UNIQUE INDEX forwarder_import_pending_ip_idx ON forwarder_import_pending (ip)")
    else:
        cursor.execute(
            """
            CREATE TEMP TABLE forwarder_import_pending AS
            SELECT nextval(pg_get_serial_sequence('forwarder_id', 'id')) AS forwarder_id, u.*
            FROM forwarder_import_unique u
            WHERE NOT EXISTS (SELECT 1 FROM forwarder f WHERE f.ip = u.ip)
            """
        )
        cursor.execute("CREATE UNIQUE INDEX forwarder_import_pending_ip_idx ON forwarder_import_pending (ip)")
    cursor.execute("SELECT COUNT(*) FROM forwarder_import_pending")
    insert_count = cursor.fetchone()[0]

    if dry_run:
        after_count = before_count
    else:
        cursor.execute(
            """
            INSERT INTO forwarder_id (id, last_update_ts, total_measurements, seen_measurements)
            SELECT forwarder_id, COALESCE(last_update_ts, NOW()), 0, 0
            FROM forwarder_import_pending
            """
        )
        cursor.execute(
            """
            INSERT INTO forwarder (
                ip, forwarder_id, is_public, last_update_ts, type, transparent_count, recursive_count,
                last_observed_as_transparent, last_observed_as_recursive, source
            )
            SELECT
                ip,
                forwarder_id,
                is_public,
                COALESCE(last_update_ts, NOW()),
                type,
                CASE WHEN type = 'transparent' THEN 1 ELSE 0 END,
                CASE WHEN type = 'recursive' THEN 1 ELSE 0 END,
                CASE WHEN type = 'transparent' THEN COALESCE(last_update_ts, NOW()) ELSE NULL END,
                CASE WHEN type = 'recursive' THEN COALESCE(last_update_ts, NOW()) ELSE NULL END,
                source
            FROM forwarder_import_pending
            ON CONFLICT (ip) DO UPDATE
            SET
                type = EXCLUDED.type,
                transparent_count = COALESCE(forwarder.transparent_count, 0) + CASE
                    WHEN EXCLUDED.last_update_ts > forwarder.last_update_ts THEN EXCLUDED.transparent_count
                    ELSE 0
                END,
                recursive_count = COALESCE(forwarder.recursive_count, 0) + CASE
                    WHEN EXCLUDED.last_update_ts > forwarder.last_update_ts THEN EXCLUDED.recursive_count
                    ELSE 0
                END,
                last_observed_as_transparent = COALESCE(
                    CASE
                        WHEN EXCLUDED.last_update_ts > forwarder.last_update_ts THEN EXCLUDED.last_observed_as_transparent
                        ELSE forwarder.last_observed_as_transparent
                    END,
                    forwarder.last_observed_as_transparent
                ),
                last_observed_as_recursive = COALESCE(
                    CASE
                        WHEN EXCLUDED.last_update_ts > forwarder.last_update_ts THEN EXCLUDED.last_observed_as_recursive
                        ELSE forwarder.last_observed_as_recursive
                    END,
                    forwarder.last_observed_as_recursive
                ),
                last_update_ts = CASE
                    WHEN EXCLUDED.last_update_ts > forwarder.last_update_ts THEN EXCLUDED.last_update_ts
                    ELSE forwarder.last_update_ts
                END,
                is_public = COALESCE(EXCLUDED.is_public, forwarder.is_public),
                source = COALESCE(EXCLUDED.source, forwarder.source)
            WHERE %s
               OR forwarder.type IS DISTINCT FROM EXCLUDED.type
               OR EXCLUDED.last_update_ts > forwarder.last_update_ts
            """,
            (force,),
        )
        cursor.execute(
            """
            DELETE FROM forwarder_id fi
            USING forwarder_import_pending p
            WHERE fi.id = p.forwarder_id
              AND NOT EXISTS (
                  SELECT 1
                  FROM forwarder f
                  WHERE f.forwarder_id = fi.id
              )
            """
        )
        cursor.execute("SELECT COUNT(*) FROM forwarder")
        after_count = cursor.fetchone()[0]

    cursor.execute(
        """
        CREATE TEMP TABLE forwarder_import_all AS
        SELECT
            COALESCE(f.forwarder_id, p.forwarder_id) AS forwarder_id,
            u.*
        FROM forwarder_import_unique u
        LEFT JOIN forwarder f ON f.ip = u.ip
        LEFT JOIN forwarder_import_pending p ON p.ip = u.ip
        """
    )
    cursor.execute("CREATE INDEX forwarder_import_all_forwarder_id_idx ON forwarder_import_all (forwarder_id)")
    cursor.execute("CREATE INDEX forwarder_import_all_ip_idx ON forwarder_import_all (ip)")

    return {
        "candidates": valid_count,
        "inserted": insert_count,
        "updated": existing_count,
        "changed_existing": changed_existing_count,
        "skipped": duplicate_count,
        "growth": insert_count if dry_run else after_count - before_count,
    }


MODULE_SQL = {
    "asn": ("forwarder_asn", "asn", "asn IS NOT NULL", "asn"),
    "prefix": ("forwarder_prefix", "prefix", "prefix IS NOT NULL", "prefix"),
    "endpoint": ("forwarder_endpoint", "endpoint", "endpoint IS NOT NULL", "endpoint"),
    "org": ("forwarder_org", "org", "org IS NOT NULL", "org"),
    "domain": ("forwarder_domain", "domain", "domain IS NOT NULL", "domain"),
}


def import_simple_module(cursor, module: str, dry_run: bool, force: bool) -> dict[str, int]:
    table, column, condition, value = MODULE_SQL[module]
    stage_table = f"forwarder_{module}_stage"
    cursor.execute(
        f"""
        CREATE TEMP TABLE {stage_table} AS
        SELECT DISTINCT ON (forwarder_id)
            forwarder_id,
            {value} AS value,
            last_update_ts
        FROM forwarder_import_all
        WHERE forwarder_id IS NOT NULL
          AND {condition}
        ORDER BY forwarder_id, last_update_ts DESC NULLS LAST
        """
    )
    cursor.execute(f"SELECT COUNT(*) FROM {stage_table}")
    candidates = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM forwarder_import_all WHERE forwarder_id IS NOT NULL")
    forwarder_candidates = cursor.fetchone()[0]
    cursor.execute(
        f"""
        SELECT COUNT(*)
        FROM {stage_table} s
        LEFT JOIN {table} t ON t.forwarder_id = s.forwarder_id
        WHERE t.forwarder_id IS NULL
        """
    )
    insert_count = cursor.fetchone()[0]
    cursor.execute(
        f"""
        SELECT COUNT(*)
        FROM {stage_table} s
        JOIN {table} t ON t.forwarder_id = s.forwarder_id
        WHERE %s
           OR t.{column} IS DISTINCT FROM s.value
           OR (s.last_update_ts IS NOT NULL AND s.last_update_ts > t.last_update_ts)
        """,
        (force,),
    )
    update_count = cursor.fetchone()[0]

    if not dry_run:
        cursor.execute(
            f"""
            INSERT INTO {table} (forwarder_id, {column}, last_update_ts)
            SELECT s.forwarder_id, s.value, COALESCE(s.last_update_ts, NOW())
            FROM {stage_table} s
            LEFT JOIN {table} t ON t.forwarder_id = s.forwarder_id
            WHERE t.forwarder_id IS NULL
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
            WHERE t.forwarder_id = s.forwarder_id
              AND (
                  %s
                  OR t.{column} IS DISTINCT FROM s.value
                  OR (s.last_update_ts IS NOT NULL AND s.last_update_ts > t.last_update_ts)
              )
            """,
            (force, force),
        )

    return {
        "candidates": candidates,
        "inserted": insert_count,
        "updated": update_count,
        "skipped": max(forwarder_candidates - insert_count - update_count, 0),
    }


def import_protocol_module(cursor, dry_run: bool, force: bool) -> dict[str, int]:
    cursor.execute(
        """
        CREATE TEMP TABLE forwarder_protocol_stage AS
        SELECT DISTINCT ON (forwarder_id, protocol)
            forwarder_id,
            protocol,
            last_update_ts
        FROM (
            SELECT
                forwarder_id,
                LOWER(TRIM(protocol_part)) AS protocol,
                last_update_ts
            FROM forwarder_import_all
            CROSS JOIN LATERAL regexp_split_to_table(protocol, ',') AS protocol_part
            WHERE forwarder_id IS NOT NULL
              AND protocol IS NOT NULL
        ) split_protocols
        WHERE protocol <> ''
        ORDER BY forwarder_id, protocol, last_update_ts DESC NULLS LAST
        """
    )
    cursor.execute("SELECT COUNT(*) FROM forwarder_protocol_stage")
    candidates = cursor.fetchone()[0]
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM forwarder_protocol_stage s
        LEFT JOIN forwarder_protocol t
          ON t.forwarder_id = s.forwarder_id
         AND t.protocol = s.protocol
        WHERE t.forwarder_id IS NULL
        """
    )
    insert_count = cursor.fetchone()[0]
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM forwarder_protocol_stage s
        JOIN forwarder_protocol t
          ON t.forwarder_id = s.forwarder_id
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
            INSERT INTO forwarder_protocol (forwarder_id, protocol, last_update_ts)
            SELECT s.forwarder_id, s.protocol, COALESCE(s.last_update_ts, NOW())
            FROM forwarder_protocol_stage s
            LEFT JOIN forwarder_protocol t
              ON t.forwarder_id = s.forwarder_id
             AND t.protocol = s.protocol
            WHERE t.forwarder_id IS NULL
            """
        )
        cursor.execute(
            """
            UPDATE forwarder_protocol t
            SET last_update_ts = COALESCE(s.last_update_ts, NOW())
            FROM forwarder_protocol_stage s
            WHERE t.forwarder_id = s.forwarder_id
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
        CREATE TEMP TABLE forwarder_location_stage AS
        SELECT DISTINCT ON (forwarder_id)
            forwarder_id,
            country,
            city,
            last_update_ts
        FROM forwarder_import_all
        WHERE forwarder_id IS NOT NULL
          AND country IS NOT NULL
        ORDER BY forwarder_id, last_update_ts DESC NULLS LAST
        """
    )
    cursor.execute("SELECT COUNT(*) FROM forwarder_location_stage")
    candidates = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM forwarder_import_all WHERE forwarder_id IS NOT NULL")
    forwarder_candidates = cursor.fetchone()[0]
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM forwarder_location_stage s
        LEFT JOIN forwarder_location t ON t.forwarder_id = s.forwarder_id
        WHERE t.forwarder_id IS NULL
        """
    )
    insert_count = cursor.fetchone()[0]
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM forwarder_location_stage s
        JOIN forwarder_location t ON t.forwarder_id = s.forwarder_id
        WHERE %s
           OR t.country IS DISTINCT FROM s.country
           OR t.city IS DISTINCT FROM s.city
           OR (s.last_update_ts IS NOT NULL AND s.last_update_ts > t.last_update_ts)
        """,
        (force,),
    )
    update_count = cursor.fetchone()[0]
    if candidates:
        cursor.execute("SELECT DISTINCT country FROM forwarder_location_stage WHERE country IS NOT NULL")
        ensure_country_locations(cursor.connection, {row[0] for row in cursor.fetchall()}, logger)

    if not dry_run:
        cursor.execute(
            """
            INSERT INTO forwarder_location (forwarder_id, country, city, last_update_ts)
            SELECT s.forwarder_id, s.country, s.city, COALESCE(s.last_update_ts, NOW())
            FROM forwarder_location_stage s
            LEFT JOIN forwarder_location t ON t.forwarder_id = s.forwarder_id
            WHERE t.forwarder_id IS NULL
            """
        )
        cursor.execute(
            """
            UPDATE forwarder_location t
            SET country = s.country,
                city = s.city,
                last_update_ts = CASE
                    WHEN %s THEN COALESCE(s.last_update_ts, NOW())
                    WHEN s.last_update_ts IS NOT NULL AND s.last_update_ts > t.last_update_ts THEN s.last_update_ts
                    WHEN t.country IS DISTINCT FROM s.country OR t.city IS DISTINCT FROM s.city THEN COALESCE(s.last_update_ts, NOW())
                    ELSE t.last_update_ts
                END
            FROM forwarder_location_stage s
            WHERE t.forwarder_id = s.forwarder_id
              AND (
                  %s
                  OR t.country IS DISTINCT FROM s.country
                  OR t.city IS DISTINCT FROM s.city
                  OR (s.last_update_ts IS NOT NULL AND s.last_update_ts > t.last_update_ts)
              )
            """,
            (force, force),
        )
    return {
        "candidates": candidates,
        "inserted": insert_count,
        "updated": update_count,
        "skipped": max(forwarder_candidates - insert_count - update_count, 0),
    }


def import_upstream_module(cursor, dry_run: bool, force: bool) -> dict[str, int]:
    cursor.execute(
        """
        CREATE TEMP TABLE forwarder_upstream_stage AS
        SELECT DISTINCT ON (a.forwarder_id, s.upstream_ip)
            a.forwarder_id,
            s.upstream_ip,
            s.last_update_ts
        FROM forwarder_import_stage s
        JOIN forwarder_import_all a ON a.ip = s.ip
        WHERE a.forwarder_id IS NOT NULL
          AND s.upstream_ip IS NOT NULL
        ORDER BY a.forwarder_id, s.upstream_ip, s.last_update_ts DESC NULLS LAST
        """
    )
    cursor.execute("SELECT COUNT(*) FROM forwarder_upstream_stage")
    candidates = cursor.fetchone()[0]

    cursor.execute(
        """
        CREATE TEMP TABLE forwarder_resolver_upstream_stage AS
        SELECT
            s.forwarder_id,
            r.resolver_id AS upstream_resolver_id,
            s.last_update_ts
        FROM forwarder_upstream_stage s
        JOIN resolver r ON r.ip = s.upstream_ip
        """
    )
    cursor.execute(
        """
        CREATE TEMP TABLE forwarder_forwarder_upstream_stage AS
        SELECT
            s.forwarder_id,
            COALESCE(f.forwarder_id, a.forwarder_id) AS upstream_forwarder_id,
            s.last_update_ts
        FROM forwarder_upstream_stage s
        LEFT JOIN resolver r ON r.ip = s.upstream_ip
        LEFT JOIN forwarder f ON f.ip = s.upstream_ip
        LEFT JOIN forwarder_import_all a ON a.ip = s.upstream_ip
        WHERE r.resolver_id IS NULL
          AND COALESCE(f.forwarder_id, a.forwarder_id) IS NOT NULL
          AND COALESCE(f.forwarder_id, a.forwarder_id) <> s.forwarder_id
        """
    )

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM forwarder_resolver_upstream_stage s
        LEFT JOIN forwarder_resolver_upstream t
          ON t.forwarder_id = s.forwarder_id
         AND t.upstream_resolver_id = s.upstream_resolver_id
        WHERE t.forwarder_id IS NULL
        """
    )
    resolver_insert_count = cursor.fetchone()[0]
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM forwarder_forwarder_upstream_stage s
        LEFT JOIN forwarder_forwarder_upstream t
          ON t.forwarder_id = s.forwarder_id
         AND t.upstream_forwarder_id = s.upstream_forwarder_id
        WHERE t.forwarder_id IS NULL
        """
    )
    forwarder_insert_count = cursor.fetchone()[0]
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM forwarder_resolver_upstream_stage s
        JOIN forwarder_resolver_upstream t
          ON t.forwarder_id = s.forwarder_id
         AND t.upstream_resolver_id = s.upstream_resolver_id
        WHERE %s
           OR (s.last_update_ts IS NOT NULL AND s.last_update_ts > t.last_update_ts)
        """,
        (force,),
    )
    resolver_update_count = cursor.fetchone()[0]
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM forwarder_forwarder_upstream_stage s
        JOIN forwarder_forwarder_upstream t
          ON t.forwarder_id = s.forwarder_id
         AND t.upstream_forwarder_id = s.upstream_forwarder_id
        WHERE %s
           OR (s.last_update_ts IS NOT NULL AND s.last_update_ts > t.last_update_ts)
        """,
        (force,),
    )
    forwarder_update_count = cursor.fetchone()[0]

    if not dry_run:
        cursor.execute(
            """
            INSERT INTO forwarder_resolver_upstream (forwarder_id, upstream_resolver_id, last_update_ts)
            SELECT s.forwarder_id, s.upstream_resolver_id, COALESCE(s.last_update_ts, NOW())
            FROM forwarder_resolver_upstream_stage s
            LEFT JOIN forwarder_resolver_upstream t
              ON t.forwarder_id = s.forwarder_id
             AND t.upstream_resolver_id = s.upstream_resolver_id
            WHERE t.forwarder_id IS NULL
            """
        )
        cursor.execute(
            """
            UPDATE forwarder_resolver_upstream t
            SET last_update_ts = COALESCE(s.last_update_ts, NOW())
            FROM forwarder_resolver_upstream_stage s
            WHERE t.forwarder_id = s.forwarder_id
              AND t.upstream_resolver_id = s.upstream_resolver_id
              AND (
                  %s
                  OR (s.last_update_ts IS NOT NULL AND s.last_update_ts > t.last_update_ts)
              )
            """,
            (force,),
        )
        cursor.execute(
            """
            INSERT INTO forwarder_forwarder_upstream (forwarder_id, upstream_forwarder_id, last_update_ts)
            SELECT s.forwarder_id, s.upstream_forwarder_id, COALESCE(s.last_update_ts, NOW())
            FROM forwarder_forwarder_upstream_stage s
            LEFT JOIN forwarder_forwarder_upstream t
              ON t.forwarder_id = s.forwarder_id
             AND t.upstream_forwarder_id = s.upstream_forwarder_id
            WHERE t.forwarder_id IS NULL
            """
        )
        cursor.execute(
            """
            UPDATE forwarder_forwarder_upstream t
            SET last_update_ts = COALESCE(s.last_update_ts, NOW())
            FROM forwarder_forwarder_upstream_stage s
            WHERE t.forwarder_id = s.forwarder_id
              AND t.upstream_forwarder_id = s.upstream_forwarder_id
              AND (
                  %s
                  OR (s.last_update_ts IS NOT NULL AND s.last_update_ts > t.last_update_ts)
              )
            """,
            (force,),
        )

    inserted = resolver_insert_count + forwarder_insert_count
    updated = resolver_update_count + forwarder_update_count
    return {
        "candidates": candidates,
        "inserted": inserted,
        "updated": updated,
        "skipped": max(candidates - inserted - updated, 0),
    }


def import_forwarders(
    path: Path,
    mapping: dict[str, str] | str | Iterable[str],
    modules: list[str] | str,
    dry_run: bool = True,
    force: bool = False,
) -> dict[str, dict[str, int]]:
    from data_gathering.config.db_connection import close_db_connection, connect_to_db

    if not isinstance(mapping, dict):
        mapping = parse_column_mapping(mapping)
    modules = parse_modules(modules)

    total_rows, rows, invalid_ip_count = load_rows(path, mapping, modules)
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
        reports = {"forwarder": import_forwarder_module(cursor, dry_run=dry_run, force=force)}
        for module in modules:
            if module == "forwarder":
                continue
            if module == "location":
                reports[module] = import_location_module(cursor, dry_run=dry_run, force=force)
            elif module == "protocol":
                reports[module] = import_protocol_module(cursor, dry_run=dry_run, force=force)
            elif module == "upstream":
                reports[module] = import_upstream_module(cursor, dry_run=dry_run, force=force)
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
    return reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="General fast forwarder importer.")
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
        help="Comma-separated modules from: forwarder,asn,prefix,location,protocol,endpoint,org,domain,upstream",
    )
    parser.add_argument(
        "--no-dry-run",
        action="store_true",
        help="Write changes to the database. By default the script only reports what would happen.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing forwarder rows and attributes regardless of timestamp comparisons.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    mapping = parse_column_mapping(args.mapping)
    modules = parse_modules(args.modules)
    import_forwarders(args.file, mapping, modules=modules, dry_run=not args.no_dry_run, force=args.force)


if __name__ == "__main__":
    main()
