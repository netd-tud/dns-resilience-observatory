"""Fast QMIN resolver importer using PostgreSQL temp tables."""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import logging
import sys
from pathlib import Path
from typing import Any, Iterable

try:
    from loguru import logger
except ModuleNotFoundError:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    logger = logging.getLogger(__name__)

OBSERVATORY_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(OBSERVATORY_ROOT))


MODULES = {"qmin"}
SUPPORTED_COLUMNS = {
    "resolver_ip",
    "qmin",
    "max_minimise_count",
    "minimize_one_lab",
    "last_update_ts",
    "source",
}
DEFAULT_SOURCE = "qmin-import"
QMIN_CODE_MAP = {
    "0": "no",
    "1": "yes",
    "2": "unstable",
    "no": "no",
    "yes": "yes",
    "unstable": "unstable",
}


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
    if not modules:
        raise ValueError("At least one module is required")
    return ["qmin"]


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


def _is_polars_frame(value: Any) -> bool:
    try:
        import polars as pl
    except ModuleNotFoundError:
        return False
    return isinstance(value, pl.DataFrame)


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


def normalize_int(value: object) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(float(text))
    except ValueError:
        return None


def normalize_qmin(value: object) -> str | None:
    text = normalize_text(value)
    if text is None:
        return None
    normalized = text.lower()
    if normalized.endswith(".0"):
        normalized = normalized[:-2]
    return QMIN_CODE_MAP.get(normalized, normalized)


def normalize_timestamp(value: object) -> dt.datetime | None:
    if value is None:
        return None
    if isinstance(value, dt.datetime):
        return value.astimezone(dt.timezone.utc) if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    if isinstance(value, dt.date):
        return dt.datetime(value.year, value.month, value.day, tzinfo=dt.timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(dt.timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def normalize_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def default_import_ts() -> dt.datetime:
    now = dt.datetime.now(dt.timezone.utc)
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


def validate_mapping(frame, mapping: dict[str, str]) -> None:
    required_columns = {"resolver_ip", "qmin"}
    missing_mapped_columns = sorted(required_columns - set(mapping))
    if missing_mapped_columns:
        raise ValueError(f"Mapping is missing required database columns: {', '.join(missing_mapped_columns)}")

    missing_file_columns = sorted({file_column for file_column in mapping.values() if file_column not in frame.columns})
    if missing_file_columns:
        raise ValueError(f"Input data is missing mapped columns: {', '.join(missing_file_columns)}")


def load_rows(
    rows_or_path: Any,
    mapping: dict[str, str],
    *,
    source: str = DEFAULT_SOURCE,
) -> tuple[int, list[dict[str, object]], int]:
    frame = read_input_file(rows_or_path) if isinstance(rows_or_path, Path) else rows_or_path
    if not _is_polars_frame(frame):
        import polars as pl

        frame = pl.DataFrame(frame)

    validate_mapping(frame, mapping)
    selected_columns = list(dict.fromkeys(mapping.values()))
    import_ts = default_import_ts()
    rows = []
    invalid_ip_count = 0

    for record in frame.select(selected_columns).to_dicts():
        resolver_ip = normalize_ip(record.get(mapping["resolver_ip"]))
        if resolver_ip is None:
            invalid_ip_count += 1
            continue

        row = {
            "resolver_ip": resolver_ip,
            "qmin": normalize_qmin(record.get(mapping["qmin"])),
            "max_minimise_count": normalize_int(record.get(mapping["max_minimise_count"]))
            if "max_minimise_count" in mapping
            else None,
            "minimize_one_lab": normalize_int(record.get(mapping["minimize_one_lab"]))
            if "minimize_one_lab" in mapping
            else None,
            "last_update_ts": normalize_timestamp(record.get(mapping["last_update_ts"]))
            if "last_update_ts" in mapping
            else import_ts,
            "source": normalize_text(record.get(mapping["source"])) if "source" in mapping else source,
        }
        row["last_update_ts"] = row["last_update_ts"] or import_ts
        row["source"] = row["source"] or source
        rows.append(row)

    return frame.height, rows, invalid_ip_count


def percent(part: int, whole: int) -> float:
    return round((part / whole) * 100, 2) if whole else 0.0


def touch_data_sources(cursor, sources: set[str], last_retrieved_ts: dt.datetime) -> None:
    if not sources:
        return
    ordered_sources = sorted(sources)
    cursor.execute("SELECT source FROM data_source WHERE source = ANY(%s)", (ordered_sources,))
    existing_sources = {row[0] for row in cursor.fetchall()}
    missing_sources = sorted(set(ordered_sources) - existing_sources)
    if missing_sources:
        raise ValueError(
            "Missing data_source rows for source(s): "
            f"{', '.join(missing_sources)}. Add them to data_source before importing QMIN data."
        )
    cursor.execute(
        """
        UPDATE data_source
        SET last_retrieved_ts = %s
        WHERE source = ANY(%s)
        """,
        (last_retrieved_ts, ordered_sources),
    )


def create_stage(cursor, rows: list[dict[str, object]]) -> None:
    cursor.execute(
        """
        CREATE TEMP TABLE qmin_import_stage (
            resolver_ip INET NOT NULL,
            qmin TEXT,
            max_minimise_count INTEGER,
            minimize_one_lab INTEGER,
            last_update_ts TIMESTAMPTZ NOT NULL,
            source TEXT NOT NULL
        ) ON COMMIT DROP
        """
    )
    with cursor.copy(
        """
        COPY qmin_import_stage (
            resolver_ip, qmin, max_minimise_count, minimize_one_lab, last_update_ts, source
        ) FROM STDIN
        """
    ) as copy:
        for row in rows:
            copy.write_row(
                [
                    row["resolver_ip"],
                    row["qmin"],
                    row["max_minimise_count"],
                    row["minimize_one_lab"],
                    row["last_update_ts"],
                    row["source"],
                ]
            )


def import_qmin_module(cursor, *, dry_run: bool, force: bool) -> dict[str, int]:
    cursor.execute("SELECT COUNT(*) FROM qmin_import_stage")
    candidates = cursor.fetchone()[0]

    cursor.execute(
        """
        CREATE TEMP TABLE qmin_missing_resolver AS
        SELECT s.resolver_ip
        FROM qmin_import_stage s
        LEFT JOIN resolver r ON r.ip = s.resolver_ip
        WHERE r.resolver_id IS NULL
        """
    )
    cursor.execute("SELECT DISTINCT resolver_ip::TEXT FROM qmin_missing_resolver ORDER BY resolver_ip LIMIT 20")
    missing_samples = [row[0] for row in cursor.fetchall()]
    cursor.execute("SELECT COUNT(*) FROM qmin_missing_resolver")
    missing_resolver_count = cursor.fetchone()[0]
    if missing_resolver_count:
        logger.warning(
            "Skipped {count} QMIN rows because resolver_ip does not exist in resolver. Samples: {samples}",
            count=missing_resolver_count,
            samples=", ".join(missing_samples),
        )

    cursor.execute(
        """
        CREATE TEMP TABLE qmin_resolved_stage AS
        SELECT DISTINCT ON (r.resolver_id)
            r.resolver_id,
            s.qmin,
            s.max_minimise_count,
            s.minimize_one_lab,
            s.last_update_ts,
            s.source
        FROM qmin_import_stage s
        JOIN resolver r ON r.ip = s.resolver_ip
        ORDER BY r.resolver_id, s.last_update_ts DESC
        """
    )
    cursor.execute("SELECT COUNT(*) FROM qmin_resolved_stage")
    matched_rows = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM qmin_resolved_stage s
        JOIN qmin_resolver q ON q.resolver_id = s.resolver_id
        WHERE %s
           OR s.last_update_ts > q.last_update_ts
           OR q.qmin IS DISTINCT FROM s.qmin
           OR q.max_minimise_count IS DISTINCT FROM s.max_minimise_count
           OR q.minimize_one_lab IS DISTINCT FROM s.minimize_one_lab
        """,
        (force,),
    )
    updated_candidates = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM qmin_resolved_stage s
        LEFT JOIN qmin_resolver q ON q.resolver_id = s.resolver_id
        WHERE q.resolver_id IS NULL
        """,
    )
    insert_candidates = cursor.fetchone()[0]

    if not dry_run:
        cursor.execute(
            """
            INSERT INTO qmin_resolver (
                resolver_id,
                qmin,
                max_minimise_count,
                minimize_one_lab,
                last_update_ts,
                first_qmin_observation,
                last_qmin_observation,
                source
            )
            SELECT
                resolver_id,
                qmin,
                max_minimise_count,
                minimize_one_lab,
                last_update_ts,
                CASE WHEN qmin = 'yes' THEN last_update_ts ELSE NULL END,
                CASE WHEN qmin = 'yes' THEN last_update_ts ELSE NULL END,
                source
            FROM qmin_resolved_stage
            ON CONFLICT (resolver_id)
            DO UPDATE SET
                qmin = EXCLUDED.qmin,
                max_minimise_count = EXCLUDED.max_minimise_count,
                minimize_one_lab = EXCLUDED.minimize_one_lab,
                last_update_ts = CASE
                    WHEN %s OR EXCLUDED.last_update_ts > qmin_resolver.last_update_ts
                        THEN EXCLUDED.last_update_ts
                    ELSE qmin_resolver.last_update_ts
                END,
                first_qmin_observation = CASE
                    WHEN EXCLUDED.qmin = 'yes'
                     AND qmin_resolver.qmin IS DISTINCT FROM 'yes'
                     AND (%s OR EXCLUDED.last_update_ts > qmin_resolver.last_update_ts)
                        THEN EXCLUDED.last_update_ts
                    ELSE qmin_resolver.first_qmin_observation
                END,
                last_qmin_observation = CASE
                    WHEN EXCLUDED.qmin = 'yes'
                     AND (%s OR EXCLUDED.last_update_ts > qmin_resolver.last_update_ts)
                        THEN EXCLUDED.last_update_ts
                    ELSE qmin_resolver.last_qmin_observation
                END,
                source = EXCLUDED.source
            WHERE %s
               OR EXCLUDED.last_update_ts > qmin_resolver.last_update_ts
               OR qmin_resolver.qmin IS DISTINCT FROM EXCLUDED.qmin
               OR qmin_resolver.max_minimise_count IS DISTINCT FROM EXCLUDED.max_minimise_count
               OR qmin_resolver.minimize_one_lab IS DISTINCT FROM EXCLUDED.minimize_one_lab
            """,
            (force, force, force, force),
        )

    return {
        "candidates": candidates,
        "matched": matched_rows,
        "missing_resolver": missing_resolver_count,
        "inserted": insert_candidates,
        "updated": updated_candidates,
        "skipped": max(candidates - insert_candidates - updated_candidates - missing_resolver_count, 0),
    }


def import_qmin(
    rows_or_path: Any,
    *,
    mapping: dict[str, str] | str | Iterable[str],
    modules: list[str] | str = "qmin",
    source: str = DEFAULT_SOURCE,
    dry_run: bool = True,
    force: bool = False,
) -> dict[str, dict[str, int]]:
    from data_gathering.config.db_connection import close_db_connection, connect_to_db

    if not isinstance(mapping, dict):
        mapping = parse_column_mapping(mapping)
    modules = parse_modules(modules)

    total_rows, rows, invalid_ip_count = load_rows(rows_or_path, mapping, source=source)
    logger.info("Read {count} QMIN rows", count=total_rows)
    logger.info("Mapping validation passed for modules: {modules}", modules=", ".join(modules))
    if dry_run:
        logger.info("Dry-run mode is active; use --no-dry-run to write changes")
    if invalid_ip_count:
        logger.warning(
            "Skipped {count} rows with missing or invalid resolver_ip values ({percent}%)",
            count=invalid_ip_count,
            percent=percent(invalid_ip_count, total_rows),
        )

    cursor = connect_to_db()
    connection = cursor.connection
    try:
        touch_data_sources(cursor, {row["source"] for row in rows}, default_import_ts())
        create_stage(cursor, rows)
        reports = {"qmin": import_qmin_module(cursor, dry_run=dry_run, force=force)}
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
            "{module}: candidates={candidates}, matched={matched}, inserted={inserted}, "
            "updated={updated}, missing_resolver={missing_resolver}, skipped={skipped}",
            module=module,
            candidates=report.get("candidates", 0),
            matched=report.get("matched", 0),
            inserted=report.get("inserted", 0),
            updated=report.get("updated", 0),
            missing_resolver=report.get("missing_resolver", 0),
            skipped=report.get("skipped", 0),
        )
    return reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fast QMIN resolver importer.")
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
        default="qmin",
        help="Comma-separated modules from: qmin",
    )
    parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE,
        help=f"Default source when no source column is mapped. Default: {DEFAULT_SOURCE}",
    )
    parser.add_argument(
        "--no-dry-run",
        action="store_true",
        help="Write changes to the database. By default the script only reports what would happen.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing QMIN rows regardless of timestamp comparisons.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    import_qmin(
        args.file,
        mapping=parse_column_mapping(args.mapping),
        modules=parse_modules(args.modules),
        source=args.source,
        dry_run=not args.no_dry_run,
        force=args.force,
    )


if __name__ == "__main__":
    main()
