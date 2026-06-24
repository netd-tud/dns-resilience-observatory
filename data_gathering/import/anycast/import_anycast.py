"""Fast anycast table importer using PostgreSQL temp tables."""

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


MODULES = {"anycast", "asn", "asn_backend", "location"}
MODULE_REQUIRED_COLUMNS = {
    "anycast": {"prefix"},
    "asn": {"prefix", "asn"},
    "asn_backend": {"prefix", "asn"},
    "location": {"prefix", "country"},
}
SUPPORTED_COLUMNS = {
    "prefix",
    "backing_prefix",
    "partial",
    "asn",
    "asn_count",
    "country",
    "country_count",
    "last_update_ts",
    "source",
}
DEFAULT_SOURCE = "anycast-import"


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
    ordered = [module for module in ("anycast", "asn", "asn_backend", "location") if module in modules]
    if not ordered:
        raise ValueError("At least one module is required")
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


def normalize_prefix(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return None


def normalize_bool(value: object | None, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "t", "yes", "y"}:
        return True
    if text in {"0", "false", "f", "no", "n"}:
        return False
    return default


def normalize_asn(value: object | None) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        asn = int(text)
    except ValueError:
        return None
    if asn < 0 or asn > 4_294_967_295:
        return None
    return asn


def normalize_count(value: object | None) -> int | None:
    if value is None:
        return None
    try:
        count = int(value)
    except (TypeError, ValueError):
        return None
    return count if count >= 0 else None


def _is_empty(rows: Any) -> bool:
    try:
        import polars as pl
    except ModuleNotFoundError:
        pl = None

    if pl is not None and isinstance(rows, pl.DataFrame):
        return rows.is_empty()
    return not rows


def _row_count(rows: Any) -> int:
    try:
        import polars as pl
    except ModuleNotFoundError:
        pl = None

    if pl is not None and isinstance(rows, pl.DataFrame):
        return rows.height
    return len(rows)


def _iter_rows(rows: Any):
    try:
        import polars as pl
    except ModuleNotFoundError:
        pl = None

    if pl is not None and isinstance(rows, pl.DataFrame):
        return rows.iter_rows()
    return iter(rows)


def _select_columns(frame, columns: list[str]):
    missing = [column for column in columns if column not in frame.columns]
    if missing:
        raise ValueError(f"Input data is missing columns: {', '.join(missing)}")
    return frame.select(columns)


def _current_import_ts() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _with_metadata(rows: Any, *, source: str, last_update_ts: dt.datetime):
    try:
        import polars as pl
    except ModuleNotFoundError:
        pl = None

    if _is_empty(rows):
        return rows
    if pl is not None and isinstance(rows, pl.DataFrame):
        expressions = []
        if "last_update_ts" in rows.columns:
            expressions.append(pl.coalesce(pl.col("last_update_ts"), pl.lit(last_update_ts)).alias("last_update_ts"))
        else:
            expressions.append(pl.lit(last_update_ts).alias("last_update_ts"))
        if "source" in rows.columns:
            expressions.append(pl.coalesce(pl.col("source"), pl.lit(source)).cast(pl.Utf8).alias("source"))
        else:
            expressions.append(pl.lit(source).alias("source"))
        return rows.with_columns(expressions)

    enriched = []
    for row in rows:
        if isinstance(row, dict):
            enriched_row = dict(row)
            enriched_row["last_update_ts"] = enriched_row.get("last_update_ts") or last_update_ts
            enriched_row["source"] = enriched_row.get("source") or source
            enriched.append(enriched_row)
        else:
            enriched.append(tuple(row) + (last_update_ts, source))
    return enriched


def _copy_rows(rows: Any, columns: list[str]):
    try:
        import polars as pl
    except ModuleNotFoundError:
        pl = None

    if pl is not None and isinstance(rows, pl.DataFrame):
        yield from rows.select(columns).iter_rows()
    else:
        for row in rows:
            if isinstance(row, dict):
                yield tuple(row[column] for column in columns)
            else:
                yield row


def _sources_from_rows(*row_sets: Any) -> set[str]:
    sources: set[str] = set()
    try:
        import polars as pl
    except ModuleNotFoundError:
        pl = None

    for rows in row_sets:
        if _is_empty(rows):
            continue
        if pl is not None and isinstance(rows, pl.DataFrame):
            if "source" in rows.columns:
                sources.update(str(value) for value in rows["source"].drop_nulls().unique().to_list())
            continue
        for row in rows:
            if isinstance(row, dict):
                value = row.get("source")
            else:
                value = row[-1] if row else None
            if value:
                sources.add(str(value))
    return sources


def _touch_data_sources(cursor, sources: set[str], last_retrieved_ts: dt.datetime) -> None:
    if not sources:
        return
    ordered_sources = sorted(sources)
    cursor.execute(
        "SELECT source FROM data_source WHERE source = ANY(%s)",
        (ordered_sources,),
    )
    existing_sources = {row[0] for row in cursor.fetchall()}
    missing_sources = sorted(set(ordered_sources) - existing_sources)
    if missing_sources:
        raise ValueError(
            "Missing data_source rows for source(s): "
            f"{', '.join(missing_sources)}. Add them to data_source before importing anycast data."
        )
    cursor.execute(
        """
        UPDATE data_source
        SET last_retrieved_ts = %s
        WHERE source = ANY(%s)
        """,
        (last_retrieved_ts, ordered_sources),
    )


def validate_mapping(frame, mapping: dict[str, str], modules: list[str]) -> None:
    required_columns = set().union(*(MODULE_REQUIRED_COLUMNS[module] for module in modules))
    missing_mapped_columns = sorted(required_columns - set(mapping))
    if missing_mapped_columns:
        raise ValueError(f"Mapping is missing required database columns: {', '.join(missing_mapped_columns)}")

    missing_file_columns = sorted({file_column for file_column in mapping.values() if file_column not in frame.columns})
    if missing_file_columns:
        raise ValueError(f"Input file is missing mapped columns: {', '.join(missing_file_columns)}")


def prepare_country_frame(frame, mapping: dict[str, str]):
    import polars as pl
    from data_gathering.tasks.country_locations import normalize_country

    country_source = mapping["country"]
    country_columns = [
        pl.col(mapping["prefix"]).map_elements(normalize_prefix, return_dtype=pl.Utf8).alias("prefix"),
        pl.col(country_source).alias("_country_source"),
    ]
    if "country_count" in mapping:
        country_columns.append(pl.col(mapping["country_count"]).alias("_country_count"))
    if "last_update_ts" in mapping:
        country_columns.append(pl.col(mapping["last_update_ts"]).alias("last_update_ts"))
    if "source" in mapping:
        country_columns.append(pl.col(mapping["source"]).cast(pl.Utf8).alias("source"))
    country_frame = frame.select(country_columns).filter(pl.col("prefix").is_not_null())

    source_dtype = country_frame.schema["_country_source"]
    logger.info(
        "Mapped country column {column} has dtype {dtype}",
        column=country_source,
        dtype=source_dtype,
    )
    if isinstance(source_dtype, pl.List):
        country_frame = country_frame.explode("_country_source").filter(pl.col("_country_source").is_not_null())
        source_dtype = country_frame.schema["_country_source"]
        logger.info(
            "Exploded country mapping column {column}; element dtype is {dtype}",
            column=country_source,
            dtype=source_dtype,
        )

    if isinstance(source_dtype, pl.Struct):
        country_frame = country_frame.unnest("_country_source")
        country_candidates = [column for column in ("country_code", "country") if column in country_frame.columns]
        if not country_candidates:
            raise ValueError(
                f"Mapped country struct column {country_source!r} must contain country_code or country"
            )
        country_column = country_candidates[0]
        logger.info(
            "Using field {field} from mapped country struct column {column}",
            field=country_column,
            column=country_source,
        )
        select_columns = [
            "prefix",
            pl.col(country_column).map_elements(normalize_country, return_dtype=pl.Utf8).alias("country"),
        ]
        if "_country_count" in country_frame.columns:
            select_columns.append(
                pl.col("_country_count").map_elements(normalize_count, return_dtype=pl.Int64).alias("country_count")
            )
        if "last_update_ts" in country_frame.columns:
            select_columns.append("last_update_ts")
        if "source" in country_frame.columns:
            select_columns.append("source")
        return country_frame.select(select_columns)

    logger.info(
        "Using mapped country column {column} as scalar country code/name",
        column=country_source,
    )
    select_columns = [
        "prefix",
        pl.col("_country_source").map_elements(normalize_country, return_dtype=pl.Utf8).alias("country"),
    ]
    if "_country_count" in country_frame.columns:
        select_columns.append(
            pl.col("_country_count").map_elements(normalize_count, return_dtype=pl.Int64).alias("country_count")
        )
    if "last_update_ts" in country_frame.columns:
        select_columns.append("last_update_ts")
    if "source" in country_frame.columns:
        select_columns.append("source")
    return country_frame.select(select_columns)


def prepare_import_frames(path: Path, mapping: dict[str, str], modules: list[str]):
    import polars as pl

    frame = read_input_file(path)
    validate_mapping(frame, mapping, modules)

    selected_columns = list(dict.fromkeys(mapping.values()))
    normalized = frame.select(selected_columns)
    if "prefix" in mapping:
        normalized = normalized.with_columns(
            pl.col(mapping["prefix"]).map_elements(normalize_prefix, return_dtype=pl.Utf8).alias("prefix")
        )
    if "backing_prefix" in mapping:
        normalized = normalized.with_columns(
            pl.col(mapping["backing_prefix"]).map_elements(normalize_prefix, return_dtype=pl.Utf8).alias("backing_prefix")
        )
    else:
        normalized = normalized.with_columns(pl.col("prefix").alias("backing_prefix"))
    if "partial" in mapping:
        normalized = normalized.with_columns(
            pl.col(mapping["partial"]).map_elements(normalize_bool, return_dtype=pl.Boolean).alias("partial")
        )
    else:
        normalized = normalized.with_columns(pl.lit(False).alias("partial"))
    if "asn" in mapping:
        normalized = (
            normalized.with_columns(pl.col(mapping["asn"]).cast(pl.Utf8).str.split("_").alias("asn"))
            .explode("asn")
            .with_columns(
                pl.when(pl.col("asn") == "-")
                .then(None)
                .otherwise(pl.col("asn"))
                .map_elements(normalize_asn, return_dtype=pl.Int64)
                .alias("asn")
            )
        )
    if "asn_count" in mapping:
        normalized = normalized.with_columns(
            pl.col(mapping["asn_count"]).map_elements(normalize_count, return_dtype=pl.Int64).alias("asn_count")
        )
    if "country_count" in mapping:
        normalized = normalized.with_columns(
            pl.col(mapping["country_count"]).map_elements(normalize_count, return_dtype=pl.Int64).alias("country_count")
        )
    if "last_update_ts" in mapping:
        normalized = normalized.with_columns(pl.col(mapping["last_update_ts"]).alias("last_update_ts"))
    if "source" in mapping:
        normalized = normalized.with_columns(pl.col(mapping["source"]).cast(pl.Utf8).alias("source"))

    normalized = normalized.filter(pl.col("prefix").is_not_null())
    metadata_aggs = []
    if "last_update_ts" in normalized.columns:
        metadata_aggs.append(pl.col("last_update_ts").drop_nulls().max())
    if "source" in normalized.columns:
        metadata_aggs.append(pl.col("source").drop_nulls().first())
    anycast_rows = None
    asn_rows = None
    country_backend_rows = None
    asn_backend_rows = None

    if "anycast" in modules:
        anycast_rows = (
            normalized.group_by("prefix")
            .agg(
                pl.col("backing_prefix").drop_nulls().first(),
                pl.col("partial").any(),
                *metadata_aggs,
            )
            .sort("prefix")
        )

    if "asn" in modules:
        if metadata_aggs:
            asn_rows = (
                normalized.filter(pl.col("asn").is_not_null())
                .group_by("prefix", "asn")
                .agg(*metadata_aggs)
                .sort("prefix", "asn")
            )
        else:
            asn_rows = (
                normalized.filter(pl.col("asn").is_not_null())
                .select("prefix", "asn")
                .unique()
                .sort("prefix", "asn")
            )

    if "asn_backend" in modules:
        if "asn_count" in mapping:
            asn_backend_rows = (
                normalized.filter(pl.col("asn").is_not_null() & pl.col("asn_count").is_not_null())
                .group_by("prefix", "asn")
                .agg(pl.col("asn_count").max(), *metadata_aggs)
                .sort("prefix", "asn")
            )
        elif "prefix" in mapping:
            asn_backend_rows = (
                normalized.filter(pl.col("asn").is_not_null())
                .group_by("prefix", "asn")
                .agg(pl.len().alias("asn_count"), *metadata_aggs)
                .sort("prefix", "asn")
            )
        else:
            asn_backend_rows = (
                normalized.filter(pl.col("asn").is_not_null())
                .group_by("prefix", "asn")
                .agg(pl.len().alias("asn_count"), *metadata_aggs)
                .sort("prefix", "asn")
            )

    if "location" in modules:
        country_frame = prepare_country_frame(frame, mapping)
        country_metadata_aggs = []
        if "last_update_ts" in country_frame.columns:
            country_metadata_aggs.append(pl.col("last_update_ts").drop_nulls().max())
        if "source" in country_frame.columns:
            country_metadata_aggs.append(pl.col("source").drop_nulls().first())
        if "country_count" in mapping:
            country_backend_rows = (
                country_frame.filter(pl.col("country").is_not_null() & pl.col("country_count").is_not_null())
                .group_by("prefix", "country")
                .agg(pl.col("country_count").sum(), *country_metadata_aggs)
                .sort("prefix", "country")
            )
        else:
            country_backend_rows = (
                country_frame.filter(pl.col("country").is_not_null())
                .group_by("prefix", "country")
                .agg(pl.len().alias("country_count"), *country_metadata_aggs)
                .sort("prefix", "country")
            )

    logger.info(
        "Prepared anycast import frames from {path}: anycast={anycast}, asn={asn}, location={location}, asn_backend={asn_backend}",
        path=path,
        anycast=0 if anycast_rows is None else anycast_rows.height,
        asn=0 if asn_rows is None else asn_rows.height,
        location=0 if country_backend_rows is None else country_backend_rows.height,
        asn_backend=0 if asn_backend_rows is None else asn_backend_rows.height,
    )
    return anycast_rows, asn_rows, country_backend_rows, asn_backend_rows


def import_anycast(
    *,
    anycast_rows=None,
    asn_rows=None,
    country_backend_rows=None,
    asn_backend_rows=None,
    source: str = DEFAULT_SOURCE,
    force: bool = False,
    dry_run: bool = False,
) -> dict[str, int]:
    from data_gathering.config.db_connection import close_db_connection, connect_to_db

    import_ts = _current_import_ts()
    anycast_rows = [] if anycast_rows is None else _with_metadata(anycast_rows, source=source, last_update_ts=import_ts)
    asn_rows = [] if asn_rows is None else _with_metadata(asn_rows, source=source, last_update_ts=import_ts)
    country_backend_rows = (
        [] if country_backend_rows is None else _with_metadata(country_backend_rows, source=source, last_update_ts=import_ts)
    )
    asn_backend_rows = [] if asn_backend_rows is None else _with_metadata(asn_backend_rows, source=source, last_update_ts=import_ts)

    report = {
        "anycast_rows": _row_count(anycast_rows),
        "anycast_asn_rows": _row_count(asn_rows),
        "anycast_country_backend_rows": _row_count(country_backend_rows),
        "anycast_asn_backend_rows": _row_count(asn_backend_rows),
        "affected_anycast": 0,
        "affected_anycast_asn": 0,
        "affected_anycast_country_backend": 0,
        "affected_anycast_asn_backend": 0,
    }
    if not any(
        not _is_empty(row_set)
        for row_set in (anycast_rows, asn_rows, country_backend_rows, asn_backend_rows)
    ):
        logger.info("No anycast rows to import")
        return report

    cursor = connect_to_db()
    connection = cursor.connection
    try:
        _touch_data_sources(
            cursor,
            _sources_from_rows(anycast_rows, asn_rows, country_backend_rows, asn_backend_rows),
            import_ts,
        )
        if not _is_empty(anycast_rows):
            cursor.execute(
                """
                CREATE TEMP TABLE anycast_stage (
                    prefix CIDR NOT NULL,
                    backing_prefix CIDR,
                    partial BOOLEAN NOT NULL,
                    last_update_ts TIMESTAMPTZ NOT NULL,
                    source TEXT NOT NULL
                ) ON COMMIT DROP
                """
            )
            with cursor.copy(
                "COPY anycast_stage (prefix, backing_prefix, partial, last_update_ts, source) FROM STDIN"
            ) as copy:
                for row in _copy_rows(anycast_rows, ["prefix", "backing_prefix", "partial", "last_update_ts", "source"]):
                    copy.write_row(row)
            cursor.execute(
                """
                INSERT INTO anycast (prefix, backing_prefix, partial, last_update_ts, source)
                SELECT prefix, backing_prefix, partial, last_update_ts, source
                FROM anycast_stage
                ON CONFLICT (prefix)
                DO UPDATE SET
                    backing_prefix = EXCLUDED.backing_prefix,
                    partial = EXCLUDED.partial,
                    last_update_ts = EXCLUDED.last_update_ts,
                    source = EXCLUDED.source
                WHERE anycast.backing_prefix IS DISTINCT FROM EXCLUDED.backing_prefix
                   OR anycast.partial IS DISTINCT FROM EXCLUDED.partial
                   OR anycast.last_update_ts IS DISTINCT FROM EXCLUDED.last_update_ts
                   OR anycast.source IS DISTINCT FROM EXCLUDED.source
                """
            )
            report["affected_anycast"] = cursor.rowcount

        if not _is_empty(asn_rows):
            cursor.execute(
                """
                CREATE TEMP TABLE anycast_asn_stage (
                    prefix CIDR NOT NULL,
                    asn BIGINT NOT NULL,
                    last_update_ts TIMESTAMPTZ NOT NULL,
                    source TEXT NOT NULL
                ) ON COMMIT DROP
                """
            )
            with cursor.copy("COPY anycast_asn_stage (prefix, asn, last_update_ts, source) FROM STDIN") as copy:
                for row in _copy_rows(asn_rows, ["prefix", "asn", "last_update_ts", "source"]):
                    copy.write_row(row)
            cursor.execute(
                """
                INSERT INTO anycast_asn (prefix, asn, last_update_ts, source)
                SELECT prefix, asn, last_update_ts, source
                FROM anycast_asn_stage
                ON CONFLICT (prefix, asn)
                DO UPDATE SET
                    last_update_ts = EXCLUDED.last_update_ts,
                    source = EXCLUDED.source
                WHERE anycast_asn.last_update_ts IS DISTINCT FROM EXCLUDED.last_update_ts
                   OR anycast_asn.source IS DISTINCT FROM EXCLUDED.source
                """
            )
            report["affected_anycast_asn"] = cursor.rowcount

        if not _is_empty(country_backend_rows):
            cursor.execute(
                """
                CREATE TEMP TABLE anycast_country_backend_stage (
                    prefix CIDR NOT NULL,
                    country TEXT NOT NULL,
                    country_count INTEGER NOT NULL,
                    last_update_ts TIMESTAMPTZ NOT NULL,
                    source TEXT NOT NULL
                ) ON COMMIT DROP
                """
            )
            with cursor.copy(
                "COPY anycast_country_backend_stage (prefix, country, country_count, last_update_ts, source) FROM STDIN"
            ) as copy:
                for row in _copy_rows(
                    country_backend_rows,
                    ["prefix", "country", "country_count", "last_update_ts", "source"],
                ):
                    copy.write_row(row)
            cursor.execute(
                """
                INSERT INTO anycast_country_backend (prefix, country, country_count, last_update_ts, source)
                SELECT prefix, country, country_count, last_update_ts, source
                FROM anycast_country_backend_stage
                ON CONFLICT (prefix, country)
                DO UPDATE SET
                    country_count = EXCLUDED.country_count,
                    last_update_ts = EXCLUDED.last_update_ts,
                    source = EXCLUDED.source
                WHERE %s
                   OR (
                       EXCLUDED.last_update_ts > anycast_country_backend.last_update_ts
                       AND EXCLUDED.country_count > anycast_country_backend.country_count
                   )
                """,
                (force,),
            )
            report["affected_anycast_country_backend"] = cursor.rowcount

        if not _is_empty(asn_backend_rows):
            cursor.execute(
                """
                CREATE TEMP TABLE anycast_asn_backend_stage (
                    prefix CIDR NOT NULL,
                    asn BIGINT NOT NULL,
                    asn_count INTEGER NOT NULL,
                    last_update_ts TIMESTAMPTZ NOT NULL,
                    source TEXT NOT NULL
                ) ON COMMIT DROP
                """
            )
            with cursor.copy(
                "COPY anycast_asn_backend_stage (prefix, asn, asn_count, last_update_ts, source) FROM STDIN"
            ) as copy:
                for row in _copy_rows(
                    asn_backend_rows,
                    ["prefix", "asn", "asn_count", "last_update_ts", "source"],
                ):
                    copy.write_row(row)
            cursor.execute(
                """
                INSERT INTO anycast_asn_backend (prefix, asn, asn_count, last_update_ts, source)
                SELECT prefix, asn, asn_count, last_update_ts, source
                FROM anycast_asn_backend_stage
                ON CONFLICT (prefix, asn)
                DO UPDATE SET
                    asn_count = EXCLUDED.asn_count,
                    last_update_ts = EXCLUDED.last_update_ts,
                    source = EXCLUDED.source
                WHERE %s
                   OR (
                       EXCLUDED.last_update_ts > anycast_asn_backend.last_update_ts
                       AND EXCLUDED.asn_count > anycast_asn_backend.asn_count
                   )
                """,
                (force,),
            )
            report["affected_anycast_asn_backend"] = cursor.rowcount

        if dry_run:
            connection.rollback()
        else:
            connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        close_db_connection(cursor)

    logger.info("Applied anycast import: {}", report)
    return report


def import_anycast_file(
    path: Path,
    mapping: dict[str, str] | str | Iterable[str],
    modules: list[str] | str,
    source: str = DEFAULT_SOURCE,
    force: bool = False,
    dry_run: bool = True,
) -> dict[str, int]:
    if not isinstance(mapping, dict):
        mapping = parse_column_mapping(mapping)
    modules = parse_modules(modules)
    anycast_rows, asn_rows, country_backend_rows, asn_backend_rows = prepare_import_frames(path, mapping, modules)
    if dry_run:
        logger.info("Dry-run mode is active; use --no-dry-run to write changes")
    return import_anycast(
        anycast_rows=anycast_rows,
        asn_rows=asn_rows,
        country_backend_rows=country_backend_rows,
        asn_backend_rows=asn_backend_rows,
        source=source,
        force=force,
        dry_run=dry_run,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fast anycast importer.")
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
        help="Comma-separated modules from: anycast,asn,asn_backend,location",
    )
    parser.add_argument(
        "--no-dry-run",
        action="store_true",
        help="Write changes to the database. By default the script rolls back after validation.",
    )
    parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE,
        help=f"Data source label to write when no source column is mapped. Defaults to {DEFAULT_SOURCE!r}.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing backend counts regardless of timestamp or count comparisons.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    mapping = parse_column_mapping(args.mapping)
    modules = parse_modules(args.modules)
    import_anycast_file(
        args.file,
        mapping,
        modules=modules,
        source=args.source,
        force=args.force,
        dry_run=not args.no_dry_run,
    )


if __name__ == "__main__":
    main()
