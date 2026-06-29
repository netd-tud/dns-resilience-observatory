"""Fast DNSSEC table importer using PostgreSQL temp tables."""

from __future__ import annotations

import datetime as dt
import logging
from typing import Any, Iterable

try:
    from loguru import logger
except ModuleNotFoundError:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    logger = logging.getLogger(__name__)

from data_gathering.imports.country.country_locations import ensure_country_locations, normalize_country


MODULES = {"country", "asn"}
DEFAULT_SOURCE = "apnic-dnssec"


def parse_modules(value: str | Iterable[str]) -> list[str]:
    if isinstance(value, str):
        modules = [item.strip().lower() for item in value.split(",") if item.strip()]
    else:
        modules = [item.strip().lower() for item in value if item.strip()]
    unknown = sorted(set(modules) - MODULES)
    if unknown:
        raise ValueError(f"Unsupported modules: {', '.join(unknown)}")
    ordered = [module for module in ("country", "asn") if module in modules]
    if not ordered:
        raise ValueError("At least one module is required")
    return ordered


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


def _current_import_ts() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _prepare_country_rows(rows: Any, *, source: str, last_update_ts: dt.datetime):
    import polars as pl

    if rows is None or _is_empty(rows):
        return pl.DataFrame(
            schema={
                "country": pl.Utf8,
                "validating": pl.Int64,
                "validating_pc": pl.Float64,
                "partial_validating": pl.Int64,
                "partial_validating_pc": pl.Float64,
                "last_update_ts": pl.Datetime(time_zone="UTC"),
                "source": pl.Utf8,
            }
        )

    frame = rows if isinstance(rows, pl.DataFrame) else pl.DataFrame(rows)
    required = {"country", "validating", "validating_pc", "partial_validating", "partial_validating_pc"}
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"DNSSEC country rows are missing columns: {', '.join(missing)}")

    timestamp_expr = (
        pl.col("last_update_ts")
        if "last_update_ts" in frame.columns
        else pl.col("last_observation_ts")
        if "last_observation_ts" in frame.columns
        else pl.lit(last_update_ts)
    )
    source_expr = pl.col("source") if "source" in frame.columns else pl.lit(source)

    return (
        frame.with_columns(
            pl.col("country").map_elements(normalize_country, return_dtype=pl.Utf8).alias("country"),
            pl.col("validating").cast(pl.Int64, strict=False).alias("validating"),
            pl.col("validating_pc").cast(pl.Float64, strict=False).alias("validating_pc"),
            pl.col("partial_validating").cast(pl.Int64, strict=False).alias("partial_validating"),
            pl.col("partial_validating_pc").cast(pl.Float64, strict=False).alias("partial_validating_pc"),
            pl.coalesce(timestamp_expr, pl.lit(last_update_ts)).alias("last_update_ts"),
            pl.coalesce(source_expr, pl.lit(source)).cast(pl.Utf8).alias("source"),
        )
        .select(
            "country",
            "validating",
            "validating_pc",
            "partial_validating",
            "partial_validating_pc",
            "last_update_ts",
            "source",
        )
        .filter(
            pl.col("country").is_not_null()
            & pl.col("validating").is_not_null()
            & pl.col("validating_pc").is_not_null()
            & pl.col("partial_validating").is_not_null()
            & pl.col("partial_validating_pc").is_not_null()
            & pl.col("last_update_ts").is_not_null()
        )
        .sort("last_update_ts", descending=True)
        .unique("country", keep="first")
    )


def _prepare_asn_rows(rows: Any, *, source: str, last_update_ts: dt.datetime):
    import polars as pl

    if rows is None or _is_empty(rows):
        return pl.DataFrame(
            schema={
                "asn": pl.Int64,
                "validating": pl.Int64,
                "validating_pc": pl.Float64,
                "partial_validating": pl.Int64,
                "partial_validating_pc": pl.Float64,
                "last_update_ts": pl.Datetime(time_zone="UTC"),
                "source": pl.Utf8,
            }
        )

    frame = rows if isinstance(rows, pl.DataFrame) else pl.DataFrame(rows)
    required = {"asn", "validating", "validating_pc", "partial_validating", "partial_validating_pc"}
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"DNSSEC ASN rows are missing columns: {', '.join(missing)}")

    timestamp_expr = (
        pl.col("last_update_ts")
        if "last_update_ts" in frame.columns
        else pl.col("last_observation_ts")
        if "last_observation_ts" in frame.columns
        else pl.lit(last_update_ts)
    )
    source_expr = pl.col("source") if "source" in frame.columns else pl.lit(source)

    return (
        frame.with_columns(
            pl.col("asn").cast(pl.Int64, strict=False).alias("asn"),
            pl.col("validating").cast(pl.Int64, strict=False).alias("validating"),
            pl.col("validating_pc").cast(pl.Float64, strict=False).alias("validating_pc"),
            pl.col("partial_validating").cast(pl.Int64, strict=False).alias("partial_validating"),
            pl.col("partial_validating_pc").cast(pl.Float64, strict=False).alias("partial_validating_pc"),
            pl.coalesce(timestamp_expr, pl.lit(last_update_ts)).alias("last_update_ts"),
            pl.coalesce(source_expr, pl.lit(source)).cast(pl.Utf8).alias("source"),
        )
        .select(
            "asn",
            "validating",
            "validating_pc",
            "partial_validating",
            "partial_validating_pc",
            "last_update_ts",
            "source",
        )
        .filter(
            pl.col("asn").is_not_null()
            & pl.col("validating").is_not_null()
            & pl.col("validating_pc").is_not_null()
            & pl.col("partial_validating").is_not_null()
            & pl.col("partial_validating_pc").is_not_null()
            & pl.col("last_update_ts").is_not_null()
        )
        .sort("last_update_ts", descending=True)
        .unique("asn", keep="first")
    )


def _touch_data_sources(cursor, sources: set[str], last_retrieved_ts: dt.datetime) -> None:
    if not sources:
        return
    ordered_sources = sorted(sources)
    cursor.execute("SELECT source FROM data_source WHERE source = ANY(%s)", (ordered_sources,))
    existing_sources = {row[0] for row in cursor.fetchall()}
    missing_sources = sorted(set(ordered_sources) - existing_sources)
    if missing_sources:
        raise ValueError(
            "Missing data_source rows for source(s): "
            f"{', '.join(missing_sources)}. Add them to data_source before importing DNSSEC data."
        )
    cursor.execute(
        """
        UPDATE data_source
        SET last_retrieved_ts = %s
        WHERE source = ANY(%s)
        """,
        (last_retrieved_ts, ordered_sources),
    )


def import_dnssec(
    *,
    country_rows=None,
    asn_rows=None,
    modules: list[str] | str = "country",
    source: str = DEFAULT_SOURCE,
    force: bool = False,
    dry_run: bool = False,
) -> dict[str, int]:
    from data_gathering.config.db_connection import close_db_connection, connect_to_db

    modules = parse_modules(modules)
    import_ts = _current_import_ts()
    country_frame = _prepare_country_rows(country_rows, source=source, last_update_ts=import_ts)
    asn_frame = _prepare_asn_rows(asn_rows, source=source, last_update_ts=import_ts)

    report = {
        "dnssec_country_rows": country_frame.height,
        "dnssec_asn_rows": asn_frame.height,
        "affected_dnssec_country": 0,
        "affected_dnssec_asn": 0,
    }
    if ("country" not in modules or country_frame.is_empty()) and ("asn" not in modules or asn_frame.is_empty()):
        logger.info("No DNSSEC rows to import")
        return report

    cursor = connect_to_db()
    connection = cursor.connection
    try:
        sources = set()
        if "country" in modules and not country_frame.is_empty():
            sources.update(country_frame["source"].drop_nulls().unique().to_list())
        if "asn" in modules and not asn_frame.is_empty():
            sources.update(asn_frame["source"].drop_nulls().unique().to_list())
        _touch_data_sources(cursor, sources, import_ts)

        if "country" in modules and not country_frame.is_empty():
            ensure_country_locations(
                connection,
                {str(country) for country in country_frame["country"].drop_nulls().unique().to_list()},
                logger,
            )
            cursor.execute(
                """
                CREATE TEMP TABLE dnssec_country_stage (
                    country TEXT NOT NULL,
                    validating BIGINT NOT NULL,
                    validating_pc DOUBLE PRECISION NOT NULL,
                    partial_validating BIGINT NOT NULL,
                    partial_validating_pc DOUBLE PRECISION NOT NULL,
                    last_update_ts TIMESTAMPTZ NOT NULL,
                    source TEXT NOT NULL
                ) ON COMMIT DROP
                """
            )
            with cursor.copy(
                """
                COPY dnssec_country_stage (
                    country, validating, validating_pc, partial_validating,
                    partial_validating_pc, last_update_ts, source
                ) FROM STDIN
                """
            ) as copy:
                for row in country_frame.iter_rows():
                    copy.write_row(row)

            cursor.execute(
                """
                INSERT INTO dnssec_country (
                    country, validating, validating_pc, partial_validating,
                    partial_validating_pc, last_update_ts, source
                )
                SELECT
                    country, validating, validating_pc, partial_validating,
                    partial_validating_pc, last_update_ts, source
                FROM dnssec_country_stage
                ON CONFLICT (country)
                DO UPDATE SET
                    validating = EXCLUDED.validating,
                    validating_pc = EXCLUDED.validating_pc,
                    partial_validating = EXCLUDED.partial_validating,
                    partial_validating_pc = EXCLUDED.partial_validating_pc,
                    last_update_ts = EXCLUDED.last_update_ts,
                    source = EXCLUDED.source
                WHERE %s OR EXCLUDED.last_update_ts > dnssec_country.last_update_ts
                """,
                (force,),
            )
            report["affected_dnssec_country"] = cursor.rowcount

        if "asn" in modules and not asn_frame.is_empty():
            cursor.execute(
                """
                CREATE TEMP TABLE dnssec_asn_stage (
                    asn BIGINT NOT NULL,
                    validating BIGINT NOT NULL,
                    validating_pc DOUBLE PRECISION NOT NULL,
                    partial_validating BIGINT NOT NULL,
                    partial_validating_pc DOUBLE PRECISION NOT NULL,
                    last_update_ts TIMESTAMPTZ NOT NULL,
                    source TEXT NOT NULL
                ) ON COMMIT DROP
                """
            )
            with cursor.copy(
                """
                COPY dnssec_asn_stage (
                    asn, validating, validating_pc, partial_validating,
                    partial_validating_pc, last_update_ts, source
                ) FROM STDIN
                """
            ) as copy:
                for row in asn_frame.iter_rows():
                    copy.write_row(row)

            cursor.execute(
                """
                INSERT INTO dnssec_asn (
                    asn, validating, validating_pc, partial_validating,
                    partial_validating_pc, last_update_ts, source
                )
                SELECT
                    asn, validating, validating_pc, partial_validating,
                    partial_validating_pc, last_update_ts, source
                FROM dnssec_asn_stage
                ON CONFLICT (asn)
                DO UPDATE SET
                    validating = EXCLUDED.validating,
                    validating_pc = EXCLUDED.validating_pc,
                    partial_validating = EXCLUDED.partial_validating,
                    partial_validating_pc = EXCLUDED.partial_validating_pc,
                    last_update_ts = EXCLUDED.last_update_ts,
                    source = EXCLUDED.source
                WHERE %s OR EXCLUDED.last_update_ts > dnssec_asn.last_update_ts
                """,
                (force,),
            )
            report["affected_dnssec_asn"] = cursor.rowcount

        if dry_run:
            connection.rollback()
        else:
            connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        close_db_connection(cursor)

    logger.info("Applied DNSSEC import: {}", report)
    return report
