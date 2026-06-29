"""Fast spoofing table importer using PostgreSQL temp tables."""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
from typing import Any, Iterable

try:
    from loguru import logger
except ModuleNotFoundError:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    logger = logging.getLogger(__name__)

from data_gathering.imports.country.country_locations import ensure_country_locations, normalize_country


MODULES = {"spoofing", "asn", "country"}
DEFAULT_SOURCE = "caida-spoofer"


def parse_modules(value: str | Iterable[str]) -> list[str]:
    if isinstance(value, str):
        modules = [item.strip().lower() for item in value.split(",") if item.strip()]
    else:
        modules = [item.strip().lower() for item in value if item.strip()]
    unknown = sorted(set(modules) - MODULES)
    if unknown:
        raise ValueError(f"Unsupported modules: {', '.join(unknown)}")
    ordered = [module for module in ("spoofing", "asn", "country") if module in modules]
    if not ordered:
        raise ValueError("At least one module is required")
    return ordered


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


def _prepare_rows(rows: Any, *, source: str, last_update_ts: dt.datetime):
    import polars as pl

    if rows is None or _is_empty(rows):
        return pl.DataFrame(
            schema={
                "prefix": pl.Utf8,
                "nat": pl.Boolean,
                "privatespoof": pl.Utf8,
                "routedspoof": pl.Utf8,
                "asn": pl.Int64,
                "country": pl.Utf8,
                "last_update_ts": pl.Datetime(time_zone="UTC"),
                "source": pl.Utf8,
            }
        )
    frame = rows if isinstance(rows, pl.DataFrame) else pl.DataFrame(rows)
    required = {"prefix", "nat", "privatespoof", "routedspoof"}
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"Spoofing rows are missing columns: {', '.join(missing)}")

    expressions = [
        pl.col("prefix").map_elements(normalize_prefix, return_dtype=pl.Utf8).alias("prefix"),
        pl.col("nat").cast(pl.Boolean, strict=False).alias("nat"),
        pl.col("privatespoof").cast(pl.Utf8).alias("privatespoof"),
        pl.col("routedspoof").cast(pl.Utf8).alias("routedspoof"),
    ]
    if "asn" in frame.columns:
        expressions.append(pl.col("asn").cast(pl.Int64, strict=False).alias("asn"))
    else:
        expressions.append(pl.lit(None, dtype=pl.Int64).alias("asn"))
    if "country" in frame.columns:
        expressions.append(pl.col("country").map_elements(normalize_country, return_dtype=pl.Utf8).alias("country"))
    else:
        expressions.append(pl.lit(None, dtype=pl.Utf8).alias("country"))
    if "last_update_ts" in frame.columns:
        expressions.append(pl.coalesce(pl.col("last_update_ts"), pl.lit(last_update_ts)).alias("last_update_ts"))
    else:
        expressions.append(pl.lit(last_update_ts).alias("last_update_ts"))
    if "source" in frame.columns:
        expressions.append(pl.coalesce(pl.col("source"), pl.lit(source)).cast(pl.Utf8).alias("source"))
    else:
        expressions.append(pl.lit(source).alias("source"))

    return (
        frame.with_columns(expressions)
        .select("prefix", "nat", "privatespoof", "routedspoof", "asn", "country", "last_update_ts", "source")
        .filter(pl.col("prefix").is_not_null())
        .sort("last_update_ts", descending=True)
        .unique("prefix", keep="first")
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
            f"{', '.join(missing_sources)}. Add them to data_source before importing spoofing data."
        )
    cursor.execute(
        """
        UPDATE data_source
        SET last_retrieved_ts = %s
        WHERE source = ANY(%s)
        """,
        (last_retrieved_ts, ordered_sources),
    )


def import_spoofing(
    rows,
    *,
    modules: list[str] | str = "spoofing,asn,country",
    source: str = DEFAULT_SOURCE,
    force: bool = False,
    dry_run: bool = False,
) -> dict[str, int]:
    from data_gathering.config.db_connection import close_db_connection, connect_to_db

    modules = parse_modules(modules)
    import_ts = _current_import_ts()
    frame = _prepare_rows(rows, source=source, last_update_ts=import_ts)
    report = {
        "spoofing_rows": _row_count(frame),
        "affected_spoofing": 0,
        "affected_spoofing_asn": 0,
        "affected_spoofing_country": 0,
    }
    if frame.is_empty():
        logger.info("No spoofing rows to import")
        return report

    cursor = connect_to_db()
    connection = cursor.connection
    try:
        _touch_data_sources(cursor, set(frame["source"].drop_nulls().unique().to_list()), import_ts)
        cursor.execute(
            """
            CREATE TEMP TABLE spoofing_stage (
                prefix CIDR NOT NULL,
                nat BOOLEAN,
                privatespoof TEXT,
                routedspoof TEXT,
                asn BIGINT,
                country TEXT,
                last_update_ts TIMESTAMPTZ NOT NULL,
                source TEXT NOT NULL
            ) ON COMMIT DROP
            """
        )
        with cursor.copy(
            """
            COPY spoofing_stage (
                prefix, nat, privatespoof, routedspoof, asn, country, last_update_ts, source
            ) FROM STDIN
            """
        ) as copy:
            for row in frame.iter_rows():
                copy.write_row(row)

        cursor.execute(
            """
            CREATE TEMP TABLE spoofing_eligible AS
            SELECT s.*
            FROM spoofing_stage s
            LEFT JOIN spoofing t ON t.prefix = s.prefix
            WHERE t.prefix IS NULL
               OR %s
               OR s.last_update_ts > t.last_update_ts
            """,
            (force,),
        )

        if "spoofing" in modules:
            cursor.execute(
                """
                INSERT INTO spoofing (prefix, nat, privatespoof, routedspoof, last_update_ts, source)
                SELECT prefix, nat, privatespoof, routedspoof, last_update_ts, source
                FROM spoofing_stage
                ON CONFLICT (prefix)
                DO UPDATE SET
                    nat = EXCLUDED.nat,
                    privatespoof = EXCLUDED.privatespoof,
                    routedspoof = EXCLUDED.routedspoof,
                    last_update_ts = EXCLUDED.last_update_ts,
                    source = EXCLUDED.source
                WHERE %s OR EXCLUDED.last_update_ts > spoofing.last_update_ts
                """,
                (force,),
            )
            report["affected_spoofing"] = cursor.rowcount

        if "asn" in modules:
            cursor.execute(
                """
                INSERT INTO spoofing_asn (prefix, asn)
                SELECT prefix, asn
                FROM spoofing_eligible
                WHERE asn IS NOT NULL
                ON CONFLICT (prefix)
                DO UPDATE SET asn = EXCLUDED.asn
                WHERE %s OR spoofing_asn.asn IS DISTINCT FROM EXCLUDED.asn
                """,
                (force,),
            )
            report["affected_spoofing_asn"] = cursor.rowcount

        if "country" in modules:
            cursor.execute("SELECT DISTINCT country FROM spoofing_eligible WHERE country IS NOT NULL")
            ensure_country_locations(cursor.connection, {row[0] for row in cursor.fetchall()}, logger)
            cursor.execute(
                """
                INSERT INTO spoofing_country (prefix, country)
                SELECT prefix, country
                FROM spoofing_eligible
                WHERE country IS NOT NULL
                ON CONFLICT (prefix)
                DO UPDATE SET country = EXCLUDED.country
                WHERE %s OR spoofing_country.country IS DISTINCT FROM EXCLUDED.country
                """,
                (force,),
            )
            report["affected_spoofing_country"] = cursor.rowcount

        if dry_run:
            connection.rollback()
        else:
            connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        close_db_connection(cursor)

    logger.info("Applied spoofing import: {}", report)
    return report
