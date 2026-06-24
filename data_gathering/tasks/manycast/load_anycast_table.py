"""Load Manycast anycast prefix data into PostgreSQL."""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import import_module
import ipaddress
from pathlib import Path

import polars as pl

from data_gathering.external_sources.config import external_data_dir
from data_gathering.external_sources.manycast.fetcher import fetch as fetch_manycast
from data_gathering.tasks.country_locations import normalize_country
from data_gathering.tasks.manycast.script_config import script_logger


logger = script_logger(__file__)


@dataclass(frozen=True)
class AnycastImportRows:
    anycast_rows: pl.DataFrame = field(default_factory=pl.DataFrame)
    asn_rows: pl.DataFrame = field(default_factory=pl.DataFrame)
    country_backend_rows: pl.DataFrame = field(default_factory=pl.DataFrame)
    asn_backend_rows: pl.DataFrame = field(default_factory=pl.DataFrame)


def _normalize_prefix(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return None


def _parse_bool(value: object | None) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "t", "yes", "y"}


def _manycast_path(data_dir: Path, manycast_path: Path | None) -> Path:
    if manycast_path is not None:
        return manycast_path
    return fetch_manycast(output_dir=data_dir)


def _prepare_rows(manycast_path: Path) -> AnycastImportRows:
    logger.info("Loading Manycast parquet: {}", manycast_path)

    required_columns = ["prefix", "backing_prefix", "partial", "ASN", "locations"]
    frame = pl.read_parquet(manycast_path).select(required_columns)
    normalized_base = frame.with_columns(
        pl.col("prefix").map_elements(_normalize_prefix, return_dtype=pl.Utf8),
        pl.col("backing_prefix").map_elements(_normalize_prefix, return_dtype=pl.Utf8),
        pl.col("partial").map_elements(_parse_bool, return_dtype=pl.Boolean),
    )
    invalid_prefixes = normalized_base.select(pl.col("prefix").is_null().sum()).item()
    normalized_base = normalized_base.filter(pl.col("prefix").is_not_null())
    normalized = (
        normalized_base.with_columns(pl.col("ASN").cast(pl.Utf8).str.split("_"))
        .explode("ASN")
        .with_columns(
            pl.when(pl.col("ASN") == "-")
            .then(None)
            .otherwise(pl.col("ASN"))
            .cast(pl.UInt32, strict=False)
            .alias("ASN")
        )
    )

    if invalid_prefixes:
        logger.warning("Skipped {} Manycast rows with invalid prefix values", invalid_prefixes)

    anycast_rows = (
        normalized_base.group_by("prefix")
        .agg(
            pl.col("backing_prefix").drop_nulls().first(),
            pl.col("partial").any(),
        )
        .sort("prefix")
    )
    asn_rows = (
        normalized.filter(pl.col("ASN").is_not_null())
        .select("prefix", pl.col("ASN").cast(pl.Int64).alias("asn"))
        .unique()
        .sort("prefix", "asn")
    )
    location_frame = (
        normalized_base.select("prefix", "locations")
        .explode("locations")
        .filter(pl.col("locations").is_not_null())
        .unnest("locations")
    )

    country_backend_rows = location_frame.with_columns(
        pl.col("country_code").map_elements(normalize_country, return_dtype=pl.Utf8).alias("country")
    ).filter(pl.col("country").is_not_null()).group_by("prefix", "country").agg(pl.len().alias("country_count"))


    logger.info(
        "Prepared Manycast anycast rows: prefixes={}, prefix/asn pairs={}, prefix/country counts={}",
        anycast_rows.height,
        asn_rows.height,
        country_backend_rows.height,
    )
    return AnycastImportRows(
        anycast_rows=anycast_rows,
        asn_rows=asn_rows,
        country_backend_rows=country_backend_rows,
    )


def _import_rows(rows: AnycastImportRows) -> dict[str, int]:
    importer = import_module("data_gathering.import.anycast.import_anycast")
    return importer.import_anycast(
        anycast_rows=rows.anycast_rows,
        asn_rows=rows.asn_rows,
        country_backend_rows=rows.country_backend_rows,
        asn_backend_rows=rows.asn_backend_rows,
        source="manycast",
    )


def load_anycast_table(
    *,
    data_dir: Path | None = None,
    manycast_path: Path | None = None,
) -> dict[str, int]:
    data_dir = data_dir or external_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    path = _manycast_path(data_dir, manycast_path)
    rows = _prepare_rows(path)
    return _import_rows(rows)


def main() -> None:
    report = load_anycast_table()
    logger.info("Manycast load complete: {}", report)


if __name__ == "__main__":
    main()
