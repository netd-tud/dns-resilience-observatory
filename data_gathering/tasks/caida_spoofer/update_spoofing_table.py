"""Fetch and normalize CAIDA Spoofer data for spoofing table updates."""

from __future__ import annotations

from pathlib import Path

import polars as pl

from data_gathering.external_sources.caida.spoofer.fetcher import fetch as fetch_caida_spoofer
from data_gathering.imports.spoofing.import_spoofing import import_spoofing
from data_gathering.tasks.caida_spoofer.script_config import (
    required_config_int,
    required_config_value,
    script_logger,
)


logger = script_logger(__file__)


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _configured_data_dir() -> Path:
    configured = Path(required_config_value(__file__, "data_dir")).expanduser()
    if configured.is_absolute():
        return configured
    return _repository_root() / configured


def _normalize_spoofing_frame(path: Path) -> pl.DataFrame:
    if path.stat().st_size == 0:
        return pl.DataFrame(
            {
                "prefix": [],
                "asn": [],
                "country": [],
                "nat": [],
                "privatespoof": [],
                "routedspoof": [],
                "last_update_ts": [],
                "source": [],
            },
            schema={
                "prefix": pl.Utf8,
                "asn": pl.Int64,
                "country": pl.Utf8,
                "nat": pl.Boolean,
                "privatespoof": pl.Utf8,
                "routedspoof": pl.Utf8,
                "last_update_ts": pl.Datetime(time_zone="UTC"),
                "source": pl.Utf8,
            },
        )
    frame = pl.read_ndjson(path)
    country = pl.col("country").cast(pl.Utf8).str.to_uppercase()
    last_update_ts = (
        pl.col("timestamp")
        .str.to_datetime(format="%Y-%m-%dT%H:%M:%S%z", time_zone="UTC", strict=False)
        .alias("last_update_ts")
    )
    source = pl.lit("caida-spoofer").alias("source")
    ipv4_rows = frame.select(
        pl.col("client4").alias("prefix"),
        pl.col("asn4").cast(pl.Int64, strict=False).alias("asn"),
        country.alias("country"),
        pl.col("nat4").alias("nat"),
        pl.col("privatespoof").alias("privatespoof"),
        pl.col("routedspoof").alias("routedspoof"),
        last_update_ts,
        source,
    )
    ipv6_rows = frame.select(
        pl.col("client6").alias("prefix"),
        pl.col("asn6").cast(pl.Int64, strict=False).alias("asn"),
        country.alias("country"),
        pl.col("nat6").alias("nat"),
        pl.col("privatespoof6").alias("privatespoof"),
        pl.col("routedspoof6").alias("routedspoof"),
        last_update_ts,
        source,
    )
    return (
        pl.concat([ipv4_rows, ipv6_rows], how="vertical")
        .filter(pl.col("prefix").is_not_null())
        .sort("prefix")
    )


def update_spoofing_table(fetch_last_days: int | None = None) -> pl.DataFrame:
    fetch_last_days = (
        fetch_last_days
        if fetch_last_days is not None
        else required_config_int(__file__, "caida_fetch_last_days")
    )
    data_dir = _configured_data_dir()
    logger.info("Fetching CAIDA Spoofer data for the past {} day(s)", fetch_last_days)
    caida_path, row_count = fetch_caida_spoofer(output_dir=data_dir, fetch_last_days=fetch_last_days)
    logger.info("Fetched {} CAIDA Spoofer rows into {}", row_count, caida_path)
    frame = (
        _normalize_spoofing_frame(caida_path)
        .filter((pl.col("routedspoof").is_not_null()) | (pl.col("privatespoof").is_not_null()))
        .sort("last_update_ts", descending=True)
        .unique("prefix", keep="first")
    )
    import_spoofing(frame, modules="spoofing,asn,country", source="caida-spoofer", dry_run=False)
    return frame


if __name__ == "__main__":
    update_spoofing_table()
