"""Fetch APNIC DNSSEC country data and import DNSSEC tables."""

from __future__ import annotations

from pathlib import Path

import polars as pl

from data_gathering.external_sources.apnic.dnssec.country.fetcher import fetch as fetch_country
from data_gathering.imports.dnssec.import_dnssec import DEFAULT_SOURCE, import_dnssec
from data_gathering.tasks.apnic_dnssec.script_config import required_config_value, script_logger


logger = script_logger(__file__)


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _configured_data_dir() -> Path:
    configured = Path(required_config_value(__file__, "data_dir")).expanduser()
    if configured.is_absolute():
        return configured
    return _repository_root() / configured


def update_dnssec_table(data_dir: Path | None = None) -> dict[str, int | str]:
    data_dir = data_dir or _configured_data_dir()
    logger.info("Fetching APNIC DNSSEC country data into {}", data_dir)
    country_path, fetched_country_rows = fetch_country(output_dir=data_dir)
    country_rows = pl.read_parquet(country_path)
    report = import_dnssec(
        country_rows=country_rows,
        modules="country",
        source=DEFAULT_SOURCE,
        dry_run=False,
    )
    return {
        "country_rows": fetched_country_rows,
        "country_parquet": str(country_path),
        **report,
    }


if __name__ == "__main__":
    update_dnssec_table()
