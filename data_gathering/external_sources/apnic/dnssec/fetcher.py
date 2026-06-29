"""Fetch latest APNIC DNSSEC data into the shared external-data directory."""

from __future__ import annotations

from pathlib import Path

from data_gathering.external_sources.config import external_data_dir
from data_gathering.external_sources.apnic.dnssec.country.fetcher import fetch as fetch_country


def fetch(*, output_dir: Path | None = None, include_asn: bool = True) -> dict[str, int | str]:
    target_dir = output_dir or external_data_dir()
    result: dict[str, int | str] = {}

    if include_asn:
        from data_gathering.external_sources.apnic.dnssec.asn.fetcher import fetch as fetch_asn

        asn_path, asn_rows = fetch_asn(output_dir=target_dir)
        result["asn_rows"] = asn_rows
        result["asn_parquet"] = str(asn_path)
    else:
        result["asn_rows"] = 0
        result["asn_parquet"] = ""

    country_path, country_rows = fetch_country(output_dir=target_dir)
    result["country_rows"] = country_rows
    result["country_parquet"] = str(country_path)
    return result
