"""Fetch APNIC DNSSEC country validation data into parquet."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import polars as pl
import pycountry

from data_gathering.external_sources.config import external_data_dir
from data_gathering.imports.country.country_locations import normalize_country
from data_gathering.tasks.apnic_dnssec.script_config import required_config_int, required_config_value, script_logger


CONFIG_KEY = "apnic_dnssec_country_fetcher.py"
logger = script_logger(CONFIG_KEY)

DNSSEC_COUNTRY_COLUMNS = [
    "country",
    "number_of_measurements",
    "validating",
    "validating_pc",
    "partial_validating",
    "partial_validating_pc",
    "last_observation_ts",
]
USER_AGENT = "dns-resilience-observatory-dnssec-country-fetcher"
HTTP_TIMEOUT_SECONDS = 30


def _country_codes() -> list[str]:
    return sorted({country.alpha_2 for country in pycountry.countries})


def _fetch_text(url: str) -> str:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        return response.read().decode("utf-8", errors="replace")


def _json_url(json_url: str, country_code: str) -> str:
    return f"{json_url}?{urlencode({'x': country_code})}"


def _parse_measurement_timestamp(value: object | None) -> dt.datetime | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return dt.datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def _metric_value(metric: dict[str, object], key: str) -> object | None:
    value = metric.get(key)
    return value if value != "" else None


def _flatten_json_row(row: dict[str, object], country_code: str) -> dict[str, object]:
    metric = row.get("30_day") if isinstance(row.get("30_day"), dict) else {}
    return {
        "country": normalize_country(row.get("cc") or country_code),
        "number_of_measurements": _metric_value(metric, "seen"),
        "validating": _metric_value(metric, "validating"),
        "validating_pc": _metric_value(metric, "validating_pc"),
        "partial_validating": _metric_value(metric, "partial_validating"),
        "partial_validating_pc": _metric_value(metric, "partial_validating_pc"),
        "last_observation_ts": _parse_measurement_timestamp(row.get("date")),
    }


def fetch_country_json(country_code: str, json_url: str) -> dict[str, object] | None:
    # Download country APNIC time series and keep latest 30-day metrics.
    url = _json_url(json_url, country_code)
    try:
        payload = json.loads(_fetch_text(url))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        logger.warning("DNSSEC country: failed to fetch JSON {}: {}", url, exc)
        return None

    data = payload.get("data", [])
    if not isinstance(data, list):
        logger.warning("DNSSEC country: unexpected JSON data shape for {}", url)
        return None
    rows = [row for row in data if isinstance(row, dict) and row.get("date")]
    if not rows:
        return None
    latest = max(rows, key=lambda row: str(row.get("date")))
    flattened = _flatten_json_row(latest, country_code)
    if flattened["country"] is None or flattened["last_observation_ts"] is None:
        logger.warning("DNSSEC country: skipping {} without country/date", country_code)
        return None
    return flattened


def fetch(*, output_dir: Path | None = None) -> tuple[Path, int]:
    output_dir = output_dir or external_data_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    json_url = required_config_value(CONFIG_KEY, "apnic_dnssec_json_url")
    country_workers = required_config_int(CONFIG_KEY, "apnic_dnssec_country_workers")

    rows: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=country_workers) as executor:
        futures = {
            executor.submit(fetch_country_json, country_code, json_url): country_code
            for country_code in _country_codes()
        }
        for future in as_completed(futures):
            row = future.result()
            if row is not None:
                rows.append(row)

    logger.info("DNSSEC country: fetched {} country rows", len(rows))
    if not rows:
        raise RuntimeError("DNSSEC country: no APNIC DNSSEC rows fetched")

    today = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    output_path = output_dir / f"apnic-dnssec-public-country-{today}.pq"
    tmp_path = output_path.with_suffix(".tmp")
    pl.DataFrame(rows).select(DNSSEC_COUNTRY_COLUMNS).write_parquet(tmp_path)
    tmp_path.replace(output_path)
    logger.info("DNSSEC country: wrote {} rows to {}", len(rows), output_path)
    return output_path, len(rows)


def load_dnssec_public_country(parquet_path: Path) -> int:
    from data_gathering.imports.dnssec.import_dnssec import import_dnssec

    rows = pl.read_parquet(parquet_path).select(DNSSEC_COUNTRY_COLUMNS)
    import_dnssec(country_rows=rows, modules="country", dry_run=False)
    return len(rows)


load_dnssec_country_public = load_dnssec_public_country
