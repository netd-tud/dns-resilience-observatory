"""Fetch and upsert current APNIC resolver usage observations."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, date, datetime
from typing import Any

import psycopg
import pycountry
from psycopg.types.json import Jsonb

from data_gathering.external_sources.http_json import JsonFetchError, JsonHttpClient
from data_gathering.tasks.resolver_usage_apnic.script_config import (
    required_config_float,
    required_config_int,
    required_config_value,
    script_logger,
)
from db.apply_schema import build_dsn


logger = script_logger(__file__)

SOURCE = "apnic-resolver-usage"
RESOLVER_TYPE_NAMES = [
    "allopnrvrs",
    "sameas",
    "samecc",
    "diffcc",
    "cloudflare",
    "cnnic",
    "dnspai",
    "dnspod",
    "dnswatch",
    "dyn",
    "freedns",
    "googlepdns",
    "greenteamdns",
    "he",
    "level3",
    "neustar",
    "onedns",
    "opendns",
    "opennic",
    "quad9",
    "uncensoreddns",
    "vrsgn",
    "yandex",
    "comodo",
    "safedns",
    "freenom",
    "cleanbrowsing",
    "alternatedns",
    "puntcat",
    "alidns",
    "baidu",
    "114dns",
    "quad101",
    "xopnrvrs",
    "incc",
    "outcc",
    "inccx",
    "outccx",
    "diffcceu",
    "diffccneu",
    "adguard",
    "canadian_shield",
    "skydns",
    "cznic",
    "dns4eu",
]
# APNIC currently exposes Kosovo as an economy code although it is not present
# in the ISO list bundled by pycountry.
EXTRA_ECONOMY_CODES = ("XK",)
DISPLAYED_METRICS = (
    "sameas",
    "samecc",
    "googlepdns",
    "cloudflare",
    "diffcc",
    "onedns",
    "dnspai",
    "opendns",
    "quad9",
    "114dns",
)


def _country_codes() -> list[str]:
    country_codes = {str(country.alpha_2) for country in pycountry.countries}
    country_codes.update(EXTRA_ECONOMY_CODES)
    return ["XA", *sorted(country_codes)]


def _latest_record(payload: dict[str, Any], country_code: str, measurement_type: str) -> dict[str, Any]:
    data = payload.get("data")
    if not isinstance(data, list):
        raise ValueError("APNIC response has no data list")
    matching = [
        record
        for record in data
        if isinstance(record, dict)
        and str(record.get("rv_cc", "")).upper() == country_code
        and str(record.get("rv_type", "")) == measurement_type
    ]
    if not matching:
        raise ValueError(f"APNIC returned no {measurement_type} data for {country_code}")
    return max(matching, key=lambda record: str(record.get("rv_dt", "")))


def _parse_record(record: dict[str, Any], country_code: str) -> dict[str, Any]:
    observation_date = date.fromisoformat(str(record["rv_dt"]))
    sample_count = int(record["rv_seen"])
    weighted_sample_count = float(record.get("rv_seen_w") or 0)
    vector = record.get("rv_rtyp_seen")
    if sample_count <= 0:
        raise ValueError(f"APNIC sample count is not positive for {country_code}")
    if not isinstance(vector, list):
        raise ValueError(f"APNIC resolver vector is missing for {country_code}")

    resolver_counts: dict[str, int] = {}
    resolver_percentages: dict[str, float] = {}
    for index, value in enumerate(vector):
        metric = (
            RESOLVER_TYPE_NAMES[index]
            if index < len(RESOLVER_TYPE_NAMES)
            else f"resolver_type_{index}"
        )
        count = int(value)
        resolver_counts[metric] = count
        resolver_percentages[metric] = round((count / sample_count) * 100.0, 6)

    missing = [metric for metric in DISPLAYED_METRICS if metric not in resolver_percentages]
    if missing:
        raise ValueError(f"APNIC resolver vector is missing metrics: {', '.join(missing)}")

    displayed_percentages = {
        f"{metric}_pc": resolver_percentages[metric]
        for metric in DISPLAYED_METRICS
        if metric != "114dns"
    }
    return {
        "country_code": country_code,
        "observation_date": observation_date,
        "measurement_type": str(record["rv_type"]),
        "sample_count": sample_count,
        "weighted_sample_count": weighted_sample_count,
        "resolver_counts": resolver_counts,
        "resolver_percentages": resolver_percentages,
        "raw_record": record,
        **displayed_percentages,
        "dns_114_pc": resolver_percentages["114dns"],
    }


def _upsert(rows: list[dict[str, Any]], fetched_at: datetime, batch_size: int) -> int:
    statement = """
        INSERT INTO resolver_usage_apnic (
            country_code, observation_date, measurement_type, sample_count,
            weighted_sample_count, resolver_counts, resolver_percentages, raw_record,
            sameas_pc, samecc_pc, googlepdns_pc, cloudflare_pc, diffcc_pc,
            onedns_pc, dnspai_pc, opendns_pc, quad9_pc, dns_114_pc,
            last_update_ts, source
        ) VALUES (
            %(country_code)s, %(observation_date)s, %(measurement_type)s, %(sample_count)s,
            %(weighted_sample_count)s, %(resolver_counts)s, %(resolver_percentages)s,
            %(raw_record)s, %(sameas_pc)s, %(samecc_pc)s, %(googlepdns_pc)s,
            %(cloudflare_pc)s, %(diffcc_pc)s, %(onedns_pc)s, %(dnspai_pc)s,
            %(opendns_pc)s, %(quad9_pc)s, %(dns_114_pc)s, %(last_update_ts)s, %(source)s
        )
        ON CONFLICT (country_code) DO UPDATE SET
            observation_date = EXCLUDED.observation_date,
            measurement_type = EXCLUDED.measurement_type,
            sample_count = EXCLUDED.sample_count,
            weighted_sample_count = EXCLUDED.weighted_sample_count,
            resolver_counts = EXCLUDED.resolver_counts,
            resolver_percentages = EXCLUDED.resolver_percentages,
            raw_record = EXCLUDED.raw_record,
            sameas_pc = EXCLUDED.sameas_pc,
            samecc_pc = EXCLUDED.samecc_pc,
            googlepdns_pc = EXCLUDED.googlepdns_pc,
            cloudflare_pc = EXCLUDED.cloudflare_pc,
            diffcc_pc = EXCLUDED.diffcc_pc,
            onedns_pc = EXCLUDED.onedns_pc,
            dnspai_pc = EXCLUDED.dnspai_pc,
            opendns_pc = EXCLUDED.opendns_pc,
            quad9_pc = EXCLUDED.quad9_pc,
            dns_114_pc = EXCLUDED.dns_114_pc,
            last_update_ts = EXCLUDED.last_update_ts,
            source = EXCLUDED.source
        WHERE EXCLUDED.observation_date >= resolver_usage_apnic.observation_date
    """
    upserted = 0
    with psycopg.connect(build_dsn()) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO data_source (
                    source, url, api_endpoint, documentation_endpoint,
                    description, apikey_required, last_retrieved_ts
                ) VALUES (%s, %s, %s, %s, %s, FALSE, %s)
                ON CONFLICT (source) DO UPDATE SET last_retrieved_ts = EXCLUDED.last_retrieved_ts
                """,
                (
                    SOURCE,
                    "https://stats.labs.apnic.net/rvrs",
                    "https://stats.labs.apnic.net/rvrs/XA?hc=XA&hs=0&hf=1",
                    "https://labs.apnic.net/rvr-data-format.html",
                    "APNIC Labs country and world recursive DNS resolver usage measurements.",
                    fetched_at,
                ),
            )
            for offset in range(0, len(rows), batch_size):
                parameters = []
                for row in rows[offset : offset + batch_size]:
                    parameters.append(
                        {
                            **row,
                            "resolver_counts": Jsonb(row["resolver_counts"]),
                            "resolver_percentages": Jsonb(row["resolver_percentages"]),
                            "raw_record": Jsonb(row["raw_record"]),
                            "last_update_ts": fetched_at,
                            "source": SOURCE,
                        }
                    )
                cursor.executemany(statement, parameters)
                upserted += cursor.rowcount
    return upserted


def update_resolver_usage() -> dict[str, Any]:
    url_template = required_config_value(__file__, "json_url_template")
    measurement_type = required_config_value(__file__, "measurement_type")
    workers = required_config_int(__file__, "request_workers")
    batch_size = required_config_int(__file__, "upsert_batch_size")
    if workers <= 0 or batch_size <= 0:
        raise ValueError("request_workers and upsert_batch_size must be greater than zero")

    client = JsonHttpClient(
        timeout_seconds=required_config_float(__file__, "request_timeout_seconds"),
        requests_per_second=required_config_float(__file__, "requests_per_second"),
        retries=required_config_int(__file__, "request_retries"),
        backoff_seconds=required_config_float(__file__, "request_backoff_seconds"),
    )
    country_codes = _country_codes()
    rows: list[dict[str, Any]] = []
    failures: list[str] = []

    def fetch(country_code: str) -> dict[str, Any]:
        payload = client.get(
            url_template.format(country_code=country_code),
            {"hc": country_code, "hs": 0, "hf": 1},
        )
        return _parse_record(
            _latest_record(payload, country_code, measurement_type),
            country_code,
        )

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(fetch, code): code for code in country_codes}
        for completed, future in enumerate(as_completed(futures), start=1):
            country_code = futures[future]
            try:
                rows.append(future.result())
            except (JsonFetchError, KeyError, TypeError, ValueError) as error:
                failures.append(country_code)
                logger.warning("APNIC resolver usage: failed {}: {}", country_code, error)
            if completed % 25 == 0 or completed == len(country_codes):
                logger.info(
                    "APNIC resolver usage: processed {}/{} targets",
                    completed,
                    len(country_codes),
                )

    if not rows:
        raise RuntimeError("APNIC resolver usage refresh failed for every target")
    fetched_at = datetime.now(UTC)
    upserted = _upsert(rows, fetched_at, batch_size)
    world_row = next((row for row in rows if row["country_code"] == "XA"), None)
    return {
        "targets": len(country_codes),
        "fetched": len(rows),
        "failed": len(failures),
        "failed_country_codes": failures,
        "upserted": upserted,
        "world_observation_date": world_row["observation_date"].isoformat() if world_row else None,
    }


if __name__ == "__main__":
    logger.info("APNIC resolver usage refresh complete: {}", update_resolver_usage())
