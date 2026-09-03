"""Refresh current MANRS readiness for resolver-linked ASNs and countries."""

from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, TypeVar, cast

import psycopg
import pycountry

from data_gathering.external_sources.http_json import JsonFetchError, JsonHttpClient
from data_gathering.external_sources.manrs.fetcher import EntityType, fetch_summary
from data_gathering.imports.manrs import import_manrs
from data_gathering.tasks.manrs.script_config import (
    required_config_float,
    required_config_int,
    required_config_value,
    script_logger,
)
from db.apply_schema import build_dsn


logger = script_logger(__file__)

SOURCE = "manrs-observatory"
METRIC_NAMES = {
    "antiSpoofing": "anti_spoofing",
    "coordination": "coordination",
    "filtering": "filtering",
    "routingInformationIRR": "routing_information_irr",
    "routingInformationRPKI": "routing_information_rpki",
}
READINESS_ALIASES = {
    "ready": "ready",
    "ok": "ready",
    "aspiring": "aspiring",
    "warn": "aspiring",
    "lagging": "lagging",
    "fail": "lagging",
    "no_data_available": "no_data_available",
}

T = TypeVar("T")
RefreshScope = Literal["asn", "country", "both"]


@dataclass(frozen=True, slots=True)
class CountryTarget:
    database_code: str
    api_code: str


def _chunks(values: list[T], size: int) -> Iterator[list[T]]:
    for offset in range(0, len(values), size):
        yield values[offset : offset + size]


def _normalize_fraction(value: object, *, field: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"MANRS {field} is not numeric: {value!r}")
    normalized = float(value)
    if 0 <= normalized <= 1:
        return normalized
    if 0 <= normalized <= 100:
        return normalized / 100
    raise ValueError(f"MANRS {field} is outside the supported 0..1/0..100 range: {value!r}")


def _normalize_trend(value: object, *, field: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"MANRS {field} is not numeric: {value!r}")
    return float(value)


def _key_figures(scores: dict[str, Any]) -> dict[str, dict[str, Any]]:
    figures = scores.get("keyFigures")
    if not isinstance(figures, list):
        raise ValueError("MANRS response has no keyFigures list")
    by_id = {
        str(figure.get("id")): figure
        for figure in figures
        if isinstance(figure, dict) and figure.get("id") is not None
    }
    missing = [identifier for identifier in METRIC_NAMES if identifier not in by_id]
    if missing:
        raise ValueError(f"MANRS response is missing readiness metrics: {', '.join(missing)}")
    return by_id


def _severities(figure: dict[str, Any]) -> list[dict[str, Any]]:
    values = figure.get("severities")
    if not isinstance(values, list):
        raise ValueError(f"MANRS metric {figure.get('id')} has no severity list")
    return [value for value in values if isinstance(value, dict)]


def _asn_readiness(figure: dict[str, Any]) -> str:
    populated = []
    for severity in _severities(figure):
        count = severity.get("count")
        if isinstance(count, (int, float)) and not isinstance(count, bool) and count > 0:
            populated.append(str(severity.get("id", "")))
    if len(populated) != 1 or populated[0] not in READINESS_ALIASES:
        raise ValueError(
            f"MANRS metric {figure.get('id')} has an unexpected single-ASN severity distribution"
        )
    return READINESS_ALIASES[populated[0]]


def _country_ready_share(figure: dict[str, Any]) -> float:
    for severity in _severities(figure):
        if str(severity.get("id", "")) in {"ready", "ok"}:
            value = _normalize_fraction(
                severity.get("percentage"),
                field=f"{figure.get('id')}.ready.percentage",
            )
            return 0.0 if value is None else value
    return 0.0


def _parse_summary(
    *,
    entity_type: EntityType,
    entity: int | str,
    scores: dict[str, Any],
    observed_at: datetime,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "asn" if entity_type == "asn" else "country": entity,
        "last_update_ts": observed_at,
    }
    figures = _key_figures(scores)
    for api_name, column_name in METRIC_NAMES.items():
        figure = figures[api_name]
        row[f"{column_name}_score"] = _normalize_fraction(
            figure.get("value"), field=f"{api_name}.value"
        )
        row[f"{column_name}_trend"] = _normalize_trend(
            figure.get("trend"), field=f"{api_name}.trend"
        )
        if entity_type == "asn":
            row[f"{column_name}_readiness"] = _asn_readiness(figure)
        else:
            row[f"{column_name}_ready_share"] = _country_ready_share(figure)
    return row


def normalize_scope(scope: str) -> RefreshScope:
    normalized = scope.strip().lower()
    if normalized not in {"asn", "country", "both"}:
        raise ValueError("MANRS refresh scope must be one of: asn, country, both")
    return cast(RefreshScope, normalized)


def _load_targets(scope: RefreshScope) -> tuple[list[int], list[CountryTarget], int]:
    asns: list[int] = []
    countries: list[CountryTarget] = []
    skipped_countries = 0
    with psycopg.connect(build_dsn()) as connection:
        with connection.cursor() as cursor:
            if scope in {"asn", "both"}:
                cursor.execute(
                    """
                    SELECT DISTINCT asn::BIGINT
                    FROM resolver_asn
                    WHERE asn > 0
                    ORDER BY asn::BIGINT
                    """
                )
                asns = [int(row[0]) for row in cursor.fetchall()]

            if scope in {"country", "both"}:
                cursor.execute(
                    """
                    SELECT DISTINCT UPPER(country)
                    FROM resolver_location
                    WHERE country ~ '^[A-Za-z]{3}$'
                    ORDER BY UPPER(country)
                    """
                )
                for row in cursor.fetchall():
                    database_code = str(row[0])
                    country = pycountry.countries.get(alpha_3=database_code)
                    if country is None:
                        skipped_countries += 1
                        logger.warning(
                            "MANRS: skipping country code {} because it has no ISO alpha-2 mapping",
                            database_code,
                        )
                        continue
                    countries.append(
                        CountryTarget(
                            database_code=database_code,
                            api_code=str(country.alpha_2),
                        )
                    )
    return asns, countries, skipped_countries


def _fetch_chunk(
    *,
    client: JsonHttpClient,
    url: str,
    entity_type: EntityType,
    entities: list[int] | list[CountryTarget],
    month: str,
    workers: int,
) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    failures = 0

    def fetch(entity: int | CountryTarget) -> dict[str, Any]:
        api_entity = entity.api_code if isinstance(entity, CountryTarget) else entity
        database_entity = entity.database_code if isinstance(entity, CountryTarget) else entity
        scores = fetch_summary(
            client,
            url=url,
            entity_type=entity_type,
            entity=api_entity,
            month=month,
        )
        return _parse_summary(
            entity_type=entity_type,
            entity=database_entity,
            scores=scores,
            observed_at=datetime.now(UTC),
        )

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(fetch, entity): entity for entity in entities}
        for future in as_completed(futures):
            entity = futures[future]
            try:
                rows.append(future.result())
            except (JsonFetchError, ValueError, TypeError) as exc:
                failures += 1
                label = (
                    f"{entity.database_code}/{entity.api_code}"
                    if isinstance(entity, CountryTarget)
                    else str(entity)
                )
                logger.warning("MANRS: failed to refresh {} {}: {}", entity_type, label, exc)
    return rows, failures


def update_manrs_tables(scope: str = "both") -> dict[str, int | str]:
    selected_scope = normalize_scope(scope)
    url = required_config_value(__file__, "manrs_summary_url")
    api_key = required_config_value(__file__, "manrs_api_key")
    if api_key == "<MANRS_API_KEY>":
        raise ValueError(
            "Replace <MANRS_API_KEY> in data_gathering/tasks/manrs/manrs.conf with a MANRS API key"
        )
    timeout = required_config_float(__file__, "request_timeout_seconds")
    workers = required_config_int(__file__, "request_workers")
    requests_per_second = required_config_float(__file__, "requests_per_second")
    retries = required_config_int(__file__, "request_retries")
    backoff = required_config_float(__file__, "request_backoff_seconds")
    batch_size = required_config_int(__file__, "upsert_batch_size")
    if workers <= 0 or batch_size <= 0:
        raise ValueError("request_workers and upsert_batch_size must be greater than zero")

    now = datetime.now(UTC)
    month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat().replace("+00:00", "Z")
    asns, countries, skipped_countries = _load_targets(selected_scope)
    target_count = len(asns) + len(countries)
    if target_count == 0:
        logger.info("MANRS: no resolver-linked targets for scope {}", selected_scope)
        return {
            "scope": selected_scope,
            "targets": 0,
            "fetched": 0,
            "upserted_asns": 0,
            "upserted_countries": 0,
            "skipped": skipped_countries,
            "failed": 0,
            "month": month[:7],
        }

    client = JsonHttpClient(
        timeout_seconds=timeout,
        requests_per_second=requests_per_second,
        retries=retries,
        backoff_seconds=backoff,
        default_headers={"Authorization": f"Bearer {api_key}"},
    )
    totals = {
        "fetched": 0,
        "upserted_asns": 0,
        "upserted_countries": 0,
        "failed": 0,
    }
    for entity_type, entities in (("asn", asns), ("country", countries)):
        entity_processed = 0
        entity_target_count = len(entities)
        for chunk in _chunks(entities, batch_size):
            rows, failures = _fetch_chunk(
                client=client,
                url=url,
                entity_type=entity_type,
                entities=chunk,
                month=month,
                workers=workers,
            )
            report = import_manrs(
                asn_rows=rows if entity_type == "asn" else (),
                country_rows=rows if entity_type == "country" else (),
                source=SOURCE,
            )
            totals["fetched"] += len(rows)
            totals["failed"] += failures
            totals["upserted_asns"] += report["upserted_asns"]
            totals["upserted_countries"] += report["upserted_countries"]
            entity_processed += len(rows) + failures
            logger.info(
                "MANRS: processed {} {}/{} targets",
                entity_type,
                entity_processed,
                entity_target_count,
            )

    if target_count and totals["fetched"] == 0:
        raise RuntimeError("MANRS refresh failed for every target")
    return {
        "scope": selected_scope,
        "targets": target_count,
        "month": month[:7],
        "skipped": skipped_countries,
        **totals,
    }


if __name__ == "__main__":
    update_manrs_tables()
