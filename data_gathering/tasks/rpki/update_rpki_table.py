"""Refresh current RIPEstat RPKI status for resolver prefix/ASN pairs."""

from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from typing import Any

import psycopg

from data_gathering.external_sources.http_json import JsonFetchError, JsonHttpClient
from data_gathering.external_sources.ripe_stat.rpki_fetcher import fetch_rpki_status
from data_gathering.imports.rpki import import_rpki
from data_gathering.tasks.rpki.script_config import (
    required_config_float,
    required_config_int,
    required_config_value,
    script_logger,
)
from db.apply_schema import build_dsn


logger = script_logger(__file__)

SOURCE = "ripe-stat-rpki"


def _target_count() -> int:
    with psycopg.connect(build_dsn()) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM (
                    SELECT DISTINCT rp.prefix, ra.asn
                    FROM resolver_prefix rp
                    JOIN resolver_asn ra ON ra.resolver_id = rp.resolver_id
                    WHERE ra.asn > 0
                ) AS targets
                """
            )
            return int(cursor.fetchone()[0])


def _target_batches(batch_size: int) -> Iterator[list[tuple[str, int]]]:
    with psycopg.connect(build_dsn()) as connection:
        with connection.cursor(name="rpki_resolver_targets") as cursor:
            cursor.execute(
                """
                SELECT DISTINCT rp.prefix::TEXT, ra.asn::BIGINT
                FROM resolver_prefix rp
                JOIN resolver_asn ra ON ra.resolver_id = rp.resolver_id
                WHERE ra.asn > 0
                ORDER BY rp.prefix::TEXT, ra.asn::BIGINT
                """
            )
            while rows := cursor.fetchmany(batch_size):
                yield [(str(prefix), int(asn)) for prefix, asn in rows]


def _fetch_batch(
    *,
    client: JsonHttpClient,
    url: str,
    targets: list[tuple[str, int]],
    workers: int,
) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    failures = 0

    def fetch(target: tuple[str, int]) -> dict[str, Any]:
        prefix, asn = target
        status = fetch_rpki_status(client, url=url, prefix=prefix, asn=asn)
        return {
            "prefix": prefix,
            "asn": asn,
            "rpki_status": status,
            "last_update_ts": datetime.now(UTC),
        }

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(fetch, target): target for target in targets}
        for future in as_completed(futures):
            prefix, asn = futures[future]
            try:
                rows.append(future.result())
            except (JsonFetchError, ValueError, TypeError) as exc:
                failures += 1
                logger.warning("RIPEstat RPKI: failed to refresh {} AS{}: {}", prefix, asn, exc)
    return rows, failures


def update_rpki_table() -> dict[str, int]:
    url = required_config_value(__file__, "ripe_stat_rpki_url")
    timeout = required_config_float(__file__, "request_timeout_seconds")
    workers = required_config_int(__file__, "request_workers")
    requests_per_second = required_config_float(__file__, "requests_per_second")
    retries = required_config_int(__file__, "request_retries")
    backoff = required_config_float(__file__, "request_backoff_seconds")
    batch_size = required_config_int(__file__, "upsert_batch_size")
    if workers <= 0 or batch_size <= 0:
        raise ValueError("request_workers and upsert_batch_size must be greater than zero")

    target_count = _target_count()
    if target_count == 0:
        logger.info("RIPEstat RPKI: no resolver prefix/ASN targets")
        return {"targets": 0, "fetched": 0, "upserted": 0, "skipped": 0, "failed": 0}

    client = JsonHttpClient(
        timeout_seconds=timeout,
        requests_per_second=requests_per_second,
        retries=retries,
        backoff_seconds=backoff,
    )
    fetched = 0
    upserted = 0
    failed = 0
    for targets in _target_batches(batch_size):
        rows, batch_failures = _fetch_batch(
            client=client,
            url=url,
            targets=targets,
            workers=workers,
        )
        fetched += len(rows)
        failed += batch_failures
        upserted += import_rpki(rows, source=SOURCE)
        logger.info(
            "RIPEstat RPKI: processed {}/{} targets",
            min(fetched + failed, target_count),
            target_count,
        )

    if fetched == 0:
        raise RuntimeError("RIPEstat RPKI refresh failed for every target")
    return {
        "targets": target_count,
        "fetched": fetched,
        "upserted": upserted,
        "skipped": 0,
        "failed": failed,
    }


if __name__ == "__main__":
    update_rpki_table()
