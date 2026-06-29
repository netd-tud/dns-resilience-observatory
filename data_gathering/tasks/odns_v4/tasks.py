"""ODNS data-gathering task implementation."""

from __future__ import annotations

from pathlib import Path

from data_gathering.celery_app import app
from data_gathering.external_sources.config import external_data_dir
from data_gathering.external_sources.manycast.fetcher import fetch as fetch_manycast
from data_gathering.external_sources.odns_api.fetcher import fetch as fetch_odns_api
from data_gathering.tasks.odns_v4.script_config import required_config_value, script_logger


logger = script_logger(__file__)

TASK_NAMES = ["data_gathering.tasks.odns.refresh"]


def _odns_data_dir() -> Path:
    return external_data_dir()


def _protocols() -> list[str]:
    configured = required_config_value(__file__, "odns_protocols")
    return [protocol.strip() for protocol in configured.split(",") if protocol.strip()]


def _fetch_odns() -> Path:
    logger.info("Open DNS: fetching API data")
    parquet_path = fetch_odns_api(output_dir=_odns_data_dir())
    logger.info("Open DNS: fetch complete: {}", parquet_path)
    return parquet_path


def _fetch_manycast(protocol: str) -> Path:
    """
    Fetch Manycast anycast deployment data from their API.
    Currently we only fetch IPv4 data, this will be extended to IPv6 in the future.
    """
    if protocol != "v4":
        raise ValueError(f"Manycast fetch currently supports v4 only, got {protocol}")
    logger.info("Manycast {}: fetching anycast data", protocol)
    parquet_path = fetch_manycast(output_dir=_odns_data_dir())
    logger.info("Manycast {}: fetch complete: {}", protocol, parquet_path)
    return parquet_path


def _load_odns(protocol: str) -> None:
    """
    Load ODNS data from parquet files into the database.
    The script fetches public resolvers (including anycast deployments) as well as closed resolvers (derived from rec./transp. forwarders).
    """
    from data_gathering.tasks.odns_v4.load_odns_api import load_odns_api

    data_dir = _odns_data_dir()
    logger.info("ODNS {}: loading parquet data from {}", protocol, data_dir)
    load_odns_api(protocol=protocol, data_dir=data_dir)
    logger.info("ODNS {}: load complete", protocol)


@app.task(name="data_gathering.tasks.odns.refresh")
def refresh() -> dict[str, int]:
    protocols = _protocols()
    logger.info("Refreshing ODNS data for protocols: {protocols}", protocols=protocols)

    refreshed = 0
    for protocol in protocols:
        logger.info("ODNS {}: refresh started", protocol)
        _fetch_odns()
        _fetch_manycast(protocol)
        _load_odns(protocol)
        refreshed += 1
        logger.info("ODNS {}: refresh finished ({}/{})", protocol, refreshed, len(protocols))

    logger.info("ODNS refresh finished for {} protocol(s)", refreshed)
    return {"protocols": refreshed}
