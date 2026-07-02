import datetime as dt
import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import polars as pl
from tqdm import tqdm

from data_gathering.external_sources.config import external_data_dir, external_interim_dir
from data_gathering.tasks.odns_v4.odns_json_to_parquet import convert_odns_json_to_parquet, normalize_entries
from data_gathering.tasks.odns_v4.script_config import (
    required_config_int,
    required_config_value,
    script_logger,
)


CONFIG_KEY = "fetch_odns_api_data.py"
logger = script_logger(CONFIG_KEY)

ODNS_SPOOFING_FIELDS = [
    "replying_ip",
    "scan_date",
    "resolver_type",
    "queried_ip",
    "queried_ip_country",
    "queried_ip_asn",
    "queried_ip_prefix",
]


def _post_json(payload: dict[str, Any], api_key: str, api_url: str) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    request = Request(
        api_url,
        data=data,
        headers={
            "accept": "application/json",
            "X-API-KEY": api_key,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request) as response:
            body = response.read().decode("utf-8")
    except HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} from API: {error_body}") from exc
    return json.loads(body)


def _normalize_spoofing_frame(entries: list[dict[str, Any]]) -> pl.DataFrame:
    frame = normalize_entries(entries)
    if "scan_date" in frame.columns:
        frame = frame.with_columns(pl.col("scan_date").cast(pl.Utf8, strict=False).str.to_datetime(strict=False, time_zone="UTC"))
    if "queried_ip_asn" in frame.columns:
        frame = frame.with_columns(pl.col("queried_ip_asn").cast(pl.Float64, strict=False).round(0).cast(pl.UInt32, strict=False))
    for column in ["resolver_type", "queried_ip_country", "queried_ip_prefix"]:
        if column in frame.columns:
            frame = frame.with_columns(pl.col(column).cast(pl.Utf8, strict=False))
    return frame


def _fetch_full(
    *,
    api_key: str | None = None,
    out_dir: Path | None = None,
    per_page: int | None = None,
    output_dir: Path | None = None,
) -> Path:
    api_key = api_key if api_key is not None else required_config_value(CONFIG_KEY, "odns_api_auth_token")
    api_url = required_config_value(CONFIG_KEY, "odns_api_url")
    per_page = per_page if per_page is not None else required_config_int(CONFIG_KEY, "odns_per_page")
    output_dir = output_dir or external_data_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    out_dir = out_dir or external_interim_dir(f"odns_{dt.datetime.now().strftime('%Y%m%d')}")
    out_dir.mkdir(parents=True, exist_ok=True)
    logger.info(
        "ODNS API data: starting fetch with per_page={} into {}",
        per_page,
        out_dir,
    )

    page = 1
    total: int | None = None
    downloaded = 0

    progress = tqdm(total=0, desc="Downloading entries", unit="entry")
    try:
        while True:
            payload = {
                "pagination": {"page": page, "per_page": per_page},
                "sort": {"field": "timestamp_request", "order": "desc"},
            }
            response = _post_json(payload, api_key, api_url)
            entries = response.get("dnsEntries", [])
            meta = response.get("metaData", {})
            if total is None:
                total = int(meta.get("total", 0))
                progress.reset(total=total)
                logger.info("ODNS API data: API reports {} entries", total)

            out_json = out_dir / f"odns_page_{page}.json"
            out_json.write_text(json.dumps(response), encoding="utf-8")

            downloaded += len(entries)
            progress.update(len(entries))
            logger.info(
                "ODNS API data: page {} downloaded {} entries ({}/{})",
                page,
                len(entries),
                downloaded,
                total if total is not None else "?",
            )

            if total is not None and downloaded >= total:
                break
            if not entries:
                break
            page += 1
    finally:
        progress.close()

    if total is None:
        total = downloaded
    timestamp = dt.datetime.now().strftime("%Y-%m-%d")
    parquet_path = output_dir / f"odns_{timestamp}.pq"
    logger.info(
        "ODNS API data: converting {} downloaded entries to {}",
        downloaded,
        parquet_path,
    )
    convert_odns_json_to_parquet(input_dir=out_dir, output=parquet_path)
    logger.info("Cleaning up temporary JSON files in {}", out_dir)
    for file in out_dir.glob("*.json"):
        file.unlink()
    out_dir.rmdir()
    logger.info("Done.")
    return parquet_path


def _fetch_spoofing(
    *,
    output_dir: Path | None = None,
    api_key: str | None = None,
    per_page: int | None = None,
) -> tuple[Path, int]:
    api_key = api_key if api_key is not None else required_config_value(CONFIG_KEY, "odns_api_auth_token")
    api_url = required_config_value(CONFIG_KEY, "odns_api_url")
    per_page = per_page if per_page is not None else required_config_int(CONFIG_KEY, "odns_per_page")
    output_dir = output_dir or external_data_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("ODNS spoofing data: fetching TransparentForwarder records")
    page = 1
    total: int | None = None
    downloaded = 0
    entries: list[dict[str, Any]] = []

    progress = tqdm(total=0, desc="Downloading ODNS spoofing entries", unit="entry")
    try:
        while True:
            payload = {
                "pagination": {"page": page, "per_page": per_page},
                "filter": {"resolver_type": "TransparentForwarder"},
                "fieldsToReturn": ODNS_SPOOFING_FIELDS,
                "sort": {"field": "scan_date", "order": "desc"},
            }
            response = _post_json(payload, api_key, api_url)
            page_entries = response.get("dnsEntries", [])
            meta = response.get("metaData", {})
            if total is None:
                total = int(meta.get("total", 0))
                progress.reset(total=total)
                logger.info("ODNS spoofing data: API reports {} matching entries", total)

            if not page_entries:
                break

            entries.extend(page_entries)
            downloaded += len(page_entries)
            progress.update(len(page_entries))
            logger.info(
                "ODNS spoofing data: page {} downloaded {} entries ({}/{})",
                page,
                len(page_entries),
                downloaded,
                total if total is not None else "?",
            )

            if total is not None and downloaded >= total:
                break
            if len(page_entries) < per_page:
                break
            page += 1
    finally:
        progress.close()

    timestamp = dt.datetime.now(dt.UTC).date().isoformat()
    parquet_path = output_dir / f"odns_spoofing_{timestamp}.pq"
    frame = _normalize_spoofing_frame(entries)
    frame.write_parquet(parquet_path)
    logger.info("ODNS spoofing data: wrote {} entries to {}", frame.height, parquet_path)
    return parquet_path, frame.height


def fetch(
    *,
    dataset: str = "full",
    api_key: str | None = None,
    out_dir: Path | None = None,
    per_page: int | None = None,
    output_dir: Path | None = None,
) -> Path | tuple[Path, int]:
    if dataset == "full":
        return _fetch_full(
            api_key=api_key,
            out_dir=out_dir,
            per_page=per_page,
            output_dir=output_dir,
        )
    if dataset == "spoofing":
        return _fetch_spoofing(
            api_key=api_key,
            per_page=per_page,
            output_dir=output_dir,
        )
    raise ValueError(f"Unsupported ODNS API dataset: {dataset}")
