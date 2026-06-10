import datetime as dt
import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from tqdm import tqdm

from data_gathering.tasks.odns_v4.odns_json_to_parquet import convert_odns_json_to_parquet
from data_gathering.tasks.odns_v4.script_config import (
    required_config_int,
    required_config_value,
    script_logger,
)


logger = script_logger(__file__)


def _data_dir() -> Path:
    return Path(required_config_value(__file__, "data_dir"))


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


def fetch_odns_api_data(
    *,
    api_key: str | None = None,
    out_dir: Path | None = None,
    per_page: int | None = None,
    output_dir: Path | None = None,
) -> Path:
    api_key = api_key if api_key is not None else required_config_value(__file__, "odns_api_auth_token")
    api_url = required_config_value(__file__, "odns_api_url")
    per_page = per_page if per_page is not None else required_config_int(__file__, "odns_per_page")
    data_dir = _data_dir()
    output_dir = output_dir or data_dir / "external"

    out_dir = out_dir or (data_dir / "interim" / f"odns_{dt.datetime.now().strftime('%Y%m%d')}")
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


def fetch_odns_api_data_from_config(
    *,
    out_dir: Path | None = None,
    per_page: int | None = None,
    output_dir: Path | None = None,
) -> Path:
    return fetch_odns_api_data(
        out_dir=out_dir,
        per_page=per_page,
        output_dir=output_dir,
    )
