"""Fetch recent CAIDA Spoofer sessions for the spoofing task."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from tqdm import tqdm

from data_gathering.external_sources.caida.spoofer.script_config import (
    required_config_path,
    required_config_int,
    required_config_value,
    script_logger,
)


CONFIG_KEY = "fetch_caida_spoofer_api_data.py"
logger = script_logger(CONFIG_KEY)


def _get_json(url: str) -> dict[str, Any] | list[dict[str, Any]]:
    request = Request(url, headers={"accept": "application/json"})
    try:
        with urlopen(request) as response:
            body = response.read().decode("utf-8")
    except HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} from CAIDA Spoofer API: {error_body}") from exc
    return json.loads(body)


def _append_page(url: str, page: int) -> str:
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}page={page}"


def _members(response: dict[str, Any] | list[dict[str, Any]]) -> list[dict[str, Any]]:
    if isinstance(response, list):
        return response
    members = response.get("hydra:member", [])
    if not isinstance(members, list):
        raise ValueError("CAIDA Spoofer API response does not contain a hydra:member list")
    return members


def _total_items(response: dict[str, Any] | list[dict[str, Any]]) -> int | None:
    if not isinstance(response, dict):
        return None
    total = response.get("hydra:totalItems")
    if total is None:
        return None
    return int(total)


def _write_jsonl(path: Path, items: list[dict[str, Any]]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item, separators=(",", ":")) + "\n")


def fetch(
    *,
    output_dir: Path | None = None,
    fetch_last_days: int | None = None,
    items_per_page: int | None = None,
    max_pages: int | None = None,
) -> tuple[Path, int]:
    api_url = required_config_value(CONFIG_KEY, "caida_spoofer_api_url")
    fetch_last_days = (
        fetch_last_days
        if fetch_last_days is not None
        else required_config_int(CONFIG_KEY, "caida_fetch_last_days")
    )
    items_per_page = (
        items_per_page
        if items_per_page is not None
        else required_config_int(CONFIG_KEY, "caida_items_per_page")
    )
    output_dir = output_dir or required_config_path(CONFIG_KEY, "data_dir")
    output_dir.mkdir(parents=True, exist_ok=True)

    today = dt.datetime.now(dt.UTC).date()
    params = {
        "itemsPerPage": str(items_per_page),
        "timestamp[after]": (today - dt.timedelta(days=fetch_last_days)).isoformat(),
        "timestamp[before]": (today + dt.timedelta(days=1)).isoformat(),
        "order[timestamp]": "desc",
    }
    base_url = f"{api_url}?{urlencode(params)}"
    output_path = output_dir / f"caida_spoofer_sessions_{today.isoformat()}.jsonl"
    output_path.write_text("", encoding="utf-8")

    logger.info(
        "CAIDA Spoofer: fetching last {} day(s) into {}",
        fetch_last_days,
        output_path,
    )
    downloaded = 0
    seen_sessions: set[str] = set()
    previous_page_first_id: str | None = None
    progress = tqdm(total=0, desc="Downloading CAIDA sessions", unit="session")
    try:
        page = 1
        while True:
            if max_pages is not None and page > max_pages:
                break
            response = _get_json(_append_page(base_url, page))
            members = _members(response)
            if page == 1:
                total = _total_items(response)
                if total is not None:
                    progress.reset(total=total)
                    logger.info("CAIDA Spoofer: API reports {} matching sessions", total)

            if not members:
                break

            first_id = str(members[0].get("session") or members[0].get("@id") or "")
            if previous_page_first_id == first_id:
                logger.warning("CAIDA Spoofer pagination did not advance; stopping")
                break
            previous_page_first_id = first_id

            new_members = []
            for item in members:
                session_id = str(item.get("session") or item.get("@id") or "")
                if session_id and session_id in seen_sessions:
                    continue
                if session_id:
                    seen_sessions.add(session_id)
                new_members.append(item)

            if new_members:
                _write_jsonl(output_path, new_members)
                downloaded += len(new_members)
                progress.update(len(new_members))
                logger.info(
                    "CAIDA Spoofer: page {} downloaded {} sessions ({})",
                    page,
                    len(new_members),
                    downloaded,
                )

            page += 1
    finally:
        progress.close()

    logger.info("CAIDA Spoofer: wrote {} sessions to {}", downloaded, output_path)
    return output_path, downloaded

if __name__=='__main__':
    fetch(fetch_last_days=1)
