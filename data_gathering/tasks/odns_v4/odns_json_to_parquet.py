import ipaddress
import json
from pathlib import Path
from typing import Any, Iterable

import polars as pl
from tqdm import tqdm

from data_gathering.tasks.odns_v4.script_config import required_config_value, script_logger


ENTRY_KEYS = (
    "data",
    "entries",
    "items",
    "results",
    "dns_entries",
    "dnsEntries",
    "records",
)

logger = script_logger(__file__)


def _data_dir() -> Path:
    return Path(required_config_value(__file__, "data_dir"))


def _extract_entries(obj: Any) -> list[dict[str, Any]]:
    if isinstance(obj, list):
        return obj
    if not isinstance(obj, dict):
        raise ValueError("Unsupported JSON payload type")

    for key in ENTRY_KEYS:
        value = obj.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            for sub_key in ENTRY_KEYS:
                nested = value.get(sub_key)
                if isinstance(nested, list):
                    return nested

    raise ValueError("Could not locate entries list in JSON payload")


def _load_entries(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    entries = _extract_entries(payload)
    if not all(isinstance(item, dict) for item in entries):
        raise ValueError(f"Entries in {path} are not objects")
    return entries


def _iter_paths(input_dir: Path, inputs: Iterable[Path]) -> list[Path]:
    if inputs:
        return list(inputs)
    if not input_dir.exists():
        raise FileNotFoundError(f"{input_dir} does not exist")
    return sorted(p for p in input_dir.glob("*.json") if p.is_file())


def _flatten_entry(entry: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    for key, value in entry.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            flattened.update(_flatten_entry(value, name))
        else:
            flattened[name] = value
    return flattened


def normalize_entries(entries: list[dict[str, Any]]) -> pl.DataFrame:
    return pl.DataFrame([_flatten_entry(entry) for entry in entries], infer_schema_length=None)


def _ip_to_u32(value: Any) -> int | None:
    if value is None:
        return None
    try:
        ip_value = int(ipaddress.ip_address(str(value)))
    except ValueError:
        return None
    if ip_value > 2**32 - 1:
        return None
    return ip_value


def convert_odns_json_to_parquet(
    *,
    input_dir: Path | None = None,
    output: Path,
    inputs: Iterable[Path] = (),
) -> Path:
    input_dir = input_dir or _data_dir() / "interim"
    paths = _iter_paths(input_dir, inputs)
    if not paths:
        raise FileNotFoundError("No JSON files found")
    logger.info("Parsing {} ODNS JSON file(s)", len(paths))

    all_entries: list[dict[str, Any]] = []
    for path in tqdm(paths, desc="Parsing JSON files", unit="file"):
        entries = _load_entries(path)
        all_entries.extend(entries)
        logger.info(
            "Parsed {} entries from {} (total {})",
            len(entries),
            path,
            len(all_entries),
        )

    if not all_entries:
        raise ValueError("No entries found across inputs")

    frame = normalize_entries(all_entries)

    category_cols = [
        "protocol",
        "resolver_type",
        "queried_ip_country",
        "replying_ip_country",
        "queried_ip_prefix",
        "replying_ip_prefix",
        "queried_ip_org",
        "replying_ip_org",
        "backend_resolver_country",
        "backend_resolver_prefix",
        "backend_resolver_org",
    ]
    for col in category_cols:
        if col in frame.columns:
            frame = frame.with_columns(pl.col(col).cast(pl.Utf8, strict=False))

    timestamp_cols = ["timestamp_request", "scan_date"]
    for col in timestamp_cols:
        if col in frame.columns:
            frame = frame.with_columns(pl.col(col).cast(pl.Utf8, strict=False).str.to_datetime(strict=False, time_zone="UTC"))

    asn_cols = ["queried_ip_asn", "replying_ip_asn", "backend_resolver_asn"]
    for col in asn_cols:
        if col in frame.columns:
            frame = frame.with_columns(pl.col(col).cast(pl.Float64, strict=False).round(0).cast(pl.UInt32, strict=False))

    ip_cols = ["queried_ip", "replying_ip", "backend_resolver"]
    for col in ip_cols:
        if col in frame.columns:
            frame = frame.with_columns(pl.col(col).map_elements(_ip_to_u32, return_dtype=pl.UInt32).alias(f"{col}_uint32"))

    output.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Writing parquet file to {}...", output)
    frame.write_parquet(output)
    logger.info("Done writing parquet file with {} entries to {}", frame.height, output)
    return output
