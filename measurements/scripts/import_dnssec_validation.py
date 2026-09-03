"""Import an externally produced ZDNS DNSSEC-validation JSONL file."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path
from typing import Iterable

from loguru import logger

from measurements.tasks.dnssec_validation.dnssec_validation import (
    DEFAULT_DOMAIN,
    DEFAULT_SOURCE,
    _extract_ip,
    _import_observations,
    _mark_run_failed,
    _start_run,
    parse_zdns_results,
)


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _load_resolver_input(path: Path) -> list[str]:
    resolver_ips: list[str] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            value = line.strip()
            if not value:
                continue
            try:
                resolver_ips.append(str(ipaddress.ip_interface(value).ip))
            except ValueError as error:
                raise ValueError(f"Invalid resolver address on line {line_number} of {path}: {value}") from error
    return _unique(resolver_ips)


def _resolver_ips_from_jsonl(path: Path) -> list[str]:
    resolver_ips: list[str] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping invalid ZDNS JSON on line {line_number}", line_number=line_number)
                continue
            if not isinstance(row, dict):
                continue
            results = row.get("results")
            result = results.get("A", {}) if isinstance(results, dict) else {}
            data = result.get("data") if isinstance(result, dict) and isinstance(result.get("data"), dict) else {}
            resolver_ip = _extract_ip(row.get("nameserver")) or _extract_ip(data.get("resolver"))
            if resolver_ip:
                resolver_ips.append(resolver_ip)
    return _unique(resolver_ips)


def _content_run_key(jsonl_path: Path, resolver_input: Path | None, query_name: str, source: str) -> str:
    digest = hashlib.sha256()
    digest.update(query_name.encode("utf-8"))
    digest.update(b"\0")
    digest.update(source.encode("utf-8"))
    for path in (jsonl_path, resolver_input):
        if path is None:
            continue
        digest.update(b"\0")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return f"external-zdns-dnssec:{digest.hexdigest()}"


def _parse_observed_at(value: str | None) -> dt.datetime:
    if not value:
        return dt.datetime.now(dt.timezone.utc)
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def import_dnssec_validation(
    jsonl_path: Path,
    *,
    resolver_input: Path | None,
    query_name: str,
    source: str,
    run_key: str | None,
    observed_at: dt.datetime,
) -> dict[str, object]:
    resolver_ips = (
        _load_resolver_input(resolver_input)
        if resolver_input is not None
        else _resolver_ips_from_jsonl(jsonl_path)
    )
    if not resolver_ips:
        raise ValueError(f"No target resolver addresses could be read from {jsonl_path}")
    if resolver_input is None:
        logger.warning(
            "No resolver input file supplied; resolvers without an attributable JSONL row cannot be recorded as unknown"
        )

    observations = parse_zdns_results(jsonl_path, resolver_ips, fallback_timestamp=observed_at)
    observation_times = [item["observed_at"] for item in observations]
    started_at = min(observation_times, default=observed_at)
    finished_at = max(observation_times, default=observed_at)
    effective_run_key = run_key or _content_run_key(jsonl_path, resolver_input, query_name, source)

    run_id, reused, reused_report = _start_run(
        run_key=effective_run_key,
        started_at=started_at,
        query_name=query_name,
        output_file=str(jsonl_path),
        source=source,
        target_count=len(resolver_ips),
    )
    if reused:
        assert reused_report is not None
        reused_report["run_key"] = effective_run_key
        return reused_report

    try:
        inserted_count = _import_observations(
            run_id=run_id,
            observations=observations,
            source=source,
            finished_at=finished_at,
        )
    except Exception as error:
        _mark_run_failed(run_id, error)
        raise

    validating_count = sum(item["dnssec_validation"] is True for item in observations)
    non_validating_count = sum(item["dnssec_validation"] is False for item in observations)
    return {
        "run_id": run_id,
        "run_key": effective_run_key,
        "resolver_count": len(observations),
        "inserted_count": inserted_count,
        "validating_count": validating_count,
        "non_validating_count": non_validating_count,
        "unknown_count": len(observations) - validating_count - non_validating_count,
        "reused_run": False,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", type=Path, help="Raw ZDNS JSONL output to import")
    parser.add_argument(
        "--resolver-input",
        type=Path,
        help="Original one-IP-per-line input file; recommended so missing outputs are retained as unknown",
    )
    parser.add_argument("--query-name", default=DEFAULT_DOMAIN)
    parser.add_argument("--source", default=DEFAULT_SOURCE)
    parser.add_argument("--run-key", help="Unique run identifier; defaults to a content-derived key")
    parser.add_argument(
        "--observed-at",
        help="Fallback measurement time for rows without timestamps (ISO 8601; defaults to import time)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = import_dnssec_validation(
        args.jsonl,
        resolver_input=args.resolver_input,
        query_name=args.query_name,
        source=args.source,
        run_key=args.run_key,
        observed_at=_parse_observed_at(args.observed_at),
    )
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
