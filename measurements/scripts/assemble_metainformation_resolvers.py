"""Assemble resolver metainformation ZDNS outputs into dataframes."""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import sys
from pathlib import Path
from typing import Any, Iterable

import polars as pl

OBSERVATORY_ROOT = Path(__file__).resolve().parents[2]
if str(OBSERVATORY_ROOT) not in sys.path:
    sys.path.insert(0, str(OBSERVATORY_ROOT))

try:
    from loguru import logger
except ModuleNotFoundError:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    logger = logging.getLogger(__name__)


def _load_rows(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        first = handle.read(1)
        handle.seek(0)
        if first == "[":
            data = json.load(handle)
            if isinstance(data, list):
                for row in data:
                    if isinstance(row, dict):
                        yield row
            elif isinstance(data, dict):
                yield data
            return

        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON in {path}:{line_number}: {exc}") from exc
            if isinstance(row, dict):
                yield row


def _clean_domain(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    domain = value.strip().rstrip(".")
    return domain or None


def _string_list(value: Any) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, list):
        values = [str(item) for item in value if item is not None]
        return values or None
    values = [part.strip() for part in str(value).split(",") if part.strip()]
    return values or None


def _resolver_ip(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    resolver = value.strip()
    if not resolver:
        return None
    if resolver.startswith("[") and "]" in resolver:
        resolver = resolver[1 : resolver.index("]")]
    else:
        try:
            return str(ipaddress.ip_address(resolver))
        except ValueError:
            pass
        host, separator, port = resolver.rpartition(":")
        if separator and port.isdigit():
            resolver = host
    try:
        return str(ipaddress.ip_address(resolver))
    except ValueError:
        return resolver or None


def _walk(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _extract_ptr_domains(data: Any) -> list[str]:
    domains: set[str] = set()
    for item in _walk(data):
        record_type = str(item.get("type", "")).upper()
        if record_type != "PTR":
            continue
        for key in ("answer", "ptrdname", "target", "name"):
            domain = _clean_domain(item.get(key))
            if domain and "in-addr.arpa" not in domain.lower():
                domains.add(domain)
    return sorted(domains)


def _extract_svcb_records(data: Any) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for item in _walk(data):
        record_type = str(item.get("type", "")).upper()
        if record_type not in {"SVCB", "HTTPS"} and "svcparams" not in item:
            continue
        svcparams = item.get("svcparams") if isinstance(item.get("svcparams"), dict) else {}
        records.append(
            {
                "domain": _clean_domain(item.get("target")) or _clean_domain(item.get("answer")) or _clean_domain(item.get("name")),
                "alpn": _string_list(svcparams.get("alpn")),
                "port": svcparams.get("port"),
                "ipv4hint": _string_list(svcparams.get("ipv4hint")),
                "ipv6hint": _string_list(svcparams.get("ipv6hint")),
                "dohpath": svcparams.get("dohpath") or svcparams.get("key7"),
            }
        )
    return records


def assemble_metainformation(inputs: Iterable[Path | str]) -> tuple[pl.DataFrame, pl.DataFrame]:
    ptr_rows: list[dict[str, Any]] = []
    svcb_rows: list[dict[str, Any]] = []

    for input_path in inputs:
        path = Path(input_path)
        for row in _load_rows(path):
            resolver_ip = row.get("name")
            results = row.get("results") if isinstance(row.get("results"), dict) else {}

            ptr_result = results.get("PTR") if isinstance(results.get("PTR"), dict) else None
            if ptr_result and ptr_result.get("status") == "NOERROR":
                for domain in _extract_ptr_domains(ptr_result.get("data", {})):
                    ptr_rows.append({"resolver_ip": resolver_ip, "domain": domain})

            for module_name in ("SVCB", "HTTPS"):
                result = results.get(module_name) if isinstance(results.get(module_name), dict) else None
                if not result or result.get("status") != "NOERROR":
                    continue
                data = result.get("data", {}) if isinstance(result.get("data"), dict) else {}
                svcb_resolver_ip = _resolver_ip(data.get("resolver")) or _resolver_ip(resolver_ip)
                for record in _extract_svcb_records(result.get("data", {})):
                    if record.get("domain"):
                        svcb_rows.append({"resolver_ip": svcb_resolver_ip, **record})

    ptr_frame = pl.DataFrame(ptr_rows, schema={"resolver_ip": pl.String, "domain": pl.String})
    svcb_frame = pl.DataFrame(
        svcb_rows,
        schema={
            "resolver_ip": pl.String,
            "domain": pl.String,
            "alpn": pl.List(pl.String),
            "port": pl.Int64,
            "ipv4hint": pl.List(pl.String),
            "ipv6hint": pl.List(pl.String),
            "dohpath": pl.String,
        },
    )
    return ptr_frame, svcb_frame


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Assemble ZDNS resolver metainformation JSON/JSONL outputs.")
    parser.add_argument("input", nargs="+", type=Path, help="ZDNS JSON or JSONL output file(s).")
    parser.add_argument("--head", type=int, default=10, help="Number of rows to print from each dataframe.")
    parser.add_argument(
        "--no-import",
        action="store_true",
        help="Only assemble and print dataframe heads; do not run database import dry-runs.",
    )
    parser.add_argument(
        "--no-dry-run",
        action="store_true",
        help="Write assembled PTR/SVCB data to the database. Default is dry-run.",
    )
    parser.add_argument(
        "--source",
        default="zdns.svcb",
        help="Source for resolver IPs inserted from IPv6 hints. Default: zdns.svcb.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ptr_frame, svcb_frame = assemble_metainformation(args.input)
    logger.info("PTR dataframe head:\n{head}", head=ptr_frame.head(args.head))
    logger.info("SVCB dataframe head:\n{head}", head=svcb_frame.head(args.head))

    if args.no_import:
        return

    from data_gathering.imports.resolver.import_resolvers import (
        import_resolver_domains_frame,
        import_svcb_metadata_frame,
    )

    dry_run = not args.no_dry_run
    domain_report = import_resolver_domains_frame(ptr_frame, dry_run=dry_run, update_existing=True)
    svcb_report = import_svcb_metadata_frame(svcb_frame, dry_run=dry_run, source=args.source)
    logger.info("PTR import report: {report}", report=domain_report)
    logger.info("SVCB import report: {report}", report=svcb_report)


if __name__ == "__main__":
    main()
