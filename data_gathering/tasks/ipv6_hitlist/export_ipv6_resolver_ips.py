"""Download the latest IPv6 Hitlist data and export every IPv6 saddr, one per line."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import ipaddress
import lzma
from pathlib import Path

from data_gathering.external_sources.ipv6_hitlist.fetcher import fetch_latest_udp53_file
from data_gathering.tasks.ipv6_hitlist.script_config import (
    required_config_int,
    required_config_value,
    script_logger,
)


logger = script_logger(__file__)
DOWNLOAD_CONFIG_SECTION = "update_ipv6_hitlist.py"


def _download_config(key: str) -> str:
    return required_config_value(DOWNLOAD_CONFIG_SECTION, key)


def _credential(key: str) -> str:
    value = _download_config(key)
    if value.startswith("<") and value.endswith(">"):
        raise ValueError(
            f"Replace {value} in data_gathering/tasks/ipv6_hitlist/ipv6_hitlist.conf"
        )
    return value


def export_ipv6_resolver_ips(
    input_path: Path,
    *,
    measurement_date: dt.date,
    output_dir: Path,
) -> dict[str, object]:
    """Export all unique IPv6 source addresses as unverified measurement candidates."""

    addresses: set[str] = set()
    rows = 0
    valid_ipv6_rows = 0
    invalid_ip_rows = 0
    non_ipv6_rows = 0
    with lzma.open(input_path, mode="rt", encoding="utf-8", newline="") as source_handle:
        reader = csv.DictReader(source_handle)
        if "saddr" not in (reader.fieldnames or []):
            raise ValueError(f"IPv6 Hitlist input is missing saddr: {input_path}")
        for row in reader:
            rows += 1
            address = (row.get("saddr") or "").strip()
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                invalid_ip_rows += 1
                continue
            if ip.version != 6:
                non_ipv6_rows += 1
                continue
            valid_ipv6_rows += 1
            addresses.add(ip.compressed)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"resolver-ipv6-{measurement_date.isoformat()}.txt"
    temporary_path = output_path.with_name(f".{output_path.name}.part")
    try:
        with temporary_path.open("w", encoding="utf-8", newline="\n") as target_handle:
            for address in sorted(addresses, key=lambda value: int(ipaddress.IPv6Address(value))):
                target_handle.write(f"{address}\n")
        temporary_path.replace(output_path)
    finally:
        temporary_path.unlink(missing_ok=True)

    report = {
        "measurement_date": measurement_date.isoformat(),
        "input_file": str(input_path),
        "output_file": str(output_path),
        "source_rows": rows,
        "valid_ipv6_rows": valid_ipv6_rows,
        "duplicate_rows": valid_ipv6_rows - len(addresses),
        "invalid_ip_rows": invalid_ip_rows,
        "non_ipv6_rows": non_ipv6_rows,
        "resolver_count": len(addresses),
    }
    logger.info("IPv6 resolver IP export complete: {}", report)
    return report


def export_latest_ipv6_resolver_ips(output_dir: Path | None = None) -> dict[str, object]:
    data_dir = Path(_download_config("data_dir"))
    output_dir = output_dir or Path(required_config_value(__file__, "output_dir"))

    selected, downloaded_path = fetch_latest_udp53_file(
        _download_config("base_url"),
        data_dir,
        username=_credential("username"),
        password=_credential("password"),
        timeout=required_config_int(DOWNLOAD_CONFIG_SECTION, "request_timeout_seconds"),
    )
    report = export_ipv6_resolver_ips(
        downloaded_path,
        measurement_date=selected.measurement_date,
        output_dir=output_dir,
    )
    return {
        **report,
        "source_url": selected.url,
        "downloaded_file": str(downloaded_path),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Download the latest IPv6 Hitlist UDP/53 data and export every IPv6 saddr."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Output directory. Defaults to output_dir from ipv6_hitlist.conf.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    export_latest_ipv6_resolver_ips(args.output_dir)


if __name__ == "__main__":
    main()
