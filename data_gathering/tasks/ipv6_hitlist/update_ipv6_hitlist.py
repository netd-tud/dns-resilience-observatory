"""Download, parse, and import the latest IPv6 Hitlist UDP/53 data."""

from __future__ import annotations

from pathlib import Path

from data_gathering.external_sources.ipv6_hitlist.fetcher import fetch_latest_udp53_file
from data_gathering.imports.ipv6_hitlist.import_ipv6_hitlist import import_ipv6_hitlist
from data_gathering.tasks.ipv6_hitlist.parse_ipv6_hitlist import parse_ipv6_hitlist
from data_gathering.tasks.ipv6_hitlist.script_config import (
    required_config_bool,
    required_config_int,
    required_config_value,
    script_logger,
)


logger = script_logger(__file__)


def _credential(key: str) -> str:
    value = required_config_value(__file__, key)
    if value.startswith("<") and value.endswith(">"):
        raise ValueError(
            f"Replace {value} in data_gathering/tasks/ipv6_hitlist/ipv6_hitlist.conf"
        )
    return value


def update_ipv6_hitlist() -> dict[str, object]:
    base_url = required_config_value(__file__, "base_url")
    username = _credential("username")
    password = _credential("password")
    data_dir = Path(required_config_value(__file__, "data_dir"))
    interim_dir = Path(required_config_value(__file__, "interim_dir"))
    timeout = required_config_int(__file__, "request_timeout_seconds")
    force = required_config_bool(__file__, "force")

    logger.info("Discovering the latest IPv6 Hitlist UDP/53 data below {}", base_url)
    selected, downloaded_path = fetch_latest_udp53_file(
        base_url,
        data_dir,
        username=username,
        password=password,
        timeout=timeout,
    )
    parsed_path = interim_dir / selected.month / f"{selected.measurement_date.isoformat()}-udp53.parsed.csv"
    logger.info("Parsing {}", downloaded_path)
    parse_report = parse_ipv6_hitlist(downloaded_path, parsed_path)
    logger.info("Importing successful IPv6 UDP/53 responders from {}", parsed_path)
    import_report = import_ipv6_hitlist(parsed_path, dry_run=False, force=force)
    return {
        "month": selected.month,
        "measurement_date": selected.measurement_date.isoformat(),
        "source_url": selected.url,
        "downloaded_file": str(downloaded_path),
        "parsed_file": str(parsed_path),
        "parse": parse_report,
        "import": import_report,
    }


def main() -> None:
    report = update_ipv6_hitlist()
    logger.info("IPv6 Hitlist update complete: {}", report)


if __name__ == "__main__":
    main()
