"""Download IPv6 candidates and dispatch RR-mirror verification/import."""

from __future__ import annotations

from pathlib import Path

from data_gathering.external_sources.ipv6_hitlist.fetcher import fetch_latest_udp53_file
from data_gathering.tasks.ipv6_hitlist.export_ipv6_resolver_ips import export_ipv6_resolver_ips
from data_gathering.tasks.ipv6_hitlist.script_config import (
    required_config_int,
    required_config_value,
    script_logger,
)


logger = script_logger(__file__)
MEASUREMENT_TASK = "measurements.tasks.verify_ipv6_resolvers.import_candidates"
MEASUREMENTS_DATA_ROOT = Path("/app/data")


def _credential(key: str) -> str:
    value = required_config_value(__file__, key)
    if value.startswith("<") and value.endswith(">"):
        raise ValueError(
            f"Replace {value} in data_gathering/tasks/ipv6_hitlist/ipv6_hitlist.conf"
        )
    return value


def _measurements_path(data_gathering_path: Path) -> Path:
    """Translate the shared /data mount to its path in the measurements container."""

    try:
        relative_path = data_gathering_path.relative_to("/data")
    except ValueError as exc:
        raise ValueError(f"IPv6 Hitlist output must be below /data: {data_gathering_path}") from exc
    return MEASUREMENTS_DATA_ROOT / relative_path


def update_ipv6_hitlist() -> dict[str, object]:
    from data_gathering.celery_app import app

    base_url = required_config_value(__file__, "base_url")
    username = _credential("username")
    password = _credential("password")
    data_dir = Path(required_config_value(__file__, "data_dir"))
    timeout = required_config_int(__file__, "request_timeout_seconds")

    logger.info("Discovering the latest IPv6 Hitlist UDP/53 data below {}", base_url)
    selected, downloaded_path = fetch_latest_udp53_file(
        base_url,
        data_dir,
        username=username,
        password=password,
        timeout=timeout,
    )
    output_dir = Path(required_config_value("export_ipv6_resolver_ips.py", "output_dir"))
    logger.info("Exporting unverified IPv6 measurement candidates from {}", downloaded_path)
    export_report = export_ipv6_resolver_ips(
        downloaded_path,
        measurement_date=selected.measurement_date,
        output_dir=output_dir,
    )
    measurement_input = _measurements_path(Path(str(export_report["output_file"])))
    measurement_output = MEASUREMENTS_DATA_ROOT / "measurements" / "verify_ipv6_resolvers" / (
        f"ipv6-hitlist-{selected.measurement_date.isoformat()}.jsonl"
    )
    measurement_result = app.send_task(
        MEASUREMENT_TASK,
        args=(str(measurement_input), str(measurement_output), "ipv6-hitlist-service"),
        queue="measurements",
    )
    logger.info(
        "Queued RR-mirror AAAA verification and matching-resolver import: task_id={task_id}",
        task_id=measurement_result.id,
    )
    return {
        "month": selected.month,
        "measurement_date": selected.measurement_date.isoformat(),
        "source_url": selected.url,
        "downloaded_file": str(downloaded_path),
        "candidate_export": export_report,
        "measurement_import": {
            "queued": True,
            "task": MEASUREMENT_TASK,
            "task_id": measurement_result.id,
            "input_file": str(measurement_input),
            "output_file": str(measurement_output),
        },
    }


def main() -> None:
    report = update_ipv6_hitlist()
    logger.info("IPv6 Hitlist update complete: {}", report)


if __name__ == "__main__":
    main()
