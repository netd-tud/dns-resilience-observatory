"""Verify IPv6 recursive DNS resolvers with a ZDNS AAAA lookup over IPv6."""

from __future__ import annotations

import configparser
import datetime as dt
import ipaddress
import subprocess
import time
from pathlib import Path

from loguru import logger

from data_gathering.task_lock import advisory_task_lock
from measurements.celery_app import app
from measurements.db import connect
from measurements.scripts.get_resolvers import query_resolvers
from measurements.zdns_config import build_zdns_command


BASE_DIR = Path(__file__).resolve().parents[3]
CONFIG_FILE = Path(__file__).with_suffix(".conf")
EXAMPLE_CONFIG_FILE = Path(__file__).with_suffix(".conf.example")
DEFAULT_DOMAIN = "rr-mirror.research6.nawrocki.berlin"
CANDIDATE_TASK_NAME = "measurements.tasks.verify_ipv6_resolvers.import_candidates"
DEFAULT_VERIFICATION_SOURCE = "measurements.zdns.ipv6-verification"


def _optional_bool(value: str | None) -> bool | None:
    if value is None or not value.strip():
        return None
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y"}:
        return True
    if normalized in {"0", "false", "no", "n"}:
        return False
    raise ValueError(f"Invalid boolean config value: {value}")


def _optional_int(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    return int(value)


def load_config(path: Path = CONFIG_FILE) -> dict[str, str]:
    parser = configparser.ConfigParser()
    read_files = parser.read(path)
    if not read_files and path == CONFIG_FILE:
        read_files = parser.read(EXAMPLE_CONFIG_FILE)
    if not read_files:
        raise FileNotFoundError(f"Missing verify_ipv6_resolvers config: {path}")
    return dict(parser["verify_ipv6_resolvers"])


def _resolve_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else BASE_DIR / path


def _ipv6_nameserver_ips(rows: list[dict[str, object]]) -> tuple[list[str], int, int]:
    resolver_ips: list[str] = []
    skipped_non_global = 0
    skipped_non_ipv6 = 0
    for row in rows:
        ip = ipaddress.ip_interface(str(row["resolver_ip"])).ip
        if ip.version != 6:
            skipped_non_ipv6 += 1
            continue
        if not ip.is_global:
            skipped_non_global += 1
            continue
        resolver_ips.append(str(ip))
    return resolver_ips, skipped_non_global, skipped_non_ipv6


def _import_existing_resolver_results(
    output_path: Path,
    resolver_ips: list[str],
    *,
    verifying_source: str,
) -> dict[str, int]:
    """Record attempted targets and matching, self-answering IPv6 resolvers."""

    from data_gathering.imports.resolver.import_resolvers import read_zdns_noerror_rows

    _, accepted_rows, invalid_count = read_zdns_noerror_rows(
        output_path,
        module="AAAA",
        source=verifying_source,
        verified=True,
        is_public=True,
    )
    successful = {str(row["ip"]): row["last_update_ts"] for row in accepted_rows}
    measured_at = dt.datetime.now(dt.timezone.utc)

    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                CREATE TEMP TABLE ipv6_verification_stage (
                    ip INET PRIMARY KEY,
                    successful BOOLEAN NOT NULL,
                    observed_at TIMESTAMPTZ NOT NULL
                ) ON COMMIT DROP
                """
            )
            with cursor.copy(
                "COPY ipv6_verification_stage (ip, successful, observed_at) FROM STDIN"
            ) as copy:
                for resolver_ip in resolver_ips:
                    copy.write_row(
                        (
                            resolver_ip,
                            resolver_ip in successful,
                            successful.get(resolver_ip) or measured_at,
                        )
                    )

            cursor.execute(
                """
                UPDATE resolver_id ri
                SET total_measurements = ri.total_measurements + 1,
                    seen_measurements = ri.seen_measurements + stage.successful::INTEGER,
                    verified = ri.verified OR stage.successful,
                    last_update_ts = CASE
                        WHEN stage.successful
                        THEN GREATEST(ri.last_update_ts, stage.observed_at)
                        ELSE ri.last_update_ts
                    END
                FROM resolver r
                JOIN ipv6_verification_stage stage ON stage.ip = r.ip
                WHERE ri.id = r.resolver_id
                """
            )
            measured_count = cursor.rowcount
            cursor.execute(
                """
                UPDATE resolver r
                SET last_update_ts = GREATEST(r.last_update_ts, stage.observed_at)
                FROM ipv6_verification_stage stage
                WHERE r.ip = stage.ip
                  AND stage.successful
                """
            )
            successful_count = cursor.rowcount
            cursor.execute(
                """
                INSERT INTO resolver_verification (resolver_id, verifying_source)
                SELECT r.resolver_id, %s
                FROM resolver r
                JOIN ipv6_verification_stage stage ON stage.ip = r.ip
                WHERE stage.successful
                ON CONFLICT DO NOTHING
                """,
                (verifying_source,),
            )
            verification_insert_count = cursor.rowcount

    return {
        "measured": measured_count,
        "successful": successful_count,
        "failed_or_unknown": measured_count - successful_count,
        "verification_inserts": verification_insert_count,
        "invalid_output_rows": invalid_count,
    }


def run_verify_ipv6_candidate_file(
    input_path: Path,
    output_path: Path,
    *,
    source: str,
    is_public: bool = True,
    config_path: Path = CONFIG_FILE,
) -> dict[str, object]:
    """Measure an external IPv6 candidate list and import only self-answering resolvers."""

    from data_gathering.imports.resolver.import_resolvers import import_resolvers

    started = time.monotonic()
    config = load_config(config_path)
    domain = config.get("domain", DEFAULT_DOMAIN).strip() or DEFAULT_DOMAIN
    if not input_path.is_file():
        raise FileNotFoundError(f"Missing IPv6 resolver candidate file: {input_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    command, _ = build_zdns_command(
        "AAAA",
        domain=domain,
        input_path=input_path,
        output_path=output_path,
        ip_version=6,
        task_config=config,
    )

    logger.info("Running IPv6 candidate ZDNS command: {command}", command=" ".join(command))
    process = subprocess.Popen(
        command,
        cwd=BASE_DIR,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
    )
    assert process.stdout is not None
    for line in process.stdout:
        line = line.strip()
        if line:
            logger.info("zdns: {line}", line=line)
    return_code = process.wait()
    if return_code != 0:
        raise RuntimeError(f"IPv6 candidate ZDNS scan failed with exit code {return_code}")

    import_report = import_resolvers(
        output_path,
        mapping=None,
        modules="resolver",
        dry_run=False,
        verified=True,
        source=source,
        is_public=is_public,
        zdns_module="AAAA",
    )
    elapsed = time.monotonic() - started
    report = {
        "input_file": str(input_path),
        "output_file": str(output_path),
        "domain": domain,
        "source": source,
        "import": import_report,
        "elapsed_seconds": round(elapsed, 3),
    }
    logger.info("IPv6 candidate measurement and import complete: {report}", report=report)
    return report


def run_verify_ipv6_resolvers(config_path: Path = CONFIG_FILE) -> dict[str, object]:
    started = time.monotonic()
    logger.info("Starting verify_ipv6_resolvers task")
    config = load_config(config_path)
    logger.info("Loaded verify_ipv6_resolvers config from {path}", path=config_path)

    output_dir = _resolve_path(config.get("output_dir", "data/measurements/verify_ipv6_resolvers"))
    output_dir.mkdir(parents=True, exist_ok=True)
    input_path = output_dir / config.get("input_file", "ipv6_resolvers.txt")
    output_path = output_dir / config.get("output_file", "verify_ipv6_resolvers.jsonl")
    domain = config.get("domain", DEFAULT_DOMAIN).strip() or DEFAULT_DOMAIN
    verification_source = (
        config.get("verification_source", DEFAULT_VERIFICATION_SOURCE).strip()
        or DEFAULT_VERIFICATION_SOURCE
    )
    command, zdns_settings = build_zdns_command(
        "AAAA",
        domain=domain,
        input_path=input_path,
        output_path=output_path,
        ip_version=6,
        task_config=config,
    )

    logger.info(
        "IPv6 resolver verification settings: domain={domain}, record_type=AAAA, transport=IPv6, "
        "local_addr={local_addr}, zdns_path={zdns_path}, output_dir={output_dir}, "
        "threads={threads}, timeout={timeout}, retries={retries}",
        domain=domain,
        local_addr=zdns_settings["local_addr"] or "automatic",
        zdns_path=zdns_settings["path"],
        output_dir=output_dir,
        threads=zdns_settings["threads"],
        timeout=zdns_settings["network_timeout"],
        retries=zdns_settings["retries"],
    )

    rows = query_resolvers(
        verified=_optional_bool(config.get("verified")),
        is_public=_optional_bool(config.get("is_public")),
        ip_version=6,
        source=config.get("source") or None,
        country=config.get("country") or None,
        asn=_optional_int(config.get("asn")),
        limit=_optional_int(config.get("limit")),
    )
    resolver_ips, skipped_non_global, skipped_non_ipv6 = _ipv6_nameserver_ips(rows)
    input_path.write_text("\n".join(resolver_ips) + ("\n" if resolver_ips else ""), encoding="utf-8")
    logger.info(
        "Wrote {count} global IPv6 resolver IPs to {path}; skipped_non_global={non_global}; "
        "skipped_non_ipv6={non_ipv6}",
        count=len(resolver_ips),
        path=input_path,
        non_global=skipped_non_global,
        non_ipv6=skipped_non_ipv6,
    )
    if resolver_ips:
        logger.info("First IPv6 resolver IPs: {sample}", sample=", ".join(resolver_ips[:5]))
    else:
        logger.warning("No global IPv6 resolver IPs matched the configured filters")

    logger.info("Running ZDNS command: {command}", command=" ".join(command))
    process = subprocess.Popen(
        command,
        cwd=BASE_DIR,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
    )
    assert process.stdout is not None
    for line in process.stdout:
        line = line.strip()
        if line:
            logger.info("zdns: {line}", line=line)

    return_code = process.wait()
    elapsed = time.monotonic() - started
    if return_code != 0:
        logger.error(
            "ZDNS IPv6 verification failed with exit code {return_code} after {elapsed:.1f}s",
            return_code=return_code,
            elapsed=elapsed,
        )
        raise RuntimeError(f"zdns failed with exit code {return_code}")

    output_lines = 0
    if output_path.exists():
        with output_path.open("r", encoding="utf-8") as handle:
            output_lines = sum(1 for _ in handle)
    import_report = _import_existing_resolver_results(
        output_path,
        resolver_ips,
        verifying_source=verification_source,
    )
    logger.info(
        "Finished verify_ipv6_resolvers task in {elapsed:.1f}s; output_file={output_file}; "
        "output_rows={output_rows}; import={import_report}",
        elapsed=elapsed,
        output_file=output_path,
        output_rows=output_lines,
        import_report=import_report,
    )

    return {
        "resolver_count": len(resolver_ips),
        "skipped_non_global_resolvers": skipped_non_global,
        "skipped_non_ipv6_resolvers": skipped_non_ipv6,
        "domain": domain,
        "record_type": "AAAA",
        "transport": "ipv6",
        "input_file": str(input_path),
        "output_file": str(output_path),
        "output_rows": output_lines,
        "import": import_report,
        "elapsed_seconds": round(elapsed, 3),
    }


@app.task(name="measurements.tasks.verify_ipv6_resolvers.run")
def run() -> dict[str, object]:
    return run_verify_ipv6_resolvers()


@app.task(name=CANDIDATE_TASK_NAME)
def import_candidates(
    input_file: str,
    output_file: str,
    source: str = "ipv6-hitlist-service",
) -> dict[str, object]:
    with advisory_task_lock(CANDIDATE_TASK_NAME) as acquired:
        if not acquired:
            logger.info("IPv6 candidate verification is already running; skipping overlapping task")
            return {"skipped": True, "reason": "already_running"}
        return run_verify_ipv6_candidate_file(
            Path(input_file),
            Path(output_file),
            source=source,
        )
