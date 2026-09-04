"""Verify IPv6 recursive DNS resolvers with a ZDNS AAAA lookup over IPv6."""

from __future__ import annotations

import configparser
import ipaddress
import subprocess
import time
from pathlib import Path

from loguru import logger

from data_gathering.task_lock import advisory_task_lock
from measurements.celery_app import app
from measurements.scripts.get_resolvers import query_resolvers


BASE_DIR = Path(__file__).resolve().parents[3]
CONFIG_FILE = Path(__file__).with_suffix(".conf")
EXAMPLE_CONFIG_FILE = Path(__file__).with_suffix(".conf.example")
DEFAULT_DOMAIN = "rr-mirror.research6.nawrocki.berlin"
CANDIDATE_TASK_NAME = "measurements.tasks.verify_ipv6_resolvers.import_candidates"


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
    zdns_path = _resolve_path(config.get("zdns_path", "measurements/tools/zdns/zdns"))
    if not input_path.is_file():
        raise FileNotFoundError(f"Missing IPv6 resolver candidate file: {input_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        str(zdns_path),
        "AAAA",
        "--name-server-mode",
        "--6",
        f"--override-name={domain}",
        f"--input-file={input_path}",
        f"--output-file={output_path}",
        f"--threads={config.get('threads', '100')}",
        f"--network-timeout={config.get('network_timeout', '8')}",
        f"--retries={config.get('retries', '1')}",
    ]
    if _optional_bool(config.get("no_recycle_sockets", "true")):
        command.append("--no-recycle-sockets")

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
    zdns_path = _resolve_path(config.get("zdns_path", "measurements/tools/zdns/zdns"))

    logger.info(
        "IPv6 resolver verification settings: domain={domain}, record_type=AAAA, transport=IPv6, "
        "zdns_path={zdns_path}, output_dir={output_dir}, threads={threads}, "
        "timeout={timeout}, retries={retries}",
        domain=domain,
        zdns_path=zdns_path,
        output_dir=output_dir,
        threads=config.get("threads", "100"),
        timeout=config.get("network_timeout", "8"),
        retries=config.get("retries", "1"),
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

    command = [
        str(zdns_path),
        "AAAA",
        "--name-server-mode",
        "--6",
        f"--override-name={domain}",
        f"--input-file={input_path}",
        f"--output-file={output_path}",
        f"--threads={config.get('threads', '100')}",
        f"--network-timeout={config.get('network_timeout', '8')}",
        f"--retries={config.get('retries', '1')}",
    ]
    if _optional_bool(config.get("no_recycle_sockets", "true")):
        command.append("--no-recycle-sockets")

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
    logger.info(
        "Finished verify_ipv6_resolvers task in {elapsed:.1f}s; output_file={output_file}; "
        "output_rows={output_rows}",
        elapsed=elapsed,
        output_file=output_path,
        output_rows=output_lines,
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
