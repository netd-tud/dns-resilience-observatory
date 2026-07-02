"""Verify resolvers by running a ZDNS A lookup through each resolver."""

from __future__ import annotations

import configparser
import ipaddress
import subprocess
import time
from pathlib import Path

from loguru import logger

from measurements.celery_app import app
from measurements.scripts.get_resolvers import query_resolvers


BASE_DIR = Path(__file__).resolve().parents[3]
CONFIG_FILE = Path(__file__).with_suffix(".conf")
EXAMPLE_CONFIG_FILE = Path(__file__).with_suffix(".conf.example")


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
        raise FileNotFoundError(f"Missing verify_resolver config: {path}")
    return dict(parser["verify_resolver"])


def _resolve_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else BASE_DIR / path


def _zdns_nameserver_ips(rows: list[dict[str, object]]) -> tuple[list[str], int]:
    resolver_ips: list[str] = []
    skipped = 0
    for row in rows:
        raw_ip = str(row["resolver_ip"])
        ip = ipaddress.ip_interface(raw_ip).ip
        if not ip.is_global:
            skipped += 1
            continue
        resolver_ips.append(str(ip))
    return resolver_ips, skipped


def run_verify_resolver(config_path: Path = CONFIG_FILE) -> dict[str, object]:
    started = time.monotonic()
    logger.info("Starting verify_resolver task")
    config = load_config(config_path)
    logger.info("Loaded verify_resolver config from {path}", path=config_path)
    output_dir = _resolve_path(config.get("output_dir", "data/measurements/verify_resolver"))
    output_dir.mkdir(parents=True, exist_ok=True)

    input_path = output_dir / config.get("input_file", "resolvers.txt")
    output_path = output_dir / config.get("output_file", "verify_resolver.jsonl")
    domain = config.get("domain", "google.com")
    zdns_path = _resolve_path(config.get("zdns_path", "measurements/tools/zdns/zdns"))
    logger.info(
        "verify_resolver settings: domain={domain}, zdns_path={zdns_path}, output_dir={output_dir}, threads={threads}, timeout={timeout}, retries={retries}",
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
        source=config.get("source") or None,
        country=config.get("country") or None,
        asn=_optional_int(config.get("asn")),
        limit=_optional_int(config.get("limit")),
    )
    resolver_ips, skipped_resolvers = _zdns_nameserver_ips(rows)
    input_path.write_text("\n".join(resolver_ips) + ("\n" if resolver_ips else ""))
    logger.info(
        "Wrote {count} resolver IPs to {path}; skipped {skipped} non-global resolver IPs",
        count=len(resolver_ips),
        path=input_path,
        skipped=skipped_resolvers,
    )
    if resolver_ips:
        logger.info("First resolver IPs: {sample}", sample=", ".join(resolver_ips[:5]))
    else:
        logger.warning("No resolver IPs matched the configured filters; ZDNS will still be invoked with an empty input file")

    command = [
        str(zdns_path),
        "A",
        "--name-server-mode",
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
        logger.error("ZDNS failed with exit code {return_code} after {elapsed:.1f}s", return_code=return_code, elapsed=elapsed)
        raise RuntimeError(f"zdns failed with exit code {return_code}")

    output_lines = 0
    if output_path.exists():
        with output_path.open("r", encoding="utf-8") as handle:
            output_lines = sum(1 for _ in handle)
    logger.info(
        "Finished verify_resolver task in {elapsed:.1f}s; output_file={output_file}; output_rows={output_rows}",
        elapsed=elapsed,
        output_file=output_path,
        output_rows=output_lines,
    )

    return {
        "resolver_count": len(resolver_ips),
        "domain": domain,
        "input_file": str(input_path),
        "output_file": str(output_path),
        "output_rows": output_lines,
        "elapsed_seconds": round(elapsed, 3),
    }


@app.task(name="measurements.tasks.verify_resolvers.run")
def run() -> dict[str, object]:
    return run_verify_resolver()
