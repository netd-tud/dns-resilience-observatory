"""Collect resolver metainformation with ZDNS."""

from __future__ import annotations

import configparser
import ipaddress
import json
import subprocess
import time
from pathlib import Path
from typing import Any

from loguru import logger

from measurements.celery_app import app
from measurements.scripts.get_resolvers import query_resolvers


BASE_DIR = Path(__file__).resolve().parents[3]
CONFIG_FILE = Path(__file__).with_suffix(".conf")
EXAMPLE_CONFIG_FILE = Path(__file__).with_suffix(".conf.example")
DEFAULT_MODULES = {"svcb", "ptr", "a", "aaaa", "https"}
PTR_DOMAIN_MODULES = {"a", "aaaa", "https"}


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


def _modules(value: str | None) -> set[str]:
    if not value or not value.strip():
        return set(DEFAULT_MODULES)
    aliases = {"http": "https"}
    modules = {aliases.get(item.strip().lower(), item.strip().lower()) for item in value.split(",") if item.strip()}
    invalid = modules - DEFAULT_MODULES
    if invalid:
        raise ValueError(f"Invalid metainformation_resolvers modules: {', '.join(sorted(invalid))}")
    return modules


def load_config(path: Path = CONFIG_FILE) -> dict[str, str]:
    parser = configparser.ConfigParser()
    read_files = parser.read(path)
    if not read_files and path == CONFIG_FILE:
        read_files = parser.read(EXAMPLE_CONFIG_FILE)
    if not read_files:
        raise FileNotFoundError(f"Missing metainformation_resolvers config: {path}")
    return dict(parser["metainformation_resolvers"])


def _resolve_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else BASE_DIR / path


def _resolver_ips(rows: list[dict[str, Any]]) -> tuple[list[str], int]:
    resolver_ips: list[str] = []
    skipped = 0
    for row in rows:
        ip = ipaddress.ip_interface(str(row["resolver_ip"])).ip
        if not ip.is_global:
            skipped += 1
            continue
        resolver_ips.append(str(ip))
    return resolver_ips, skipped


def _line_count(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8") as handle:
        return sum(1 for _ in handle)


def _run_zdns(command: list[str], *, cwd: Path = BASE_DIR) -> None:
    logger.info("Running ZDNS command: {command}", command=" ".join(command))
    process = subprocess.Popen(
        command,
        cwd=cwd,
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
        raise RuntimeError(f"zdns failed with exit code {return_code}")


def _base_zdns_command(config: dict[str, str], module: str, input_path: Path, output_path: Path) -> list[str]:
    command = [
        str(_resolve_path(config.get("zdns_path", "measurements/tools/zdns/zdns"))),
        module,
        f"--input-file={input_path}",
        f"--output-file={output_path}",
        f"--threads={config.get('threads', '100')}",
        f"--network-timeout={config.get('network_timeout', '8')}",
        f"--retries={config.get('retries', '1')}",
    ]
    if _optional_bool(config.get("no_recycle_sockets", "true")):
        command.append("--no-recycle-sockets")
    return command


def _add_recursive_name_servers(command: list[str], config: dict[str, str]) -> list[str]:
    name_servers = config.get("recursive_name_servers", "").strip()
    if name_servers:
        command.append(f"--name-servers={name_servers}")
    return command


def _extract_ptr_answer(value: Any) -> set[str]:
    domains: set[str] = set()
    if isinstance(value, dict):
        record_type = str(value.get("type", "")).upper()
        for key, item in value.items():
            normalized_key = str(key).lower()
            if isinstance(item, str) and (
                normalized_key in {"ptrdname", "target"} or (record_type == "PTR" and normalized_key in {"answer", "name"})
            ):
                candidate = item.strip().rstrip(".")
                if candidate and not _looks_like_ip(candidate):
                    domains.add(candidate)
            domains.update(_extract_ptr_answer(item))
    elif isinstance(value, list):
        for item in value:
            domains.update(_extract_ptr_answer(item))
    return domains


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _extract_ptr_domains(ptr_output_path: Path) -> list[str]:
    domains: set[str] = set()
    with ptr_output_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping invalid JSON line in PTR output: {line}", line=line[:200])
                continue
            result = row.get("results", {}).get("PTR", {})
            if result.get("status") != "NOERROR":
                continue
            domains.update(_extract_ptr_answer(result.get("data", {})))
    return sorted(domains)


def run_metainformation_resolvers(config_path: Path = CONFIG_FILE) -> dict[str, object]:
    started = time.monotonic()
    logger.info("Starting metainformation_resolvers task")
    config = load_config(config_path)
    logger.info("Loaded metainformation_resolvers config from {path}", path=config_path)

    output_dir = _resolve_path(config.get("output_dir", "data/measurements/metainformation_resolvers"))
    output_dir.mkdir(parents=True, exist_ok=True)

    resolver_input_path = output_dir / config.get("resolver_input_file", "resolvers.txt")
    ptr_domains_path = output_dir / config.get("ptr_domains_file", "ptr_domains.txt")
    svcb_output_path = output_dir / config.get("svcb_output_file", "resolver_arpa_svcb.jsonl")
    ptr_output_path = output_dir / config.get("ptr_output_file", "resolver_ptr.jsonl")
    a_output_path = output_dir / config.get("a_output_file", "ptr_domains_a.jsonl")
    aaaa_output_path = output_dir / config.get("aaaa_output_file", "ptr_domains_aaaa.jsonl")
    https_output_path = output_dir / config.get("https_output_file", "ptr_domains_https.jsonl")
    resolver_information_domain = config.get("resolver_information_domain", "_dns.resolver.arpa")
    modules = _modules(config.get("modules"))
    logger.info("Enabled metainformation modules: {modules}", modules=", ".join(sorted(modules)))

    rows = query_resolvers(
        verified=_optional_bool(config.get("verified")),
        is_public=_optional_bool(config.get("is_public")),
        source=config.get("source") or None,
        country=config.get("country") or None,
        asn=_optional_int(config.get("asn")),
        limit=_optional_int(config.get("limit")),
    )
    resolver_ips, skipped_resolvers = _resolver_ips(rows)
    resolver_input_path.write_text("\n".join(resolver_ips) + ("\n" if resolver_ips else ""), encoding="utf-8")
    logger.info(
        "Wrote {count} resolver IPs to {path}; skipped {skipped} non-global resolver IPs",
        count=len(resolver_ips),
        path=resolver_input_path,
        skipped=skipped_resolvers,
    )

    if "svcb" in modules:
        svcb_command = _base_zdns_command(config, "SVCB", resolver_input_path, svcb_output_path)
        svcb_command.extend(["--name-server-mode", f"--override-name={resolver_information_domain}"])
        _run_zdns(svcb_command)
    else:
        logger.info("Skipping SVCB module")

    ptr_domains: list[str] = []
    if "ptr" in modules:
        ptr_command = _add_recursive_name_servers(_base_zdns_command(config, "PTR", resolver_input_path, ptr_output_path), config)
        _run_zdns(ptr_command)
        ptr_domains = _extract_ptr_domains(ptr_output_path)
        ptr_domains_path.write_text("\n".join(ptr_domains) + ("\n" if ptr_domains else ""), encoding="utf-8")
        logger.info("Extracted {count} unique PTR domains to {path}", count=len(ptr_domains), path=ptr_domains_path)
    elif modules & PTR_DOMAIN_MODULES:
        if not ptr_domains_path.exists():
            raise FileNotFoundError(
                f"Requested {', '.join(sorted(modules & PTR_DOMAIN_MODULES))} without ptr, but PTR domain file is missing: {ptr_domains_path}"
            )
        ptr_domains = [line.strip() for line in ptr_domains_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        logger.info("Loaded {count} existing PTR domains from {path}", count=len(ptr_domains), path=ptr_domains_path)
    else:
        logger.info("Skipping PTR module")

    for module, output_path in [("A", a_output_path), ("AAAA", aaaa_output_path), ("HTTPS", https_output_path)]:
        module_key = module.lower()
        if module_key not in modules:
            logger.info("Skipping {module} module", module=module)
            continue
        command = _add_recursive_name_servers(_base_zdns_command(config, module, ptr_domains_path, output_path), config)
        _run_zdns(command)

    elapsed = time.monotonic() - started
    report = {
        "resolver_count": len(resolver_ips),
        "skipped_non_global_resolvers": skipped_resolvers,
        "modules": sorted(modules),
        "ptr_domain_count": len(ptr_domains),
        "svcb_output_file": str(svcb_output_path),
        "ptr_output_file": str(ptr_output_path),
        "a_output_file": str(a_output_path),
        "aaaa_output_file": str(aaaa_output_path),
        "https_output_file": str(https_output_path),
        "svcb_output_rows": _line_count(svcb_output_path),
        "ptr_output_rows": _line_count(ptr_output_path),
        "a_output_rows": _line_count(a_output_path),
        "aaaa_output_rows": _line_count(aaaa_output_path),
        "https_output_rows": _line_count(https_output_path),
        "elapsed_seconds": round(elapsed, 3),
    }
    logger.info("Finished metainformation_resolvers task: {report}", report=report)
    return report


@app.task(name="measurements.tasks.metainformation_resolvers.run")
def run() -> dict[str, object]:
    return run_metainformation_resolvers()
