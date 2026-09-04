"""Shared ZDNS runtime configuration and command-line options."""

from __future__ import annotations

import configparser
import ipaddress
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
CONFIG_FILE = Path(__file__).with_name("zdns.conf")
EXAMPLE_CONFIG_FILE = Path(__file__).with_name("zdns.conf.example")


def _parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y"}:
        return True
    if normalized in {"0", "false", "no", "n"}:
        return False
    raise ValueError(f"Invalid ZDNS boolean value: {value}")


def load_zdns_config(path: Path = CONFIG_FILE) -> dict[str, str]:
    parser = configparser.ConfigParser()
    read_files = parser.read(path)
    if not read_files and path == CONFIG_FILE:
        read_files = parser.read(EXAMPLE_CONFIG_FILE)
    if not read_files:
        raise FileNotFoundError(f"Missing ZDNS config: {path}")
    return dict(parser["zdns"])


def _resolve_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else BASE_DIR / path


def build_zdns_command(
    module: str,
    *,
    domain: str,
    input_path: Path,
    output_path: Path,
    ip_version: int,
    task_config: dict[str, str] | None = None,
    config_path: Path = CONFIG_FILE,
) -> tuple[list[str], dict[str, str]]:
    """Build a ZDNS command, preferring settings from the shared config."""

    if ip_version not in {4, 6}:
        raise ValueError("ip_version must be 4 or 6")

    task_config = task_config or {}
    shared = load_zdns_config(config_path)

    def setting(name: str, default: str) -> str:
        # Shared settings are authoritative when present. Task values remain a
        # backwards-compatible fallback for existing deployments.
        return shared.get(name) or task_config.get(name) or default

    local_addr_key = "ipv6_local_addr" if ip_version == 6 else "ipv4_local_addr"
    local_addr = shared.get(local_addr_key, "").strip()
    if local_addr:
        parsed_addr = ipaddress.ip_address(local_addr)
        if parsed_addr.version != ip_version:
            raise ValueError(
                f"{local_addr_key} must contain an IPv{ip_version} address, got {local_addr!r}"
            )

    zdns_path = _resolve_path(setting("path", task_config.get("zdns_path", "measurements/tools/zdns/zdns")))
    command = [
        str(zdns_path),
        module.upper(),
        "--name-server-mode",
    ]
    if ip_version == 6:
        command.append("--6")
    if local_addr:
        command.append(f"--local-addr={local_addr}")
    command.extend(
        [
            f"--override-name={domain}",
            f"--input-file={input_path}",
            f"--output-file={output_path}",
            f"--threads={setting('threads', '100')}",
            f"--network-timeout={setting('network_timeout', '8')}",
            f"--retries={setting('retries', '1')}",
        ]
    )
    if _parse_bool(setting("no_recycle_sockets", "true")):
        command.append("--no-recycle-sockets")

    effective = {
        "path": str(zdns_path),
        "ip_version": str(ip_version),
        "local_addr": local_addr,
        "threads": setting("threads", "100"),
        "network_timeout": setting("network_timeout", "8"),
        "retries": setting("retries", "1"),
    }
    return command, effective
