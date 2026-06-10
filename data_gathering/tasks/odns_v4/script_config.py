"""Per-module configuration and logging setup for ODNS tasks."""

from __future__ import annotations

from configparser import ConfigParser, SectionProxy
import sys
from pathlib import Path

from loguru import logger as base_logger


LOG_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level: <8}</level> | "
    "[tag={extra[logging_tag]}] "
    "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
    "<level>{message}</level>"
)

_CONFIGURED = False
CONFIG_FILE = Path(__file__).with_name("odns_v4.conf")


def _ensure_logger_configured() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return

    def add_default_script(record: dict[str, object]) -> None:
        extra = record["extra"]
        if isinstance(extra, dict):
            file_info = record["file"]
            extra.setdefault("logging_tag", getattr(file_info, "name", "unknown"))

    base_logger.configure(
        handlers=[{"sink": sys.stderr, "format": LOG_FORMAT}],
        patcher=add_default_script,
    )
    _CONFIGURED = True


def load_script_config(script_path: str | Path) -> SectionProxy:
    script_path = Path(script_path)
    parser = ConfigParser()
    if not parser.read(CONFIG_FILE):
        raise FileNotFoundError(f"Missing ODNS config file: {CONFIG_FILE}")
    if not parser.has_section(script_path.name):
        raise KeyError(f"Missing config section [{script_path.name}] in {CONFIG_FILE}")
    return parser[script_path.name]


def required_config_value(script_path: str | Path, key: str) -> str:
    script_path = Path(script_path)
    config = load_script_config(script_path)
    if key not in config:
        raise KeyError(f"Missing config value '{key}' in section [{script_path.name}] of {CONFIG_FILE}")
    value = config[key].strip()
    if value == "":
        raise ValueError(f"Empty config value '{key}' in section [{script_path.name}] of {CONFIG_FILE}")
    return value


def required_config_int(script_path: str | Path, key: str) -> int:
    value = required_config_value(script_path, key)
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(
            f"Invalid integer config value '{key}' in section [{Path(script_path).name}] "
            f"of {CONFIG_FILE}: {value!r}"
        ) from exc


def script_logger(script_path: str | Path):
    script_path = Path(script_path)
    tag = required_config_value(script_path, "logging_tag")
    _ensure_logger_configured()
    return base_logger.bind(logging_tag=tag)
