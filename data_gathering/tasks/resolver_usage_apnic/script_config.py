"""Configuration and logging helpers for APNIC resolver usage tasks."""

from __future__ import annotations

from configparser import ConfigParser, SectionProxy
from pathlib import Path

from loguru import logger


CONFIG_FILE = Path(__file__).with_name("resolver_usage_apnic.conf")
EXAMPLE_CONFIG_FILE = Path(__file__).with_name("resolver_usage_apnic.conf.example")


def load_script_config(script_path: str | Path) -> SectionProxy:
    script_path = Path(script_path)
    parser = ConfigParser()
    read_files = parser.read(CONFIG_FILE)
    if not read_files:
        read_files = parser.read(EXAMPLE_CONFIG_FILE)
    if not read_files:
        raise FileNotFoundError(f"Missing APNIC resolver usage config: {CONFIG_FILE}")
    if not parser.has_section(script_path.name):
        raise KeyError(f"Missing config section [{script_path.name}] in {read_files[0]}")
    return parser[script_path.name]


def required_config_value(script_path: str | Path, key: str) -> str:
    section = load_script_config(script_path)
    value = section.get(key, fallback="").strip()
    if not value:
        raise ValueError(f"Missing APNIC resolver usage config value {key!r}")
    return value


def required_config_int(script_path: str | Path, key: str) -> int:
    return int(required_config_value(script_path, key))


def required_config_float(script_path: str | Path, key: str) -> float:
    return float(required_config_value(script_path, key))


def script_logger(script_path: str | Path):
    return logger.bind(logging_tag=required_config_value(script_path, "logging_tag"))
