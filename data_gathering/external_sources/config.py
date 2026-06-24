"""Shared configuration for external data-source fetchers."""

from __future__ import annotations

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    load_dotenv = None


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_env() -> None:
    env_path = repository_root() / ".env"
    if load_dotenv is not None:
        load_dotenv(env_path)
        return

    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def external_data_dir() -> Path:
    _load_env()
    configured = os.getenv("EXTERNAL_DATA_DIR")
    if configured:
        return Path(configured).expanduser()

    data_dir = os.getenv("DATA_DIR")
    if data_dir:
        return Path(data_dir).expanduser() / "external"

    return repository_root() / "data" / "external"


def external_interim_dir(source_name: str) -> Path:
    return external_data_dir().parent / "interim" / source_name
