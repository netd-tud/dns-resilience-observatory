"""Database connection helpers for measurement scripts."""

from __future__ import annotations

import os
from pathlib import Path

import psycopg
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parents[1]


def build_dsn() -> str:
    load_dotenv(BASE_DIR / ".env")

    db_url = os.getenv("DATABASE_URL")
    if db_url:
        return db_url

    host = os.getenv("DATABASE_HOST", "localhost")
    port = os.getenv("DATABASE_PORT", "5432")
    user = os.getenv("DATABASE_USER", "postgres")
    password = os.getenv("DATABASE_PASSWORD", "")
    name = os.getenv("DATABASE_NAME", "dns_resilience_observatory")

    if password:
        return f"postgresql://{user}:{password}@{host}:{port}/{name}"
    return f"postgresql://{user}@{host}:{port}/{name}"


def connect():
    return psycopg.connect(build_dsn())
