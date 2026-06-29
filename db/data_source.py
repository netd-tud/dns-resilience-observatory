"""Insert configured data sources into the database."""

from __future__ import annotations

import argparse
from configparser import ConfigParser, SectionProxy
import logging
import os
from pathlib import Path

try:
    from loguru import logger
except ModuleNotFoundError:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    logger = logging.getLogger(__name__)


CONFIG_FILE = Path(__file__).with_name("data-sources.conf")


def build_dsn() -> str:
    try:
        from dotenv import dotenv_values, load_dotenv
    except ModuleNotFoundError:
        env = dict(os.environ)
    else:
        load_dotenv()
        env = {**dotenv_values(), **dict(os.environ)}

    db_url = env.get("DATABASE_URL")
    if db_url:
        return db_url

    host = env.get("DATABASE_HOST", "localhost")
    port = env.get("DATABASE_PORT", "5432")
    user = env.get("DATABASE_USER", "postgres")
    password = env.get("DATABASE_PASSWORD", "")
    name = env.get("DATABASE_NAME", "dns_resilience_observatory")

    if password:
        return f"postgresql://{user}:{password}@{host}:{port}/{name}"
    return f"postgresql://{user}@{host}:{port}/{name}"


def _optional(section: SectionProxy, key: str) -> str | None:
    value = section.get(key, fallback="").strip()
    return value or None


def _source_name(section_name: str) -> str:
    prefix = "source."
    if not section_name.startswith(prefix):
        raise ValueError(f"Invalid section {section_name!r}; expected [source.<name>]")
    source = section_name[len(prefix) :].strip()
    if not source:
        raise ValueError(f"Invalid empty source name in section {section_name!r}")
    return source


def load_sources(config_file: Path) -> list[dict[str, object]]:
    parser = ConfigParser()
    if not parser.read(config_file):
        raise FileNotFoundError(f"Missing data sources config file: {config_file}")

    sources = []
    for section_name in parser.sections():
        section = parser[section_name]
        sources.append(
            {
                "source": _source_name(section_name),
                "url": _optional(section, "url"),
                "api_endpoint": _optional(section, "api_endpoint"),
                "documentation_endpoint": _optional(section, "documentation_endpoint"),
                "description": _optional(section, "description"),
                "apikey_required": section.getboolean("apikey_required", fallback=False),
            }
        )
    return sources


def insert_sources(config_file: Path = CONFIG_FILE) -> dict[str, int]:
    import psycopg

    sources = load_sources(config_file)
    inserted = 0

    with psycopg.connect(build_dsn()) as connection:
        with connection.cursor() as cursor:
            for source in sources:
                cursor.execute(
                    """
                    INSERT INTO data_source (
                        source,
                        url,
                        api_endpoint,
                        documentation_endpoint,
                        description,
                        apikey_required
                    )
                    VALUES (
                        %(source)s,
                        %(url)s,
                        %(api_endpoint)s,
                        %(documentation_endpoint)s,
                        %(description)s,
                        %(apikey_required)s
                    )
                    ON CONFLICT (source) DO NOTHING
                    """,
                    source,
                )
                inserted += cursor.rowcount
        connection.commit()

    skipped = len(sources) - inserted
    logger.info("Data sources loaded: inserted={}, already_present={}", inserted, skipped)
    return {"configured": len(sources), "inserted": inserted, "already_present": skipped}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Insert configured data_source rows if missing.")
    parser.add_argument(
        "--config",
        type=Path,
        default=CONFIG_FILE,
        help=f"Path to data sources config. Default: {CONFIG_FILE}",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    insert_sources(args.config)


if __name__ == "__main__":
    main()
