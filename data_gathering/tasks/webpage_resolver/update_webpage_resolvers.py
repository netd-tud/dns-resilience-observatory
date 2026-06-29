"""Download configured webpage resolver lists and import them into the database."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from data_gathering.config.db_connection import close_db_connection, connect_to_db
from data_gathering.imports.resolver.import_resolvers import import_resolvers
from data_gathering.tasks.webpage_resolver.script_config import load_parser, required_config_value, script_logger
from data_gathering.tools.download_and_import_from_web import download_file


logger = script_logger(__file__)


@dataclass(frozen=True)
class ResolverUrlConfig:
    name: str
    url: str
    mapping: str
    modules: str
    headers: str | None
    no_header: bool
    separator: str
    source: str
    description: str | None
    verified: bool
    force: bool


def _config_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    raise ValueError(f"Invalid boolean config value: {value!r}")


def _required(section, key: str, section_name: str) -> str:
    if key not in section or not section[key].strip():
        raise KeyError(f"Missing required config value '{key}' in section [{section_name}]")
    return section[key].strip()


def _load_url_configs() -> list[ResolverUrlConfig]:
    parser = load_parser()
    if not parser.has_section("urls"):
        raise KeyError("Missing config section [urls]")

    configs = []
    for name, url in parser.items("urls"):
        url = url.strip()
        if not url:
            continue
        section_name = f"url.{name}"
        if not parser.has_section(section_name):
            raise KeyError(f"Missing config section [{section_name}]")
        section = parser[section_name]
        headers = section.get("headers", fallback=None)
        headers = headers.strip() if headers and headers.strip() else None
        source = section.get("source", fallback="webpage-resolver").strip() or "webpage-resolver"
        configs.append(
            ResolverUrlConfig(
                name=name,
                url=url,
                mapping=_required(section, "mapping", section_name),
                modules=_required(section, "modules", section_name),
                headers=headers,
                no_header=_config_bool(section.get("no_header", fallback=None), default=headers is not None),
                separator=section.get("separator", fallback=","),
                source=source,
                description=section.get("description", fallback=None),
                verified=_config_bool(section.get("verified", fallback=None), default=False),
                force=_config_bool(section.get("force", fallback=None), default=False),
            )
        )
    return configs


def _ensure_data_source(source: str, description: str | None) -> None:
    cursor = connect_to_db()
    connection = cursor.connection
    try:
        cursor.execute(
            """
            INSERT INTO data_source (source, description, apikey_required)
            VALUES (%s, %s, FALSE)
            ON CONFLICT (source) DO UPDATE SET
                description = COALESCE(EXCLUDED.description, data_source.description)
            """,
            (source, description),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        close_db_connection(cursor)


def update_webpage_resolvers(data_dir: Path | None = None) -> dict[str, object]:
    data_dir = data_dir or Path(required_config_value(__file__, "data_dir"))
    configs = _load_url_configs()
    data_dir.mkdir(parents=True, exist_ok=True)

    reports: dict[str, object] = {"urls": len(configs), "imports": {}}
    for config in configs:
        logger.info("Processing webpage resolver URL {name}: {url}", name=config.name, url=config.url)
        _ensure_data_source(config.source, config.description)
        downloaded_path = download_file(config.url, output_dir=data_dir / config.name)
        import_report = import_resolvers(
            downloaded_path,
            mapping=config.mapping,
            modules=config.modules,
            dry_run=False,
            verified=config.verified,
            force=config.force,
            has_header=not config.no_header,
            headers=config.headers,
            separator=config.separator,
            source=config.source,
        )
        reports["imports"][config.name] = import_report
    return reports
