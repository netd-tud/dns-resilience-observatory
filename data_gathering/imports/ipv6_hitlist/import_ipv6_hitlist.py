"""Import parsed IPv6 Hitlist rows into resolver and resolver_service."""

from __future__ import annotations

import argparse
from pathlib import Path

from data_gathering.config.db_connection import close_db_connection, connect_to_db
from data_gathering.imports.resolver.import_resolvers import import_resolvers


SOURCE = "ipv6-hitlist-service"
SOURCE_URL = "https://ipv6hitlist.github.io/"
SOURCE_OUTPUT_URL = "https://alcatraz.net.in.tum.de/ipv6-hitlist-service/registered/output/"
MAPPING = "ip:resolver_ip,port:port,protocol:protocol,supported:supported"


def _ensure_data_source() -> None:
    cursor = connect_to_db()
    connection = cursor.connection
    try:
        cursor.execute(
            """
            INSERT INTO data_source (
                source, url, api_endpoint, documentation_endpoint, description, apikey_required
            )
            VALUES (%s, %s, %s, %s, %s, TRUE)
            ON CONFLICT (source) DO UPDATE SET
                url = EXCLUDED.url,
                api_endpoint = EXCLUDED.api_endpoint,
                documentation_endpoint = EXCLUDED.documentation_endpoint,
                description = EXCLUDED.description,
                apikey_required = TRUE
            """,
            (
                SOURCE,
                SOURCE_URL,
                SOURCE_OUTPUT_URL,
                "https://ipv6hitlist.github.io/",
                "IPv6 Hitlist Service UDP/53 responder data.",
            ),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        close_db_connection(cursor)


def _touch_data_source() -> None:
    cursor = connect_to_db()
    connection = cursor.connection
    try:
        cursor.execute("UPDATE data_source SET last_retrieved_ts = NOW() WHERE source = %s", (SOURCE,))
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        close_db_connection(cursor)


def import_ipv6_hitlist(
    path: Path,
    *,
    dry_run: bool = True,
    force: bool = False,
) -> dict[str, dict[str, int]]:
    if not dry_run:
        _ensure_data_source()
    report = import_resolvers(
        path,
        mapping=MAPPING,
        modules="resolver,protocol",
        dry_run=dry_run,
        verified=True,
        force=force,
        source=SOURCE,
        is_public=True,
    )
    if not dry_run:
        _touch_data_source()
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Import parsed IPv6 Hitlist resolver data.")
    parser.add_argument("file", type=Path, help="Parsed CSV from parse_ipv6_hitlist.py")
    parser.add_argument(
        "--no-dry-run",
        action="store_true",
        help="Write changes to the database. The default is a dry run.",
    )
    parser.add_argument("--force", action="store_true", help="Force updates regardless of timestamps.")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    import_ipv6_hitlist(args.file, dry_run=not args.no_dry_run, force=args.force)


if __name__ == "__main__":
    main()
