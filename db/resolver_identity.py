"""Helpers for linking resolver IP rows to logical resolver identities."""

from __future__ import annotations

from typing import Any

import psycopg


def _clean_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _clean_domain(value: object) -> str | None:
    text = _clean_text(value)
    if text is None:
        return None
    return text.rstrip(".").lower()


def _identity_name(row: dict[str, Any], domain: str | None) -> str | None:
    return (
        _clean_text(row.get("resolver_name"))
        or _clean_text(row.get("identity_name"))
        or _clean_text(row.get("name"))
        or domain
    )


def _identity_operator(row: dict[str, Any]) -> str | None:
    return _clean_text(row.get("resolver_operator") or row.get("operator"))


def _row_domain(row: dict[str, Any]) -> str | None:
    return _clean_domain(row.get("resolver_domain") or row.get("domain"))


def _find_identity(
    cursor: psycopg.Cursor,
    *,
    name: str | None,
    operator: str | None,
    domain: str | None,
) -> int | None:
    if domain:
        cursor.execute(
            """
            SELECT resolver_identity_id
            FROM resolver_domain
            WHERE LOWER(domain) = LOWER(%s)
            ORDER BY id
            LIMIT 1
            """,
            (domain,),
        )
        row = cursor.fetchone()
        if row:
            return int(row[0])

    if name:
        cursor.execute(
            """
            SELECT id
            FROM resolver_identity
            WHERE LOWER(name) = LOWER(%s)
              AND (
                  (%s IS NULL AND operator IS NULL)
                  OR LOWER(operator) = LOWER(%s)
              )
            ORDER BY id
            LIMIT 1
            """,
            (name, operator, operator),
        )
        row = cursor.fetchone()
        if row:
            return int(row[0])

    return None


def _ensure_identity(
    cursor: psycopg.Cursor,
    *,
    name: str | None,
    operator: str | None,
    source: str | None,
    domain: str | None,
) -> int:
    identity_id = _find_identity(cursor, name=name, operator=operator, domain=domain)
    if identity_id is not None:
        cursor.execute(
            """
            UPDATE resolver_identity
            SET
                name = COALESCE(name, %s),
                operator = COALESCE(operator, %s),
                source = COALESCE(source, %s),
                updated_at = NOW()
            WHERE id = %s
            """,
            (name, operator, source, identity_id),
        )
        return identity_id

    cursor.execute(
        """
        INSERT INTO resolver_identity (name, operator, source)
        VALUES (%s, %s, %s)
        RETURNING id
        """,
        (name, operator, source),
    )
    return int(cursor.fetchone()[0])


def _upsert_domain(
    cursor: psycopg.Cursor,
    *,
    identity_id: int,
    domain: str,
    source: str | None,
    last_observation_ts: object | None,
) -> None:
    cursor.execute(
        """
        INSERT INTO resolver_domain (
            resolver_identity_id, domain, source, last_observation_ts
        )
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (resolver_identity_id, (LOWER(domain)))
        DO UPDATE SET
            source = COALESCE(EXCLUDED.source, resolver_domain.source),
            last_observation_ts = GREATEST(
                resolver_domain.last_observation_ts,
                COALESCE(EXCLUDED.last_observation_ts, resolver_domain.last_observation_ts)
            ),
            updated_at = NOW()
        """,
        (identity_id, domain, source, last_observation_ts),
    )


def attach_resolver_identities(
    connection: psycopg.Connection,
    rows: list[dict[str, Any]],
) -> None:
    """Set resolver_identity_id on rows with identity or domain evidence."""

    with connection.cursor() as cursor:
        for row in rows:
            row.setdefault("resolver_identity_id", None)
            if row["resolver_identity_id"] is not None:
                identity_id = int(row["resolver_identity_id"])
            else:
                domain = _row_domain(row)
                name = _identity_name(row, domain)
                operator = _identity_operator(row)
                if name is None and operator is None and domain is None:
                    continue
                identity_id = _ensure_identity(
                    cursor,
                    name=name,
                    operator=operator,
                    source=_clean_text(row.get("source")),
                    domain=domain,
                )
                row["resolver_identity_id"] = identity_id

            domain = _row_domain(row)
            if domain:
                _upsert_domain(
                    cursor,
                    identity_id=identity_id,
                    domain=domain,
                    source=_clean_text(row.get("source")),
                    last_observation_ts=row.get("last_observation_ts"),
                )
