"""Fetch MANRS readiness summaries for one ASN or economy."""

from __future__ import annotations

from typing import Any, Literal

from data_gathering.external_sources.http_json import JsonHttpClient


EntityType = Literal["asn", "country"]


def fetch_summary(
    client: JsonHttpClient,
    *,
    url: str,
    entity_type: EntityType,
    entity: int | str,
    month: str,
) -> dict[str, Any]:
    parameter = "asns" if entity_type == "asn" else "economies"
    payload = client.get(url, {parameter: entity, "month": month})
    scores = payload.get("scores")
    if not isinstance(scores, dict):
        raise ValueError(f"MANRS returned no scores object for {entity_type} {entity}")
    return scores
