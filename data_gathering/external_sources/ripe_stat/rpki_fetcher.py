"""Fetch RIPEstat RPKI validity for a prefix/origin-ASN pair."""

from __future__ import annotations

from data_gathering.external_sources.http_json import JsonHttpClient


RPKI_STATES = {"valid", "unknown", "invalid_asn", "invalid_length"}


def fetch_rpki_status(
    client: JsonHttpClient,
    *,
    url: str,
    prefix: str,
    asn: int,
) -> str:
    payload = client.get(url, {"resource": asn, "prefix": prefix})
    data = payload.get("data")
    if not isinstance(data, dict):
        raise ValueError(f"RIPEstat returned no data object for {prefix} AS{asn}")
    status = str(data.get("status", "")).strip().lower().replace("-", "_")
    if status not in RPKI_STATES:
        raise ValueError(f"RIPEstat returned unknown status {status!r} for {prefix} AS{asn}")
    return status
