"""Load anycast resolver records from a parquet file into PostgreSQL."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
import urllib.parse
import urllib.request
from functools import lru_cache

import psycopg
from dotenv import load_dotenv
from loguru import logger
from pyarrow import parquet as pq
import pycountry
from tqdm import tqdm

from apply_schema import build_dsn


DATA_FILE = Path(__file__).resolve().parents[1] / "data" / "anycast_resolver.pq"

ANYCAST_COLUMNS = [
    "resolver_id",
    "instance_id",
    "ipv4",
    "ipv6",
    "netmask",
    "asn",
    "bgp_prefix",
    "org",
    "org_short",
    "country",
    "city",
    "latitude",
    "longitude",
    "last_observation_ts",
    "source",
]

RESOLVER_LOOKUP_SQL = "SELECT id, ipv4, ipv6 FROM resolver"
GEOCODE_USER_AGENT = "dns-resilience-observatory-anycast-loader"
GEOCODE_MIN_DELAY_SECONDS = 1
GEOCODE_TIMEOUT_SECONDS = 5
NOMINATIM_URL = "https://nominatim.openstreetmap.org/search"
CACHE_FILE = Path(__file__).resolve().parents[1] / "data" / "anycast_geocode_cache.json"


def _normalize_key(value: object | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        trimmed = value.strip()
        return trimmed or None
    return str(value)


def _get_value(row: dict[str, object], keys: list[str]) -> object | None:
    for key in keys:
        if key in row and row.get(key) not in (None, ""):
            return row.get(key)
    return None


def _split_prefix(prefix: str | None) -> tuple[str | None, str | None]:
    if not prefix:
        return None, None
    if "/" not in prefix:
        return prefix, None
    ip_part, mask_part = prefix.split("/", 1)
    return ip_part or None, mask_part or None


@lru_cache(maxsize=512)
def _geocode_query(query: str) -> tuple[float | None, float | None]:
    if not query or not query.strip():
        return None, None

    params = urllib.parse.urlencode(
        {
            "q": query.strip(),
            "format": "json",
            "limit": 1,
        }
    )
    url = f"{NOMINATIM_URL}?{params}"

    try:
        request = urllib.request.Request(url, headers={"User-Agent": GEOCODE_USER_AGENT})
        with urllib.request.urlopen(request, timeout=GEOCODE_TIMEOUT_SECONDS) as response:
            data = json.loads(response.read().decode())
            if data:
                print(f"Geocoded '{query}' to lat={data[0]['lat']}, lon={data[0]['lon']}")
                return float(data[0]["lat"]), float(data[0]["lon"])
    except Exception:
        print(f"Geocoding failed for query: {query}")
        return None, None

    return None, None


def _cache_key(country: str | None, city: str | None) -> str:
    return f"{(country or '').strip().upper()}||{(city or '').strip()}"


def _country_query_value(country: str) -> str:
    trimmed = country.strip().upper()
    if len(trimmed) == 3:
        entry = pycountry.countries.get(alpha_3=trimmed)
    elif len(trimmed) == 2:
        entry = pycountry.countries.get(alpha_2=trimmed)
    else:
        entry = pycountry.countries.get(name=country.strip())
    return entry.name if entry else country.strip()


def _country_name_key(country_name: str | None) -> tuple[str | None, None]:
    if not country_name:
        return (None, None)
    return (country_name.strip().upper(), None)


def _cache_hit(country: str | None, city: str | None, cache: dict[tuple[str | None, str | None], tuple[float | None, float | None]]) -> bool:
    if not country:
        return False
    country_code = country.strip().upper()
    key = (country_code, city.strip() if city else None)
    if key in cache:
        return True
    if city is None:
        country_query = _country_query_value(country_code)
        return _country_name_key(country_query) in cache
    return False


def _load_cache() -> dict[tuple[str | None, str | None], tuple[float | None, float | None]]:
    if not CACHE_FILE.exists():
        return {}
    try:
        raw = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}

    cache: dict[tuple[str | None, str | None], tuple[float | None, float | None]] = {}
    for key, coords in raw.items():
        if not isinstance(key, str) or not isinstance(coords, list) or len(coords) != 2:
            continue
        country, city = key.split("||", 1)
        country_value = country or None
        city_value = city or None
        lat = coords[0] if isinstance(coords[0], (int, float)) else None
        lon = coords[1] if isinstance(coords[1], (int, float)) else None
        cache[(country_value, city_value)] = (lat, lon)
    return cache


def _save_cache(cache: dict[tuple[str | None, str | None], tuple[float | None, float | None]]) -> None:
    payload: dict[str, list[float | None]] = {}
    for (country, city), (lat, lon) in cache.items():
        payload[_cache_key(country, city)] = [lat, lon]
    CACHE_FILE.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _resolve_coordinates(
    country: str | None,
    city: str | None,
    cache: dict[tuple[str | None, str | None], tuple[float | None, float | None]],
) -> tuple[float | None, float | None]:
    if not country:
        return None, None

    country_code = country.strip().upper()
    key = (country_code, city.strip() if city else None)
    if key in cache:
        return cache[key]

    country_query = _country_query_value(country_code)
    country_name_key = _country_name_key(country_query)
    if city is None and country_name_key in cache:
        coords = cache[country_name_key]
        cache[key] = coords
        return coords
    query = ", ".join(part for part in [city, country_query] if part)
    coords = _geocode_query(query) if query else (None, None)
    if coords == (None, None) and city:
        country_key = (country_code, None)
        if country_key in cache:
            coords = cache[country_key]
        elif country_name_key in cache:
            coords = cache[country_name_key]
        else:
            coords = _geocode_query(country_query)
            cache[country_key] = coords
            cache[country_name_key] = coords

    if city is None:
        cache[country_name_key] = coords

    cache[key] = coords
    return coords


def _collect_geo_keys(rows: list[dict[str, object]]) -> list[tuple[str, str | None]]:
    unique_keys: set[tuple[str, str | None]] = set()
    for row in tqdm(rows, desc="Scanning geo keys", unit="row"):
        latitude = _get_value(row, ["latitude", "lat"])
        longitude = _get_value(row, ["longitude", "lon", "lng"])
        if latitude is not None and longitude is not None:
            continue

        country = _get_value(row, ["backend_resolver_country", "country", "country_code"])
        if not isinstance(country, str) or not country.strip():
            continue

        city = _get_value(row, ["city"])
        city_value = city.strip() if isinstance(city, str) and city.strip() else None
        unique_keys.add((country.strip().upper(), city_value))

    return sorted(unique_keys)


def load_resolver_lookup() -> dict[str, int]:
    dsn = build_dsn()
    lookup: dict[str, int] = {}
    with psycopg.connect(dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute(RESOLVER_LOOKUP_SQL)
            for resolver_id, ipv4, ipv6 in cursor.fetchall():
                ipv4_key = _normalize_key(ipv4)
                ipv6_key = _normalize_key(ipv6)
                if ipv4_key:
                    lookup[ipv4_key] = resolver_id
                if ipv6_key:
                    lookup[ipv6_key] = resolver_id
    return lookup


def load_rows(data_file: Path) -> list[dict[str, object]]:
    table = pq.read_table(data_file)
    rows = table.to_pylist()
    resolver_lookup = load_resolver_lookup()
    coord_cache = _load_cache()
    locations = _collect_geo_keys(rows)
    pbar = tqdm(locations, desc="Retrieving coordinates", unit="location")
    for country_code, city in pbar:
        if _cache_hit(country_code, city, coord_cache):
            pbar.set_description("Retrieving coordinates (Cache hit)")
            _resolve_coordinates(country_code, city, coord_cache)
            continue

        pbar.set_description("Retrieving coordinates")
        _resolve_coordinates(country_code, city, coord_cache)
        _save_cache(coord_cache)
        time.sleep(GEOCODE_MIN_DELAY_SECONDS)

    normalized: list[dict[str, object]] = []
    skipped = 0

    for row in tqdm(rows, desc="Loading anycast rows", unit="row"):
        resolver_ip = _get_value(row, ["replying_ip", "resolver_ipv4", "resolver_ip", "ipv4"])
        resolver_ip = _normalize_key(resolver_ip)
        if not resolver_ip:
            skipped += 1
            continue

        resolver_id = resolver_lookup.get(resolver_ip)
        if resolver_id is None:
            skipped += 1
            continue

        prefix = _get_value(row, ["backend_resolver_prefix", "prefix", "bgp_prefix"])
        prefix_ip, prefix_mask = _split_prefix(prefix if isinstance(prefix, str) else None)

        ipv4_site = _get_value(row, ["backend_resolver", "site_ipv4", "ipv4"])
        ipv6_site = _get_value(row, ["site_ipv6", "ipv6"])

        latitude = _get_value(row, ["latitude", "lat"])
        longitude = _get_value(row, ["longitude", "lon", "lng"])

        country = _get_value(row, ["backend_resolver_country", "country", "country_code"])
        city = _get_value(row, ["city"])

        if latitude is None or longitude is None:
            resolved_lat, resolved_lon = _resolve_coordinates(
                country if isinstance(country, str) else None,
                city if isinstance(city, str) else None,
                coord_cache,
            )
            _save_cache(coord_cache)
            if latitude is None:
                latitude = resolved_lat
            if longitude is None:
                longitude = resolved_lon

        row_data = {
            "resolver_id": resolver_id,
            "instance_id": row.get("instance_id"),
            "ipv4": _normalize_key(ipv4_site),
            "ipv6": _normalize_key(ipv6_site),
            "netmask": _get_value(row, ["netmask"]) or prefix_mask,
            "asn": _get_value(row, ["backend_resolver_asn", "asn", "ASN"]),
            "bgp_prefix": _get_value(row, ["bgp_prefix"]) or prefix_ip,
            "org": _get_value(row, ["backend_resolver_org", "org", "organization"]),
            "org_short": _get_value(row, ["org_short", "org_short_name"]),
            "country": country,
            "city": city,
            "latitude": latitude,
            "longitude": longitude,
            "last_observation_ts": _get_value(row, ["last_observation_ts", "timestamp_request", "last_seen"]) or datetime.now(timezone.utc),
            "source": _get_value(row, ["source"]) or "anycast-import",
        }

        normalized.append(row_data)

    if skipped:
        logger.warning("Skipped {count} rows without resolver_id match", count=skipped)

    return normalized

def insert_rows(rows: list[dict[str, object]]) -> None:
    if not rows:
        logger.info("No rows to insert")
        return

    dsn = build_dsn()
    with psycopg.connect(dsn) as connection:
        with connection.cursor() as cursor:
            # Get current max instance_id per resolver_id
            cursor.execute(
                "SELECT resolver_id, COALESCE(MAX(instance_id), 0) "
                "FROM anycast GROUP BY resolver_id"
            )
            counters = dict(cursor.fetchall())

        # Assign instance_id in Python
        for row in tqdm(rows, desc="Assigning instance_id", unit="row"):
            if row.get("instance_id") is None:
                rid = row["resolver_id"]
                counters[rid] = counters.get(rid, 0) + 1
                row["instance_id"] = counters[rid]

        placeholders = ", ".join([f"%({col})s" for col in ANYCAST_COLUMNS])
        columns = ", ".join(ANYCAST_COLUMNS)
        query = f"INSERT INTO anycast ({columns}) VALUES ({placeholders})"
        print(query)
        with connection.cursor() as cursor:
            cursor.executemany(query, rows)
        connection.commit()

    logger.info("Inserted {count} anycast rows", count=len(rows))

def main() -> None:
    load_dotenv()
    data_file = Path(os.getenv("ANYCAST_DATA_FILE", str(DATA_FILE)))
    logger.info("Loading anycast data from {path}", path=data_file)
    rows = load_rows(data_file)
    insert_rows(rows)


if __name__ == "__main__":
    main()
