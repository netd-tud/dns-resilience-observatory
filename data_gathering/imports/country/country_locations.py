"""Country normalization and country_location maintenance."""

from __future__ import annotations

from functools import lru_cache
import json
import re
import time
import urllib.parse
import urllib.request

import psycopg
import pycountry


NOMINATIM_URL = "https://nominatim.openstreetmap.org/search"
GEOCODE_USER_AGENT = "dns-resilience-observatory-country-location"
GEOCODE_MIN_DELAY_SECONDS = 1
GEOCODE_TIMEOUT_SECONDS = 5
UNKNOWN_COUNTRY_VALUES = {"***"}


def _clean_country_query(value: str) -> str:
    without_parentheses = re.sub(r"\s*\([^)]*\)", "", value)
    return " ".join(without_parentheses.split())


def normalize_country(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip().upper()
    if not text or text in UNKNOWN_COUNTRY_VALUES:
        return None
    if len(text) == 2:
        entry = pycountry.countries.get(alpha_2=text)
        return entry.alpha_3 if entry else text
    if len(text) == 3:
        entry = pycountry.countries.get(alpha_3=text)
        return entry.alpha_3 if entry else text
    entry = pycountry.countries.get(name=str(value).strip())
    return entry.alpha_3 if entry else text


def country_query_value(country: str) -> str:
    trimmed = country.strip().upper()
    if len(trimmed) == 3:
        entry = pycountry.countries.get(alpha_3=trimmed)
    elif len(trimmed) == 2:
        entry = pycountry.countries.get(alpha_2=trimmed)
    else:
        entry = pycountry.countries.get(name=country.strip())
    if entry and "," in entry.name:
        return _clean_country_query(entry.name.split(",", 1)[0])
    return _clean_country_query(entry.name if entry else country.strip())


@lru_cache(maxsize=512)
def geocode_country(country: str) -> tuple[float, float]:
    query = country_query_value(country)
    params = urllib.parse.urlencode({"q": query, "format": "json", "limit": 1})
    url = f"{NOMINATIM_URL}?{params}"
    request = urllib.request.Request(url, headers={"User-Agent": GEOCODE_USER_AGENT})
    with urllib.request.urlopen(request, timeout=GEOCODE_TIMEOUT_SECONDS) as response:
        data = json.loads(response.read().decode())
        if data:
            return float(data[0]["lat"]), float(data[0]["lon"])

    raise ValueError(f"Country geocoding returned no coordinates for {country} -- {query}")


def ensure_country_locations(
    connection: psycopg.Connection,
    countries: set[str],
    logger: object,
) -> None:
    normalized_countries = sorted(
        country
        for country in {normalize_country(country) for country in countries}
        if country is not None
    )
    if not normalized_countries:
        return

    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT country, latitude, longitude FROM country_location WHERE country = ANY(%s)",
            (normalized_countries,),
        )
        existing_with_coordinates = {
            row[0]
            for row in cursor.fetchall()
            if row[1] is not None and row[2] is not None
        }

        missing = [country for country in normalized_countries if country not in existing_with_coordinates]
        for country in missing:
            latitude, longitude = geocode_country(country)
            cursor.execute(
                """
                INSERT INTO country_location (country, latitude, longitude)
                VALUES (%s, %s, %s)
                ON CONFLICT (country) DO UPDATE SET
                    latitude = COALESCE(country_location.latitude, EXCLUDED.latitude),
                    longitude = COALESCE(country_location.longitude, EXCLUDED.longitude)
                """,
                (country, latitude, longitude),
            )
            time.sleep(GEOCODE_MIN_DELAY_SECONDS)

    if missing:
        logger.info("Inserted {count} missing country coordinate rows", count=len(missing))
