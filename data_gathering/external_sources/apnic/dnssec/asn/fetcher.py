"""Fetch APNIC DNSSEC validation data and load dnssec_public_asn."""

from __future__ import annotations

import datetime as dt
from html import unescape
import json
from pathlib import Path
from queue import Queue
import re
import sys
from threading import Lock, Thread
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import polars as pl
import psycopg
import pycountry

from data_gathering.external_sources.config import external_data_dir
from data_gathering.tasks.apnic_dnssec.script_config import (
    required_config_int,
    required_config_value,
    script_logger,
)


CONFIG_KEY = "apnic_dnssec_fetcher.py"
logger = script_logger(CONFIG_KEY)

TASK_ROOT = Path(__file__).resolve().parent
OBSERVATORY_ROOT = TASK_ROOT.parents[4]

sys.path.insert(0, str(OBSERVATORY_ROOT / "db"))
from apply_schema import apply_schema, build_dsn


DNSSEC_COLUMNS = [
    "asn",
    "number_of_measurements",
    "validating",
    "validating_pc",
    "partial_validating",
    "partial_validating_pc",
    "last_observation_ts",
]
JS_ROW_RE = re.compile(
    r'\["<a\s+href=\\"[^"]*/dnssec/AS(?P<asn>\d+)\?[^"]*\\">AS\d+</a>"\s*,\s*"(?P<name>(?:\\.|[^"])*)"\s*,\s*(?P<validating>\{[^}]*\}|""|"[^"]*"|[^,]*?)\s*,\s*(?P<partial>\{[^}]*\}|""|"[^"]*"|[^,]*?)\s*,\s*(?P<samples>\d+)',
    re.IGNORECASE | re.DOTALL,
)
HTML_ARRAY_ROW_RE = re.compile(
    r'<a\s+href="[^"]*/dnssec/AS(?P<asn>\d+)\?[^"]*">AS\d+</a>"\s*,\s*"(?P<name>(?:\\.|[^"])*)"\s*,\s*(?P<validating>[^,]+)\s*,\s*(?P<partial>[^,]+)\s*,\s*(?P<samples>\d+)',
    re.IGNORECASE,
)
HTML_ROW_RE = re.compile(
    r"<tr[^>]*>\s*"
    r'<td[^>]*>\s*<a\s+href="[^"]*/dnssec/AS(?P<asn>\d+)[^"]*">AS\d+</a>\s*</td>\s*'
    r"<td[^>]*>(?P<name>.*?)</td>\s*"
    r"<td[^>]*>(?P<validating>.*?)</td>\s*"
    r"<td[^>]*>(?P<partial>.*?)</td>\s*"
    r"<td[^>]*>(?P<samples>.*?)</td>",
    re.IGNORECASE | re.DOTALL,
)
AS_HREF_RE = re.compile(r"/dnssec/AS(?P<asn>\d+)\?", re.IGNORECASE)
USER_AGENT = "dns-resilience-observatory-dnssec-fetcher"
HTTP_TIMEOUT_SECONDS = 30
QUEUE_SENTINEL = object()
MAX_ASN = 2_147_483_647


def _country_codes() -> list[str]:
    return sorted({country.alpha_2 for country in pycountry.countries})


def _fetch_text(url: str) -> str:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        return response.read().decode("utf-8", errors="replace")


def _parse_percent(value: str) -> float | None:
    text = re.sub(r"<[^>]+>", "", value).strip().strip('"')
    if text in ("", "0"):
        return 0.0 if text == "0" else None
    match = re.search(r"[-+]?\d+(?:\.\d+)?", text)
    return float(match.group(0)) if match else None


def _parse_int_text(value: str) -> int | None:
    text = re.sub(r"<[^>]+>", "", value).strip().replace(",", "")
    return int(text) if text.isdigit() else None


def _decode_js_string(value: str) -> str:
    try:
        return json.loads(f'"{value}"')
    except json.JSONDecodeError:
        return value.replace(r"\"", '"')


def _clean_html_text(value: str) -> str:
    return unescape(re.sub(r"<[^>]+>", "", value).strip())


def _parse_asn(value: object) -> int | None:
    try:
        asn = int(str(value).removeprefix("AS"))
    except (TypeError, ValueError):
        return None
    if asn < 0 or asn > MAX_ASN:
        logger.warning("DNSSEC: skipping ASN outside PostgreSQL INTEGER range: {}", value)
        return None
    return asn


def _parse_as_rows(country_code: str, html: str) -> list[dict[str, object]]:
    rows_by_asn: dict[int, dict[str, object]] = {}
    for match in JS_ROW_RE.finditer(html):
        asn = _parse_asn(match.group("asn"))
        if asn is None:
            continue
        rows_by_asn[asn] = {
            "asn": asn,
            "as_name": unescape(_decode_js_string(match.group("name"))),
        }
    for match in HTML_ARRAY_ROW_RE.finditer(html):
        asn = _parse_asn(match.group("asn"))
        if asn is None:
            continue
        rows_by_asn.setdefault(
            asn,
            {
                "asn": asn,
                "as_name": unescape(_decode_js_string(match.group("name"))),
            },
        )
    for match in HTML_ROW_RE.finditer(html):
        asn = _parse_asn(match.group("asn"))
        if asn is None:
            continue
        rows_by_asn.setdefault(
            asn,
            {
                "asn": asn,
                "as_name": _clean_html_text(match.group("name")),
            },
        )
    for match in AS_HREF_RE.finditer(html):
        asn = _parse_asn(match.group("asn"))
        if asn is None:
            continue
        rows_by_asn.setdefault(
            asn,
            {
                "asn": asn,
                "as_name": None,
            },
        )
    return list(rows_by_asn.values())


def discover_country_ases(country_code: str, base_url: str) -> list[dict[str, object]]:
    # Scrape country page AS links, avoiding ASN brute force.
    url = f"{base_url.rstrip('/')}/{country_code}"
    try:
        html = _fetch_text(url)
    except (HTTPError, URLError, TimeoutError) as exc:
        logger.warning("DNSSEC: failed to fetch country AS list {}: {}", url, exc)
        return []

    rows = _parse_as_rows(country_code, html)
    logger.info("DNSSEC: discovered {} AS rows for {}", len(rows), country_code)
    return rows


def _json_url(json_url: str, asn: int) -> str:
    return f"{json_url}?{urlencode({'x': str(asn)})}"


def _parse_measurement_timestamp(value: object | None) -> dt.datetime | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return dt.datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def _metric_value(metric: dict[str, object], key: str) -> object | None:
    value = metric.get(key)
    return value if value != "" else None


def _flatten_json_row(row: dict[str, object], metadata: dict[str, object]) -> dict[str, object]:
    asn_text = str(row.get("as") or f"AS{metadata['asn']}")
    asn = _parse_asn(asn_text)
    if asn is None:
        raise ValueError(f"Invalid APNIC ASN value: {asn_text!r}")
    metric = row.get("30_day") if isinstance(row.get("30_day"), dict) else {}
    return {
        "asn": asn,
        "number_of_measurements": _metric_value(metric, "seen"),
        "validating": _metric_value(metric, "validating"),
        "validating_pc": _metric_value(metric, "validating_pc"),
        "partial_validating": _metric_value(metric, "partial_validating"),
        "partial_validating_pc": _metric_value(metric, "partial_validating_pc"),
        "last_observation_ts": _parse_measurement_timestamp(row.get("date")),
    }


def fetch_as_json(metadata: dict[str, object], json_url: str) -> dict[str, object] | None:
    # Download country-independent APNIC time series and keep latest 30-day metrics.
    asn = _parse_asn(metadata["asn"])
    if asn is None:
        return None
    url = _json_url(json_url, asn)
    try:
        payload = json.loads(_fetch_text(url))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        logger.warning("DNSSEC: failed to fetch JSON {}: {}", url, exc)
        return None

    data = payload.get("data", [])
    if not isinstance(data, list):
        logger.warning("DNSSEC: unexpected JSON data shape for {}", url)
        return None
    rows = [row for row in data if isinstance(row, dict) and row.get("date")]
    if not rows:
        return None
    latest = max(rows, key=lambda row: str(row.get("date")))
    flattened = _flatten_json_row(latest, metadata)
    if flattened["last_observation_ts"] is None:
        logger.warning("DNSSEC: skipping AS{} without parseable measurement date", asn)
        return None
    return flattened


def _stage_columns_sql() -> str:
    return """
        asn INTEGER NOT NULL,
        number_of_measurements INTEGER,
        validating INTEGER,
        validating_pc DOUBLE PRECISION,
        partial_validating INTEGER,
        partial_validating_pc DOUBLE PRECISION,
        last_observation_ts TIMESTAMPTZ NOT NULL
    """


def _upsert_dnssec_rows(connection: psycopg.Connection, rows: list[dict[str, object]]) -> int:
    if not rows:
        return 0
    with connection.cursor() as cursor:
        # Stage a batch and upsert immediately.
        cursor.execute("DROP TABLE IF EXISTS dnssec_public_asn_stage")
        cursor.execute(f"CREATE TEMP TABLE dnssec_public_asn_stage ({_stage_columns_sql()}) ON COMMIT DROP")
        with cursor.copy("COPY dnssec_public_asn_stage (" + ", ".join(DNSSEC_COLUMNS) + ") FROM STDIN") as copy:
            for row in rows:
                copy.write_row([row[column] for column in DNSSEC_COLUMNS])

        cursor.execute(
            """
            INSERT INTO dnssec_public_asn (
                asn, number_of_measurements, validating, validating_pc,
                partial_validating, partial_validating_pc, last_observation_ts
            )
            SELECT
                asn, number_of_measurements, validating, validating_pc,
                partial_validating, partial_validating_pc, last_observation_ts
            FROM dnssec_public_asn_stage
            ON CONFLICT (asn)
            DO UPDATE SET
                number_of_measurements = EXCLUDED.number_of_measurements,
                validating = EXCLUDED.validating,
                validating_pc = EXCLUDED.validating_pc,
                partial_validating = EXCLUDED.partial_validating,
                partial_validating_pc = EXCLUDED.partial_validating_pc,
                last_observation_ts = EXCLUDED.last_observation_ts
            """
        )
        affected = cursor.rowcount
        cursor.execute("DROP TABLE dnssec_public_asn_stage")
    connection.commit()
    return affected


def _country_worker(country_queue: Queue, as_queue: Queue, base_url: str, seen_asns: set[int], seen_lock: Lock) -> None:
    while True:
        country_code = country_queue.get()
        try:
            if country_code is QUEUE_SENTINEL:
                return
            for metadata in discover_country_ases(str(country_code), base_url):
                asn = _parse_asn(metadata["asn"])
                if asn is None:
                    continue
                with seen_lock:
                    if asn in seen_asns:
                        continue
                    seen_asns.add(asn)
                metadata["asn"] = asn
                as_queue.put(metadata)
        finally:
            country_queue.task_done()


def _stats_worker(as_queue: Queue, row_queue: Queue, json_url: str) -> None:
    while True:
        metadata = as_queue.get()
        try:
            if metadata is QUEUE_SENTINEL:
                return
            row = fetch_as_json(metadata, json_url)
            if row is not None:
                row_queue.put(row)
        finally:
            as_queue.task_done()


def _insert_worker(row_queue: Queue, inserted_rows: list[dict[str, object]], counters: dict[str, int], batch_size: int) -> None:
    dsn = build_dsn()
    batch: list[dict[str, object]] = []
    try:
        with psycopg.connect(dsn) as connection:
            while True:
                row = row_queue.get()
                try:
                    if row is QUEUE_SENTINEL:
                        if batch:
                            _upsert_dnssec_rows(connection, batch)
                            counters["inserted"] += len(batch)
                            inserted_rows.extend(batch)
                        return
                    batch.append(row)
                    if len(batch) >= batch_size:
                        _upsert_dnssec_rows(connection, batch)
                        counters["inserted"] += len(batch)
                        inserted_rows.extend(batch)
                        logger.info("DNSSEC: inserted {} rows so far", counters["inserted"])
                        batch = []
                finally:
                    row_queue.task_done()
    except Exception as exc:
        counters["error"] = exc
        logger.exception("DNSSEC: insert worker failed")


def fetch(*, output_dir: Path | None = None) -> tuple[Path, int]:
    output_dir = output_dir or external_data_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    base_url = required_config_value(CONFIG_KEY, "apnic_dnssec_base_url")
    json_url = required_config_value(CONFIG_KEY, "apnic_dnssec_json_url")
    country_workers = required_config_int(CONFIG_KEY, "apnic_dnssec_country_workers")
    stats_workers = required_config_int(CONFIG_KEY, "apnic_dnssec_stats_workers")
    batch_size = required_config_int(CONFIG_KEY, "apnic_dnssec_insert_batch_size")

    apply_schema()

    # Run discovery, stats fetch, and DB insert concurrently.
    country_queue: Queue = Queue()
    as_queue: Queue = Queue(maxsize=stats_workers * 20)
    row_queue: Queue = Queue(maxsize=batch_size * 4)
    inserted_rows: list[dict[str, object]] = []
    counters = {"inserted": 0}
    seen_asns: set[int] = set()
    seen_lock = Lock()

    country_threads = [
        Thread(target=_country_worker, args=(country_queue, as_queue, base_url, seen_asns, seen_lock), daemon=True)
        for _ in range(country_workers)
    ]
    stats_threads = [
        Thread(target=_stats_worker, args=(as_queue, row_queue, json_url), daemon=True)
        for _ in range(stats_workers)
    ]
    insert_thread = Thread(target=_insert_worker, args=(row_queue, inserted_rows, counters, batch_size), daemon=True)

    for thread in [*country_threads, *stats_threads, insert_thread]:
        thread.start()
    for country_code in _country_codes():
        country_queue.put(country_code)
    for _ in country_threads:
        country_queue.put(QUEUE_SENTINEL)

    country_queue.join()
    logger.info("DNSSEC: country discovery complete; unique ASNs queued={}", len(seen_asns))
    for _ in stats_threads:
        as_queue.put(QUEUE_SENTINEL)
    as_queue.join()
    logger.info("DNSSEC: AS stats fetch complete")
    row_queue.put(QUEUE_SENTINEL)
    insert_thread.join()
    if "error" in counters:
        raise counters["error"]

    if not inserted_rows:
        raise RuntimeError("DNSSEC: no APNIC DNSSEC rows fetched")

    today = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    output_path = output_dir / f"apnic-dnssec-public-asn-{today}.pq"
    tmp_path = output_path.with_suffix(".tmp")
    pl.DataFrame(inserted_rows).select(DNSSEC_COLUMNS).write_parquet(tmp_path)
    tmp_path.replace(output_path)
    logger.info("DNSSEC: wrote {} rows to {}", len(inserted_rows), output_path)
    return output_path, counters["inserted"]


def load_dnssec_public(parquet_path: Path) -> int:
    apply_schema()
    rows = pl.read_parquet(parquet_path).select(DNSSEC_COLUMNS).to_dicts()
    if not rows:
        logger.info("DNSSEC: no rows to load from {}", parquet_path)
        return 0
    dsn = build_dsn()
    with psycopg.connect(dsn) as connection:
        affected = _upsert_dnssec_rows(connection, rows)
    logger.info("DNSSEC: applied upsert for {} parquet rows; affected={}", len(rows), affected)
    return len(rows)
