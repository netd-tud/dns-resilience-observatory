"""Load ODNS API parquet data into the resolver table."""

from __future__ import annotations

import ipaddress
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg

import polars as pl 
from data_gathering.tasks.odns_v4.script_config import required_config_value, script_logger

logger = script_logger(__file__)

TASK_ROOT = Path(__file__).resolve().parent
OBSERVATORY_ROOT = TASK_ROOT.parents[2]

sys.path.insert(0, str(OBSERVATORY_ROOT / "db"))
from apply_schema import build_dsn

RESOLVER_COLUMNS = [
    "ipv4",
    "ipv6",
    "asn",
    "bgp_prefix",
    "org",
    "org_short",
    "country",
    "city",
    "latitude",
    "longitude",
    "is_public",
    "supported_protocols",
    "last_observation_ts",
    "source",
]


def _latest_parquet(data_dir: Path,pattern: str) -> Path | None:
    #e.g. pattern = f"odns_*.parquet"
    candidates = sorted(data_dir.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def _normalize_timestamp(value: object) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.astimezone(timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _fetch_existing_ids(
    connection: psycopg.Connection,
    ipv4s: list[str],
    ipv6s: list[str],
) -> dict[str, int]:
    if not ipv4s and not ipv6s:
        return {}

    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT id, ipv4, ipv6 FROM resolver "
            "WHERE (ipv4 = ANY(%s) AND ipv4 IS NOT NULL) "
            "OR (ipv6 = ANY(%s) AND ipv6 IS NOT NULL)",
            (ipv4s, ipv6s),
        )
        rows = cursor.fetchall()

    lookup: dict[str, int] = {}
    for resolver_id, ipv4, ipv6 in rows:
        if ipv4:
            lookup[ipv4] = resolver_id
        if ipv6:
            lookup[ipv6] = resolver_id
    return lookup


def _upsert_resolvers(rows: list[dict[str, object]]) -> None:
    if not rows:
        logger.info("No resolver rows to upsert")
        return

    dsn = build_dsn()
    with psycopg.connect(dsn) as connection:
        ipv4s = sorted({row.get("ipv4") for row in rows if row.get("ipv4")})
        ipv6s = sorted({row.get("ipv6") for row in rows if row.get("ipv6")})
        existing = _fetch_existing_ids(connection, ipv4s, ipv6s)

        update_rows: list[dict[str, object]] = []
        insert_rows: list[dict[str, object]] = []
        for row in rows:
            resolver_id = None
            ipv4 = row.get("ipv4")
            ipv6 = row.get("ipv6")
            if ipv4:
                resolver_id = existing.get(ipv4)
            if resolver_id is None and ipv6:
                resolver_id = existing.get(ipv6)

            if resolver_id is None:
                insert_rows.append(row)
            else:
                row["id"] = resolver_id
                update_rows.append(row)

        update_query = (
            "UPDATE resolver SET "
            "ipv4 = COALESCE(%(ipv4)s, ipv4), "
            "ipv6 = COALESCE(%(ipv6)s, ipv6), "
            "asn = COALESCE(%(asn)s, asn), "
            "bgp_prefix = COALESCE(%(bgp_prefix)s, bgp_prefix), "
            "org = COALESCE(%(org)s, org), "
            "org_short = COALESCE(%(org_short)s, org_short), "
            "country = COALESCE(%(country)s, country), "
            "city = COALESCE(%(city)s, city), "
            "latitude = COALESCE(%(latitude)s, latitude), "
            "longitude = COALESCE(%(longitude)s, longitude), "
            "is_public = COALESCE(%(is_public)s, is_public), "
            "supported_protocols = COALESCE(%(supported_protocols)s, supported_protocols), "
            "last_observation_ts = GREATEST(last_observation_ts, COALESCE(%(last_observation_ts)s, last_observation_ts)), "
            "source = COALESCE(%(source)s, source) "
            "WHERE id = %(id)s"
        )

        insert_placeholders = ", ".join([f"%({col})s" for col in RESOLVER_COLUMNS])
        insert_columns = ", ".join(RESOLVER_COLUMNS)
        insert_query = f"INSERT INTO resolver ({insert_columns}) VALUES ({insert_placeholders})"

        with connection.cursor() as cursor:
            if update_rows:
                cursor.executemany(update_query, update_rows)
            if insert_rows:
                cursor.executemany(insert_query, insert_rows)
        connection.commit()

    logger.info(
        "Applied ODNS resolver updates: {updated} updated, {inserted} inserted",
        updated=len(update_rows),
        inserted=len(insert_rows),
    )

def ipv4_to_int_expr(col: pl.Expr) -> pl.Expr:
    octets = col.str.split(".").list.eval(pl.element().cast(pl.UInt64))
    return (
        octets.list.get(0) * 16777216
        + octets.list.get(1) * 65536
        + octets.list.get(2) * 256
        + octets.list.get(3)
    )

def load_resolver_df(odns: Path, anycast: Path) -> list[dict[str, object]]:
    df_odns = pl.read_parquet(odns)
    anycast = pl.read_parquet(anycast)
    # Perform any necessary data processing or merging here
    # We recommend filtering on (AB > 3) || (GCD > 1) when high confidence is needed
    ab_cols = [c for c in anycast.columns if c.startswith('AB_')]
    gcd_cols = [c for c in anycast.columns if c.startswith('GCD_')]
    ab_any = pl.any_horizontal([pl.col(c) > 3 for c in ab_cols])
    gcd_any = pl.any_horizontal([pl.col(c) > 1 for c in gcd_cols])
    anycast_hc = anycast.filter(ab_any & gcd_any)

    prefix_parts = pl.col("prefix").str.split("/")
    prefix_ip = prefix_parts.list.first()
    prefix_len = prefix_parts.list.last().cast(pl.UInt64)

    ranges = (
        anycast_hc
        .select([
            ipv4_to_int_expr(prefix_ip).alias("net"),
            prefix_len.alias("prefix_len"),
        ])
        .with_columns(
            (pl.lit(2, dtype=pl.UInt64) ** (32 - pl.col("prefix_len"))).alias("block_size")
        )
        .with_columns([
            ((pl.col("net") // pl.col("block_size")) * pl.col("block_size")).alias("start"),
            (((pl.col("net") // pl.col("block_size")) * pl.col("block_size")) + pl.col("block_size") - 1).alias("end"),
        ])
        .select(["start", "end"])
        .unique()
    )

    ip_cols = []
    for c in df_odns.columns:
        if c == "queried_ip":
            ip_cols.append(c)
            continue
        if c.startswith("queried_ip_") and c[len("queried_ip_"):].isdigit():
            ip_cols.append(c)

    df_odns = df_odns.with_row_index("row_id")
    for col in ip_cols:
        ip_int_col = f"{col}__int"
        match_col = f"{col}__anycast"
        matches = (
            df_odns
            .lazy()
            .select(["row_id", col])
            .with_columns(ipv4_to_int_expr(pl.col(col).cast(pl.String)).alias(ip_int_col))
            .join_where(
                ranges.lazy(),
                (pl.col(ip_int_col) >= pl.col("start")) & (pl.col(ip_int_col) <= pl.col("end")),
            )
            .group_by("row_id")
            .agg(pl.col("start").is_not_null().any().alias(match_col))
            .collect()
        )
        df_odns = df_odns.join(matches, on="row_id", how="left")

    df_odns = (
        df_odns
        .drop("row_id")
        .with_columns(pl.any_horizontal([pl.col(f"{c}__anycast") for c in ip_cols]).alias("anycast_supported"))
    )
    all_resolver = (
        df_odns
        .filter((pl.col('resolver_type')=='Resolver') | ((pl.col('resolver_type')=='Forwarder') & pl.col('anycast_supported')))
        .rename({'queried_ip':'ipv4','queried_ip_asn':'asn','queried_ip_prefix':'bgp_prefix',
                 'queried_ip_org':'org','queried_ip_country':'country','timestamp_request':'last_observation_ts','protocol':'supported_protocols'})
        .select('ipv4','asn','bgp_prefix','org','country','last_observation_ts','supported_protocols')
        .group_by('ipv4')
        .agg(
            pl.col('asn', 'bgp_prefix', 'org', 'country').first(),
            pl.col('last_observation_ts').max(),
            pl.col('supported_protocols').flatten().drop_nulls().unique(),
        )
    )
    
    forwarder_only = df_odns.filter(
        (pl.col("resolver_type") == "Forwarder")
        & (~pl.col("replying_ip").is_in(all_resolver["ipv4"]))
        & (~pl.col("backend_resolver").is_in(all_resolver["ipv4"]))
    )
    tfwd_only = df_odns.filter(
        (pl.col("resolver_type") == "Transparent Forwarder")
        & (~pl.col("replying_ip").is_in(all_resolver["ipv4"]))
        & (~pl.col("backend_resolver").is_in(all_resolver["ipv4"]))
    )

    closed_resolver = pl.concat([forwarder_only.rename({'backend_resolver':'ipv4','backend_resolver_asn':'asn','backend_resolver_prefix':'bgp_prefix',
                        'backend_resolver_org':'org','backend_resolver_country':'country','timestamp_request':'last_observation_ts','protocol':'supported_protocols'})
                        .select('ipv4','asn','bgp_prefix','org','country','last_observation_ts','supported_protocols')
                        .group_by('ipv4')
                        .agg(
                            pl.col('asn', 'bgp_prefix', 'org', 'country').first(),
                            pl.col('last_observation_ts').max(),
                            pl.col('supported_protocols').flatten().drop_nulls().unique(),
                        ),
                        tfwd_only.rename({'replying_ip':'ipv4','replying_ip_asn':'asn','replying_ip_prefix':'bgp_prefix',
                        'replying_ip_org':'org','replying_ip_country':'country','timestamp_request':'last_observation_ts','protocol':'supported_protocols'})
                        .select('ipv4','asn','bgp_prefix','org','country','last_observation_ts','supported_protocols')
                        .group_by('ipv4')
                        .agg(
                            pl.col('asn', 'bgp_prefix', 'org', 'country').first(),
                            pl.col('last_observation_ts').max(),
                            pl.col('supported_protocols').flatten().drop_nulls().unique(),
                        )])
    all_resolver = all_resolver.with_columns(pl.lit(True).alias("is_public"))
    closed_resolver = closed_resolver.with_columns(pl.lit(False).alias("is_public"))
    combined = pl.concat([all_resolver, closed_resolver], how="vertical").cast({"org": pl.Utf8})
    combined = combined.with_columns(
        pl.col("org").str.extract(r"^([A-Za-z0-9]+)", 1).alias("org_short")
    )
    
    return [
        {
            "ipv4": row["ipv4"],
            "ipv6": None,
            "asn": row["asn"],
            "bgp_prefix": row["bgp_prefix"],
            "org": row["org"],
            "org_short": row["org_short"],
            "country": row["country"],
            "city": None,
            "latitude": None,
            "longitude": None,
            "is_public": row["is_public"],
            "supported_protocols": row["supported_protocols"],
            "last_observation_ts": _normalize_timestamp(row["last_observation_ts"]),
            "source": "odns-api",
        }
        for row in combined.to_dicts()
    ]


def load_odns_api(
    *,
    data_dir: Path | None = None,
    protocol: str | None = None,
    input_path: Path | None = None,
) -> None:
    data_dir = data_dir or Path(required_config_value(__file__, "data_dir")) / "external"
    protocol = protocol or required_config_value(__file__, "odns_default_protocol")
    odns_path = input_path or _latest_parquet(data_dir, "odns_*.pq")
    anycast_path = input_path or (
        _latest_parquet(data_dir, "manycast-*.pq")
        or _latest_parquet(data_dir, "manycast_*.pq")
    )
    if odns_path is None:
        raise FileNotFoundError(f"No ODNS parquet file found in {data_dir}")
    if anycast_path is None:
        raise FileNotFoundError(f"No Manycast parquet file found in {data_dir}")

    logger.info("Loading ODNS {protocol} parquet from {path}", protocol=protocol, path=odns_path)
    rows = load_resolver_df(odns_path,anycast_path)
    _upsert_resolvers(rows)
