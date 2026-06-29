"""Prepare ODNS API parquet data and import resolver records."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from pathlib import Path

import polars as pl 
from data_gathering.external_sources.config import external_data_dir
from data_gathering.imports.anycast.import_anycast import import_anycast
from data_gathering.imports.forwarder.import_forwarders import import_forwarders
from data_gathering.imports.resolver.import_resolvers import import_resolvers
from data_gathering.imports.spoofing.import_spoofing import import_spoofing
from data_gathering.imports.country.country_locations import normalize_country
from data_gathering.tasks.odns_v4.script_config import required_config_value, script_logger

logger = script_logger(__file__)

TASK_ROOT = Path(__file__).resolve().parent
OBSERVATORY_ROOT = TASK_ROOT.parents[2]
DATA_DIR = OBSERVATORY_ROOT / "data"

RESOLVER_OUTPUT_COLUMNS = [
    "ipv4",
    "asn",
    "bgp_prefix",
    "org",
    "country",
    "is_public",
    "protocol",
    "supported_protocols",
    "last_update_ts",
    "source",
]

FORWARDER_OUTPUT_COLUMNS = [
    "ip",
    "resolver",
    "resolver_id",
    "type",
    "is_public",
    "supported_protocols",
    "asn",
    "bgp_prefix",
    "org",
    "org_short",
    "country",
    "last_update_ts",
    "source",
]

RESOLVER_IMPORT_MAPPING = (
    "ip:ipv4,"
    "is_public:is_public,"
    "source:source,"
    "last_update_ts:last_update_ts,"
    "asn:asn,"
    "prefix:bgp_prefix,"
    "org:org,"
    "country:country,"
    "protocol:protocol"
)
RESOLVER_IMPORT_MODULES = "resolver,asn,org,prefix,location,protocol"
FORWARDER_IMPORT_MAPPING = (
    "ip:ip,"
    "is_public:is_public,"
    "source:source,"
    "last_update_ts:last_update_ts,"
    "asn:asn,"
    "prefix:bgp_prefix,"
    "org:org,"
    "country:country,"
    "type:type,"
    "protocol:supported_protocols,"
    "upstream_ip:resolver"
)
FORWARDER_IMPORT_MODULES = "forwarder,asn,org,prefix,location,protocol,upstream"
ODNS_SOURCE = "odns-api"


def _write_parquet(
    rows: list[dict[str, object]],
    path: Path,
    columns: list[str],
    rename: dict[str, str] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    frame = pl.DataFrame(rows) if rows else pl.DataFrame({column: [] for column in columns})
    if rename and rows:
        frame = frame.rename({old: new for old, new in rename.items() if old in frame.columns})
    frame = frame.select([column for column in columns if column in frame.columns])
    frame.write_parquet(path)
    logger.info("Wrote {count} rows to {path}", count=frame.height, path=path)


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


def _normalize_ip(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return str(ipaddress.ip_address(text))


def _supported_protocols_to_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        return ",".join(str(item) for item in value if item is not None)
    return str(value)


def ipv4_to_int_expr(col: pl.Expr) -> pl.Expr:
    octets = col.str.split(".").list.eval(pl.element().cast(pl.UInt64))
    return (
        octets.list.get(0) * 16777216
        + octets.list.get(1) * 65536
        + octets.list.get(2) * 256
        + octets.list.get(3)
    )

def load_odns_data(
    odns: Path,
    anycast: Path,
) -> tuple[list[dict[str, object]], list[dict[str, object]], pl.DataFrame, pl.DataFrame, pl.DataFrame]:
    df_odns = pl.read_parquet(odns)
    df_odns = df_odns.with_columns(
        pl.col("timestamp_request")
        .fill_null(pl.col("timestamp_request").min())
        .alias("timestamp_request")
    )
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
            "prefix",
        ])
        .with_columns(
            (pl.lit(2, dtype=pl.UInt64) ** (32 - pl.col("prefix_len"))).alias("block_size")
        )
        .with_columns([
            ((pl.col("net") // pl.col("block_size")) * pl.col("block_size")).alias("start"),
            (((pl.col("net") // pl.col("block_size")) * pl.col("block_size")) + pl.col("block_size") - 1).alias("end"),
        ])
        .select(["start", "end","prefix"])
        .unique()
    )
    ip_cols = []
    for c in df_odns.columns:
        if c == "queried_ip":
            ip_cols.append(c)
        elif c == "replying_ip":
            ip_cols.append(c)
        elif c.startswith("queried_ip_") and c[len("queried_ip_"):].isdigit():
            ip_cols.append(c)
        elif c.startswith("replying_ip_") and c[len("replying_ip_"):].isdigit():
            ip_cols.append(c)
        else:
            continue
    df_odns = df_odns.with_row_index("row_id")
    for col in ip_cols:
        ip_int_col = f"{col}__int"
        match_col = f"{col}__anycast"
        prefix_col = f"{col}_anycast_prefix"
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
            .agg([
                pl.col("start").is_not_null().any().alias(match_col),
                pl.col("prefix").first().alias(prefix_col),
            ])
            .collect()
        )
        df_odns = df_odns.join(matches, on="row_id", how="left")

    df_odns = df_odns.drop("row_id")
    for c in ip_cols:
        df_odns = (
            df_odns
            .with_columns(pl.any_horizontal(pl.col(f"{c}__anycast")).alias(f"{c}_anycast_supported"))
        )
    public_resolver = (
        df_odns
        .filter((pl.col('resolver_type')=='Resolver') | ((pl.col('resolver_type')=='Forwarder') & pl.col('queried_ip_anycast_supported')))
        .rename({'queried_ip':'ipv4','queried_ip_asn':'asn','queried_ip_prefix':'bgp_prefix',
                 'queried_ip_org':'org','queried_ip_country':'country','timestamp_request':'last_update_ts','protocol':'supported_protocols'})
        .select('ipv4','asn','bgp_prefix','org','country','last_update_ts','supported_protocols')
        .group_by('ipv4')
        .agg(
            pl.col('asn', 'bgp_prefix', 'org', 'country').first(),
            pl.col('last_update_ts').max(),
            pl.col('supported_protocols').explode().drop_nulls().unique(),
        )
    )

    tfwd_anycast_country = df_odns.filter(
        (pl.col("resolver_type") == "Transparent Forwarder")
        & (pl.col("replying_ip_anycast_supported"))
    ).group_by("replying_ip_anycast_prefix","queried_ip_country").agg(
        pl.col('backend_resolver').n_unique().alias("country_count"),
    ).filter(pl.col("queried_ip_country").is_not_null()).rename({
        "replying_ip_anycast_prefix": "prefix",
        "queried_ip_country": "country",
    })

    tfwd_anycast_asn = df_odns.filter(
        (pl.col("resolver_type") == "Transparent Forwarder")
        & (pl.col("replying_ip_anycast_supported"))
    ).group_by("replying_ip_anycast_prefix","queried_ip_asn").agg(
        pl.col('backend_resolver').n_unique().alias("asn_count"),
    ).filter(pl.col("queried_ip_asn").is_not_null()).rename({
        "replying_ip_anycast_prefix": "prefix",
        "queried_ip_asn": "asn",
    })

    tfwd_spoofing = df_odns.filter(
        (pl.col("resolver_type") == "Transparent Forwarder")
        & (pl.col("replying_ip_anycast_supported"))
    ).select("queried_ip","queried_ip_asn","queried_ip_country", "timestamp_request").with_columns(
        pl.col("queried_ip").str.replace(r"\.\d+$", ".0/24").alias("prefix")
    ).group_by("prefix").agg(
        pl.col("timestamp_request").max().dt.replace_time_zone("UTC").alias("last_update_ts"),
        pl.col("queried_ip_asn").first().alias("asn"),
        pl.col("queried_ip_country").first().alias("country"),
        pl.lit(None, dtype=pl.Boolean).alias("nat"),
        pl.lit("unknown").alias("privatespoof"),
        pl.lit("received").alias("routedspoof")
    )

    forwarder_only = df_odns.filter(
        (pl.col("resolver_type") == "Forwarder")
        & (~pl.col("replying_ip").is_in(public_resolver["ipv4"]))
        & (~pl.col("backend_resolver").is_in(public_resolver["ipv4"]))
    )
    #transparent forwarder interesting for closed resolver
    #if replying_ip is forwarder and backend_resolver is not in public_resolver list
    #or
    #if replying_ip is not in forwarder list and not in public resolver list and replying_ip does not support anycast
    tfwd_closed_backend_resolver = df_odns.filter(
        # Replying IP is a public forwarder (not anycast resolver)
        # or the replying IP is not a public forwarder
        # and the backend resolver is not in the public resolver list
        # then the backend_resolver is a closed resolver
        (pl.col("resolver_type") == "Transparent Forwarder")
        & (
                (pl.col("replying_ip").is_in(
                df_odns.filter(
                    (pl.col("resolver_type") == "Forwarder") &
                    (pl.col('replying_ip_anycast_supported').is_null() | ~pl.col("queried_ip_anycast_supported"))
                    )["queried_ip"])) &
            ~pl.col("backend_resolver").is_in(public_resolver["ipv4"])
        )
        | 
        # Replying IP is not a public forwarder and also not a public resolver
        # and the backend IP is not a public resolver and also not a public forwarder
        # then the backend IP is a closed resolver
        (
            ~pl.col("replying_ip").is_in(df_odns.filter(pl.col("resolver_type") == "Forwarder")["queried_ip"]) &
            ~pl.col("replying_ip").is_in(public_resolver["ipv4"]) &
            ~pl.col("backend_resolver").is_in(public_resolver["ipv4"]) &
            ~pl.col("backend_resolver").is_in(df_odns.filter(pl.col("resolver_type") == "Forwarder")["queried_ip"])
        )
    )
    
    tfwd_closed_replying_resolver = df_odns.filter(
        # Replying IP is not a public resolver and also not a public forwarder
        # and anycast supported then replying IP is a closed resolver
        (pl.col("resolver_type") == "Transparent Forwarder")
        & 
        (
            ~pl.col("replying_ip").is_in(df_odns.filter(pl.col("resolver_type") == "Forwarder")["queried_ip"]) &
            ~pl.col("replying_ip").is_in(public_resolver["ipv4"]) &
            pl.col("replying_ip_anycast_supported")
        )
    )

    closed_resolver = (
        pl.concat([
        forwarder_only
        .rename({'backend_resolver':'ipv4','backend_resolver_asn':'asn','backend_resolver_prefix':'bgp_prefix',
                 'backend_resolver_org':'org','backend_resolver_country':'country','timestamp_request':'last_update_ts','protocol':'supported_protocols'})
        .select('ipv4','asn','bgp_prefix','org','country','last_update_ts','supported_protocols')
        .group_by('ipv4')
        .agg(
            pl.col('asn', 'bgp_prefix', 'org', 'country').first(),
            pl.col('last_update_ts').max(),
            pl.col('supported_protocols').flatten().drop_nulls().unique(),
        ),
        tfwd_closed_backend_resolver
        .rename({'backend_resolver':'ipv4','backend_resolver_asn':'asn','backend_resolver_prefix':'bgp_prefix',
                 'backend_resolver_org':'org','backend_resolver_country':'country','timestamp_request':'last_update_ts','protocol':'supported_protocols'})
        .select('ipv4','asn','bgp_prefix','org','country','last_update_ts','supported_protocols')
        .group_by('ipv4')
        .agg(
            pl.col('asn', 'bgp_prefix', 'org', 'country').first(),
            pl.col('last_update_ts').max(),
            pl.col('supported_protocols').flatten().drop_nulls().unique(),
        ),
        tfwd_closed_replying_resolver
        .rename({'replying_ip':'ipv4','replying_ip_asn':'asn','replying_ip_prefix':'bgp_prefix',
                 'replying_ip_org':'org','replying_ip_country':'country','timestamp_request':'last_update_ts','protocol':'supported_protocols'})
        .select('ipv4','asn','bgp_prefix','org','country','last_update_ts','supported_protocols')
        .group_by('ipv4')
        .agg(
            pl.col('asn', 'bgp_prefix', 'org', 'country').first(),
            pl.col('last_update_ts').max(),
            pl.col('supported_protocols').flatten().drop_nulls().unique(),
        ),
        ],how="vertical")
    )
    public_resolver = public_resolver.with_columns(pl.lit(True).alias("is_public"))
    closed_resolver = closed_resolver.with_columns(pl.lit(False).alias("is_public"))
    combined = pl.concat([public_resolver, closed_resolver], how="vertical").cast({"org": pl.Utf8})
    combined = combined.with_columns(
        pl.col("org").str.extract(r"^([A-Za-z0-9]+)", 1).alias("org_short")
    )
    
    resolver_rows = [
        {
            "ip": _normalize_ip(row["ipv4"]),
            "asn": row["asn"],
            "bgp_prefix": row["bgp_prefix"],
            "org": row["org"],
            "org_short": row["org_short"],
            "country": normalize_country(row["country"]),
            "is_public": row["is_public"],
            "protocol": _supported_protocols_to_text(row["supported_protocols"]),
            "supported_protocols": _supported_protocols_to_text(row["supported_protocols"]),
            "last_update_ts": _normalize_timestamp(row["last_update_ts"]),
            "source": ODNS_SOURCE,
        }
        for row in combined.to_dicts()
    ]

    # public forwarder if not anycast resolver
    public_forwarder = df_odns.filter(
        (pl.col("resolver_type") == "Forwarder")
        & (~pl.col("replying_ip").is_in(public_resolver["ipv4"]))
    )
    # closed forwarder if replying ip of transparent forwarder is not in public and not in closed resolver list
    closed_forwarder = df_odns.filter(
        (pl.col("resolver_type") == "Transparent Forwarder")
        & (~pl.col("replying_ip").is_in(combined["ipv4"]))
    )

    all_forwarder = pl.concat([(
        public_forwarder
        .rename({'queried_ip':'ipv4','queried_ip_asn':'asn','queried_ip_prefix':'bgp_prefix',
                 'queried_ip_org':'org','queried_ip_country':'country','timestamp_request':'last_update_ts','protocol':'supported_protocols','backend_resolver':'resolver'})
        .select('ipv4','resolver','asn','bgp_prefix','org','country','last_update_ts','supported_protocols')
        .group_by('ipv4', 'resolver')
        .agg(
            pl.col('asn', 'bgp_prefix', 'org', 'country').first(),
            pl.col('last_update_ts').max(),
            pl.col('supported_protocols').flatten().drop_nulls().unique(),
        )
        .with_columns(pl.lit("recursive").alias("type"))
        .with_columns(pl.lit(True).alias("is_public"))
    ),(
        closed_forwarder
        .rename({'replying_ip':'ipv4','replying_ip_asn':'asn','replying_ip_prefix':'bgp_prefix',
                 'replying_ip_org':'org','replying_ip_country':'country','timestamp_request':'last_update_ts','protocol':'supported_protocols','backend_resolver':'resolver'})
        .select('ipv4','resolver','asn','bgp_prefix','org','country','last_update_ts','supported_protocols')
        .group_by('ipv4', 'resolver')
        .agg(
            pl.col('asn', 'bgp_prefix', 'org', 'country').first(),
            pl.col('last_update_ts').max(),
            pl.col('supported_protocols').flatten().drop_nulls().unique(),
        )
        .with_columns(pl.lit("recursive").alias("type"))
        .with_columns(pl.lit(False).alias("is_public"))
    )],how='vertical')

    tfwd_only = df_odns.filter(
        (pl.col("resolver_type") == "Transparent Forwarder")
    )
    tfwd_only = (
        tfwd_only
        .rename({'queried_ip':'ipv4','queried_ip_asn':'asn','queried_ip_prefix':'bgp_prefix',
                 'queried_ip_org':'org','queried_ip_country':'country','timestamp_request':'last_update_ts','protocol':'supported_protocols','replying_ip':'resolver'})
        .select('ipv4','resolver','asn','bgp_prefix','org','country','last_update_ts','supported_protocols')
        .group_by('ipv4', 'resolver')
        .agg(
            pl.col('asn', 'bgp_prefix', 'org', 'country').first(),
            pl.col('last_update_ts').max(),
            pl.col('supported_protocols').explode().drop_nulls().unique(),
        )
        .with_columns(pl.lit("transparent").alias("type"))
        .with_columns(pl.lit(True).alias("is_public"))
    )
    
    resolver_ips = combined.select(pl.col("ipv4")).unique()
    forwarder_ips = all_forwarder.select(pl.col('ipv4')).unique()
    target_ips = pl.concat([resolver_ips, forwarder_ips], how="vertical").unique()
    forwarder_targets = pl.concat(
        [
            all_forwarder.select("ipv4", "type"),
            tfwd_only.select("ipv4", "type"),
        ],
        how="vertical",
    ).filter(pl.col("ipv4").is_not_null())

    missing_targets = forwarder_targets.join(target_ips, on="ipv4", how="anti")
    if missing_targets.height:
        by_type = (
            missing_targets
            .group_by("type")
            .agg(
                pl.len().alias("rows"),
                pl.col("ipv4").n_unique().alias("unique_resolvers"),
            )
            .sort("rows", descending=True)
            .to_dicts()
        )
        sample = (
            missing_targets
            .group_by("ipv4", "type")
            .agg(pl.len().alias("rows"))
            .sort("rows", descending=True)
            .head(10)
            .to_dicts()
        )
        logger.info(
            "Prepared forwarder targets missing from prepared resolver and forwarder rows: {rows} rows, {unique} unique target IPs",
            rows=missing_targets.height,
            unique=missing_targets.select(pl.col("ipv4").n_unique()).item(),
        )
        logger.info("Missing prepared forwarder targets by type: {summary}", summary=by_type)
        logger.info("Sample missing prepared forwarder targets: {sample}", sample=sample)
    else:
        logger.info(
            "All {count} prepared forwarder target rows have matching prepared resolver or forwarder rows",
            count=forwarder_targets.height,
        )

    logger.info(
        "Prepared {count} closed transparent-forwarder targets as non-public forwarders",
        count=closed_forwarder.height,
    )
    forwarder_rows = pl.concat([all_forwarder, tfwd_only], how="vertical").cast({"org": pl.Utf8}).with_columns(
        pl.col("org").str.extract(r"^([A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)", 1).alias("org_short")
    ).to_dicts()

    forwarder_rows = [
        {
            "ip": _normalize_ip(row["ipv4"]),
            "resolver": row["resolver"],
            "resolver_id": None,
            "type": row["type"],
            "is_public": row["is_public"],
            "supported_protocols": _supported_protocols_to_text(row["supported_protocols"]),
            "asn": row["asn"],
            "bgp_prefix": row["bgp_prefix"],
            "org": row["org"],
            "org_short": row["org_short"],
            "country": normalize_country(row["country"]),
            "last_update_ts": _normalize_timestamp(row["last_update_ts"]),
            "source": ODNS_SOURCE,
        }
        for row in forwarder_rows
    ]

    return resolver_rows, forwarder_rows, tfwd_anycast_country, tfwd_anycast_asn, tfwd_spoofing


def load_odns_api(
    *,
    data_dir: Path | None = None,
    protocol: str | None = None,
    input_path: Path | None = None,
) -> None:
    data_dir = data_dir or external_data_dir()
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
    (
        resolver_rows,
        forwarder_rows,
        anycast_country_backend_rows,
        anycast_asn_backend_rows,
        spoofing_rows,
    ) = load_odns_data(odns_path, anycast_path)
    logger.info("Loaded {count} resolver rows from ODNS parquet", count=len(resolver_rows))
    logger.info("Loaded {count} forwarder rows from ODNS parquet", count=len(forwarder_rows))
    logger.info("Loaded {count} anycast country backend rows from ODNS parquet", count=anycast_country_backend_rows.height)
    logger.info("Loaded {count} anycast ASN backend rows from ODNS parquet", count=anycast_asn_backend_rows.height)
    logger.info("Loaded {count} spoofing rows from ODNS parquet", count=spoofing_rows.height)
    
    resolver_path = DATA_DIR / "resolver.pq"
    forwarder_path = DATA_DIR / "forwarder.pq"
    _write_parquet(resolver_rows, resolver_path, columns=RESOLVER_OUTPUT_COLUMNS, rename={"ip": "ipv4"})
    _write_parquet(forwarder_rows, forwarder_path, columns=FORWARDER_OUTPUT_COLUMNS)

    logger.info("Importing resolver data from {path}", path=resolver_path)
    import_resolvers(
        resolver_path,
        mapping=RESOLVER_IMPORT_MAPPING,
        modules=RESOLVER_IMPORT_MODULES,
        dry_run=False,
        verified=True,
    )

    logger.info("Importing forwarder data from {path}", path=forwarder_path)
    import_forwarders(
        forwarder_path,
        mapping=FORWARDER_IMPORT_MAPPING,
        modules=FORWARDER_IMPORT_MODULES,
        dry_run=False,
    )
    
    logger.info("Importing anycast backend data from ODNS parquet")
    import_anycast(
        country_backend_rows=anycast_country_backend_rows,
        asn_backend_rows=anycast_asn_backend_rows,
        source=ODNS_SOURCE,
        dry_run=False,
    )

    logger.info("Importing spoofing data from ODNS parquet")
    import_spoofing(spoofing_rows, modules="spoofing,asn,country", source=ODNS_SOURCE, dry_run=False)
