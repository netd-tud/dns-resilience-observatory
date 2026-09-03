import json
import re
import urllib.parse
from functools import wraps
from ipaddress import ip_address, ip_network

import pycountry
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import connection


def cached(ttl: int = 300):
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            key = "dns-resilience:" + func.__name__ + ":" + repr((args, sorted(kwargs.items())))
            cached_value = cache.get(key)
            if cached_value is not None:
                return cached_value
            value = func(self, *args, **kwargs)
            cache.set(key, value, ttl)
            return value

        return wrapper

    return decorator


class DNSResilienceService:
    _TCP_PATTERN = r"(^|[^a-z])tcp([^a-z]|$)"
    _UDP_PATTERN = r"(^|[^a-z])udp([^a-z]|$)"
    _SPOOFING_ALLOW_SQL = """
        (
            LOWER(COALESCE(s.privatespoof, '')) IN ('received', 'rewritten')
            OR LOWER(COALESCE(s.routedspoof, '')) IN ('received', 'rewritten')
        )
    """

    def _fetchall(self, sql: str, params: list | tuple | None = None) -> list[dict]:
        with connection.cursor() as cursor:
            cursor.execute(sql, params or [])
            columns = [column[0] for column in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def _fetchone(self, sql: str, params: list | tuple | None = None) -> dict | None:
        rows = self._fetchall(sql, params)
        return rows[0] if rows else None

    def _protocol_tokens(self, value: str | None) -> set[str]:
        return set(re.findall(r"[a-z]+", (value or "").lower()))

    def _resolver_select(self, where_sql: str, order_sql: str = "r.ip", limit: int = 100) -> tuple[str, list]:
        sql = f"""
            SELECT
                r.resolver_id AS id,
                host(r.ip) AS ip,
                ra.asn,
                rp.prefix::TEXT AS bgp_prefix,
                ro.org,
                STRING_AGG(DISTINCT rd.domain, ', ' ORDER BY rd.domain) AS domain,
                rl.country,
                rl.city,
                r.is_public,
                r.last_update_ts AS last_observation_ts,
                r.source,
                STRING_AGG(
                    DISTINCT (rs.protocol || ':' || rs.port::TEXT),
                    ',' ORDER BY (rs.protocol || ':' || rs.port::TEXT)
                ) FILTER (
                    WHERE rs.protocol IS NOT NULL
                      AND rs.port IS NOT NULL
                      AND rs.supported IS TRUE
                ) AS supported_protocols
            FROM resolver r
            LEFT JOIN resolver_asn ra ON ra.resolver_id = r.resolver_id
            LEFT JOIN resolver_prefix rp ON rp.resolver_id = r.resolver_id
            LEFT JOIN resolver_org ro ON ro.resolver_id = r.resolver_id
            LEFT JOIN resolver_domain rd ON rd.resolver_id = r.resolver_id
            LEFT JOIN resolver_location rl ON rl.resolver_id = r.resolver_id
            LEFT JOIN resolver_service rs ON rs.resolver_id = r.resolver_id
            WHERE {where_sql}
            GROUP BY r.resolver_id, r.ip, ra.asn, rp.prefix, ro.org, rl.country, rl.city,
                     r.is_public, r.last_update_ts, r.source
            ORDER BY {order_sql}
            LIMIT %s
        """
        return sql, [limit]

    def validate_ip_address(self, ip: str) -> str:
        if not ip or not isinstance(ip, str):
            raise ValidationError("Resolver IP must be a non-empty string")
        try:
            return str(ip_address(ip.strip()))
        except ValueError as exc:
            raise ValidationError(f"Invalid IP address '{ip}': must be a valid IPv4 or IPv6 address") from exc

    def validate_network_prefix(self, prefix: str) -> str:
        if not prefix or not isinstance(prefix, str):
            raise ValidationError("Network prefix must be a non-empty string")
        decoded = urllib.parse.unquote(prefix.strip())
        try:
            return str(ip_network(decoded, strict=False))
        except ValueError as exc:
            raise ValidationError(f"Invalid network prefix '{prefix}': must be CIDR notation") from exc

    def validate_asn(self, asn_str: str) -> int:
        if not asn_str or not isinstance(asn_str, str):
            raise ValidationError("ASN must be a non-empty string")
        cleaned = asn_str.strip().upper()
        if cleaned.startswith("AS"):
            cleaned = cleaned[2:].strip()
        if not cleaned.isdigit():
            raise ValidationError(f"Invalid ASN '{asn_str}': must be a number or AS<number>")
        asn = int(cleaned)
        if not (1 <= asn <= 4294967295):
            raise ValidationError(f"ASN {asn} is out of range")
        return asn

    def validate_country_code(self, country: str) -> str:
        if not country or not isinstance(country, str):
            raise ValidationError("Country code must be a non-empty string")
        country_upper = country.strip().upper()
        if re.match(r"^[A-Z]{2}$", country_upper):
            entry = pycountry.countries.get(alpha_2=country_upper)
            if not entry:
                raise ValidationError(f"Invalid country code '{country}': must be ISO 3166-1 alpha-2")
            return entry.alpha_3
        if re.match(r"^[A-Z]{3}$", country_upper):
            entry = pycountry.countries.get(alpha_3=country_upper)
            if not entry:
                raise ValidationError(f"Invalid country code '{country}': must be ISO 3166-1 alpha-3")
            return entry.alpha_3
        raise ValidationError(f"Invalid country code '{country}': must be ISO 3166-1 alpha-2 or alpha-3")

    def validate_domain(self, domain: str) -> str:
        if not domain or not isinstance(domain, str):
            raise ValidationError("Domain must be a non-empty string")
        normalized = domain.strip().rstrip(".").lower()
        if len(normalized) > 253 or "." not in normalized:
            raise ValidationError(f"Invalid domain '{domain}': must be a fully qualified domain name")
        label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        if not re.fullmatch(rf"{label}(?:\.{label})+", normalized):
            raise ValidationError(f"Invalid domain '{domain}': contains invalid DNS label characters")
        return normalized

    def validate_organization(self, organization: str) -> str:
        if not organization or not isinstance(organization, str):
            raise ValidationError("Organization must be a non-empty string")
        normalized = organization.strip()
        if len(normalized) > 200:
            raise ValidationError("Organization lookup must not exceed 200 characters")
        return normalized

    def validate_resolver_service(self, service: str) -> tuple[str, int | None]:
        if not service or not isinstance(service, str):
            raise ValidationError("Protocol must be a non-empty string")
        normalized = service.strip().lower()
        if ":" in normalized:
            protocol, port_text = normalized.rsplit(":", 1)
            if not port_text.isdigit():
                raise ValidationError(f"Invalid protocol lookup '{service}': port must be numeric")
            port = int(port_text)
            if not (1 <= port <= 65535):
                raise ValidationError(f"Invalid protocol lookup '{service}': port is out of range")
        else:
            protocol, port = normalized, None
        if not re.fullmatch(r"[a-z0-9][a-z0-9.+-]*", protocol):
            raise ValidationError(f"Invalid protocol '{service}'")
        return protocol, port

    def validate_port(self, port: int | str) -> int:
        try:
            normalized = int(port)
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"Invalid port '{port}': must be numeric") from exc
        if not (1 <= normalized <= 65535):
            raise ValidationError(f"Invalid port '{port}': must be between 1 and 65535")
        return normalized

    @staticmethod
    def _manrs_readiness_payload(row: dict | None) -> dict:
        metric_columns = {
            "anti_spoofing_pc": "anti_spoofing_score",
            "coordination_pc": "coordination_score",
            "filtering_pc": "filtering_score",
            "routing_information_irr_pc": "routing_information_irr_score",
            "routing_information_rpki_pc": "routing_information_rpki_score",
        }
        if not row:
            return {
                "available": False,
                "average_readiness_pc": None,
                "metric_count": 0,
                "last_update_ts": None,
                **{output: None for output in metric_columns},
            }

        available_scores = [
            float(row[column])
            for column in metric_columns.values()
            if row.get(column) is not None
        ]
        average_readiness_pc = (
            round((sum(available_scores) / len(available_scores)) * 100.0, 2)
            if available_scores
            else None
        )
        return {
            "available": bool(available_scores),
            "average_readiness_pc": average_readiness_pc,
            "metric_count": len(available_scores),
            "last_update_ts": row.get("last_update_ts"),
            **{
                output: round(float(row[column]) * 100.0, 2)
                if row.get(column) is not None
                else None
                for output, column in metric_columns.items()
            },
        }

    def _get_manrs_asn_row(self, asn: int) -> dict | None:
        return self._fetchone(
            """
            SELECT
                anti_spoofing_score,
                coordination_score,
                filtering_score,
                routing_information_irr_score,
                routing_information_rpki_score,
                last_update_ts
            FROM manrs_asn
            WHERE asn = %s
            """,
            [asn],
        )

    def _get_manrs_country_row(self, country: str) -> dict | None:
        return self._fetchone(
            """
            SELECT
                anti_spoofing_score,
                coordination_score,
                filtering_score,
                routing_information_irr_score,
                routing_information_rpki_score,
                last_update_ts
            FROM manrs_country
            WHERE country = %s
            """,
            [country],
        )

    @cached()
    def get_asn_manrs(self, asn: str) -> dict:
        normalized = self.validate_asn(asn)
        return {
            "entity_type": "asn",
            "target": f"AS{normalized}",
            "asn": normalized,
            **self._manrs_readiness_payload(self._get_manrs_asn_row(normalized)),
        }

    @cached()
    def get_country_manrs(self, country: str) -> dict:
        normalized = self.validate_country_code(country)
        return {
            "entity_type": "country",
            "target": normalized,
            "country": normalized,
            **self._manrs_readiness_payload(self._get_manrs_country_row(normalized)),
        }

    @cached()
    def get_resolver_manrs(self, ip: str) -> dict:
        normalized = self.validate_ip_address(ip)
        resolver_asn = self._fetchone(
            """
            SELECT ra.asn::BIGINT AS asn
            FROM resolver r
            LEFT JOIN resolver_asn ra ON ra.resolver_id = r.resolver_id
            WHERE r.ip = %s::INET
            LIMIT 1
            """,
            [normalized],
        ) or {}
        asn = resolver_asn.get("asn")
        readiness = self._manrs_readiness_payload(
            self._get_manrs_asn_row(int(asn)) if asn is not None else None
        )
        return {
            "entity_type": "resolver_asn",
            "target": normalized,
            "resolver_ip": normalized,
            "asn": asn,
            "source_entity": f"AS{asn}" if asn is not None else None,
            **readiness,
        }

    @cached(ttl=300)
    def get_comparison_metrics(self, entity_type: str, target: str) -> dict:
        normalized_type = (entity_type or "").strip().lower()
        if normalized_type in {"as", "asn"}:
            normalized_type = "asn"
            normalized_target = self.validate_asn(target)
            display_target = f"AS{normalized_target}"
            scope_sql = """
                SELECT DISTINCT r.resolver_id, r.ip, r.is_public, r.last_update_ts
                FROM resolver r
                JOIN resolver_asn ra ON ra.resolver_id = r.resolver_id
                WHERE ra.asn = %s
            """
            scope_params = [normalized_target]
            manrs = self.get_asn_manrs(str(normalized_target))
            country_dnssec = None
        elif normalized_type == "country":
            normalized_target = self.validate_country_code(target)
            country = pycountry.countries.get(alpha_3=normalized_target)
            display_target = f"{country.name} ({normalized_target})" if country else normalized_target
            scope_sql = """
                SELECT DISTINCT r.resolver_id, r.ip, r.is_public, r.last_update_ts
                FROM resolver r
                JOIN resolver_location rl ON rl.resolver_id = r.resolver_id
                WHERE rl.country = %s
            """
            scope_params = [normalized_target]
            manrs = self.get_country_manrs(normalized_target)
            country_dnssec = self.get_country_dnssec(normalized_target)
        elif normalized_type in {"resolver", "ip", "resolver-ip"}:
            normalized_type = "resolver"
            normalized_target = self.validate_ip_address(target)
            display_target = normalized_target
            scope_sql = """
                SELECT DISTINCT r.resolver_id, r.ip, r.is_public, r.last_update_ts
                FROM resolver r
                WHERE r.ip = %s::INET
            """
            scope_params = [normalized_target]
            manrs = self.get_resolver_manrs(normalized_target)
            country_dnssec = None
        else:
            raise ValidationError("Comparison entity type must be 'country', 'asn', or 'resolver'")

        row = self._fetchone(
            f"""
            WITH scoped_resolvers AS MATERIALIZED (
                {scope_sql}
            ),
            scoped_asns AS MATERIALIZED (
                SELECT DISTINCT ra.asn
                FROM scoped_resolvers sr
                JOIN resolver_asn ra ON ra.resolver_id = sr.resolver_id
                WHERE ra.asn > 0
            ),
            caida_allowing_asns AS MATERIALIZED (
                SELECT DISTINCT sa.asn
                FROM spoofing_asn sa
                JOIN scoped_asns scoped ON scoped.asn = sa.asn
                JOIN spoofing s ON s.prefix = sa.prefix
                WHERE s.source = 'caida-spoofer'
                  AND {self._SPOOFING_ALLOW_SQL}
            ),
            transparent_forwarder_asns AS MATERIALIZED (
                SELECT DISTINCT fa.asn::BIGINT AS asn
                FROM forwarder f
                JOIN forwarder_asn fa ON fa.forwarder_id = f.forwarder_id
                JOIN scoped_asns scoped ON scoped.asn = fa.asn
                WHERE (
                        LOWER(TRIM(f.type)) = 'transparent'
                        OR f.transparent_count > 0
                    )
                  AND f.source = 'odns-api'
            ),
            allowing_asns AS MATERIALIZED (
                SELECT asn FROM caida_allowing_asns
                UNION
                SELECT asn FROM transparent_forwarder_asns
            ),
            caida_blocking_asns AS MATERIALIZED (
                SELECT DISTINCT sa.asn
                FROM spoofing_asn sa
                JOIN scoped_asns scoped ON scoped.asn = sa.asn
                JOIN spoofing s ON s.prefix = sa.prefix
                WHERE s.source = 'caida-spoofer'
                  AND NOT {self._SPOOFING_ALLOW_SQL}
                  AND (
                      LOWER(COALESCE(s.privatespoof, '')) = 'blocked'
                      OR LOWER(COALESCE(s.routedspoof, '')) = 'blocked'
                  )
            ),
            resolver_features AS MATERIALIZED (
                SELECT
                    sr.resolver_id,
                    sr.ip,
                    sr.is_public,
                    sr.last_update_ts,
                    EXISTS (
                        SELECT 1 FROM dnssec_resolver dr
                        WHERE dr.ip = sr.ip AND dr.validates IS TRUE
                    ) AS validates_dnssec,
                    EXISTS (
                        SELECT 1 FROM dnssec_resolver dr
                        WHERE dr.ip = sr.ip AND dr.validates IS FALSE
                    ) AS does_not_validate_dnssec,
                    EXISTS (
                        SELECT 1 FROM qmin_resolver q
                        WHERE q.resolver_id = sr.resolver_id
                          AND LOWER(COALESCE(q.qmin, '')) = 'yes'
                          AND q.max_minimise_count <= 10
                    ) AS proper_qmin,
                    EXISTS (
                        SELECT 1 FROM qmin_resolver q
                        WHERE q.resolver_id = sr.resolver_id
                          AND LOWER(TRIM(COALESCE(q.qmin, ''))) = 'yes'
                          AND q.max_minimise_count > 10
                    ) AS qmin_too_many_queries,
                    EXISTS (
                        SELECT 1 FROM qmin_resolver q
                        WHERE q.resolver_id = sr.resolver_id
                          AND LOWER(TRIM(COALESCE(q.qmin, ''))) = 'no'
                    ) AS qmin_not_implemented,
                    EXISTS (
                        SELECT 1 FROM qmin_resolver q
                        WHERE q.resolver_id = sr.resolver_id
                          AND LOWER(TRIM(COALESCE(q.qmin, ''))) = 'unstable'
                    ) AS qmin_unstable,
                    EXISTS (
                        SELECT 1 FROM anycast a
                        WHERE sr.ip <<= a.prefix
                    ) AS anycast_enabled,
                    (
                        EXISTS (
                            SELECT 1 FROM resolver r4
                            WHERE r4.resolver_id = sr.resolver_id AND family(r4.ip) = 4
                        )
                        AND EXISTS (
                            SELECT 1 FROM resolver r6
                            WHERE r6.resolver_id = sr.resolver_id AND family(r6.ip) = 6
                        )
                    ) AS dual_stack,
                    EXISTS (
                        SELECT 1 FROM resolver_service rs
                        WHERE rs.resolver_id = sr.resolver_id
                          AND (
                              LOWER(TRIM(rs.protocol)) IN ('doq', 'dot')
                              OR LOWER(TRIM(rs.protocol)) LIKE 'doh%%'
                          )
                    ) AS secure_protocol_tested,
                    EXISTS (
                        SELECT 1 FROM resolver_service rs
                        WHERE rs.resolver_id = sr.resolver_id
                          AND rs.supported IS TRUE
                          AND (
                              LOWER(TRIM(rs.protocol)) IN ('doq', 'dot')
                              OR LOWER(TRIM(rs.protocol)) LIKE 'doh%%'
                          )
                    ) AS secure_protocol_supported,
                    EXISTS (
                        SELECT 1
                        FROM resolver_asn ra
                        JOIN allowing_asns allowing ON allowing.asn = ra.asn
                        WHERE ra.resolver_id = sr.resolver_id
                    ) AS allows_spoofing,
                    EXISTS (
                        SELECT 1
                        FROM resolver_asn ra
                        JOIN caida_blocking_asns blocking ON blocking.asn = ra.asn
                        WHERE ra.resolver_id = sr.resolver_id
                    ) AS blocks_spoofing,
                    EXISTS (
                        SELECT 1
                        FROM resolver_prefix rp
                        JOIN resolver_asn ra ON ra.resolver_id = rp.resolver_id
                        JOIN rpki_prefix rpk
                          ON rpk.prefix = rp.prefix
                         AND rpk.asn = ra.asn
                        WHERE rp.resolver_id = sr.resolver_id
                          AND rpk.rpki_status = 'valid'
                    ) AS rpki_valid,
                    EXISTS (
                        SELECT 1
                        FROM resolver_prefix rp
                        JOIN resolver_asn ra ON ra.resolver_id = rp.resolver_id
                        JOIN rpki_prefix rpk
                          ON rpk.prefix = rp.prefix
                         AND rpk.asn = ra.asn
                        WHERE rp.resolver_id = sr.resolver_id
                          AND rpk.rpki_status IN ('invalid_asn', 'invalid_length')
                    ) AS rpki_invalid
                FROM scoped_resolvers sr
            )
            SELECT
                COUNT(*)::INTEGER AS resolver_count,
                COUNT(*) FILTER (WHERE is_public IS TRUE)::INTEGER AS open_resolver_count,
                COUNT(*) FILTER (WHERE validates_dnssec)::INTEGER AS dnssec_validating_count,
                COUNT(*) FILTER (WHERE does_not_validate_dnssec)::INTEGER
                    AS dnssec_not_validating_count,
                COUNT(*) FILTER (WHERE proper_qmin)::INTEGER AS proper_qmin_count,
                COUNT(*) FILTER (WHERE qmin_too_many_queries)::INTEGER AS qmin_risk_count,
                COUNT(*) FILTER (WHERE qmin_not_implemented)::INTEGER
                    AS qmin_not_implemented_count,
                COUNT(*) FILTER (WHERE qmin_unstable)::INTEGER AS qmin_unstable_count,
                COUNT(*) FILTER (WHERE anycast_enabled)::INTEGER AS anycast_count,
                COUNT(*) FILTER (WHERE dual_stack)::INTEGER AS dual_stack_count,
                COUNT(*) FILTER (WHERE secure_protocol_tested)::INTEGER AS secure_protocol_tested_count,
                COUNT(*) FILTER (WHERE secure_protocol_supported)::INTEGER AS secure_protocol_count,
                COUNT(*) FILTER (
                    WHERE secure_protocol_tested AND NOT secure_protocol_supported
                )::INTEGER AS secure_protocol_unsupported_count,
                COUNT(*) FILTER (WHERE allows_spoofing)::INTEGER AS spoofing_allowing_count,
                COUNT(*) FILTER (WHERE NOT allows_spoofing AND blocks_spoofing)::INTEGER
                    AS spoofing_blocking_count,
                COUNT(*) FILTER (WHERE rpki_valid)::INTEGER AS rpki_valid_count,
                COUNT(*) FILTER (WHERE NOT rpki_valid AND rpki_invalid)::INTEGER
                    AS rpki_invalid_count,
                MAX(last_update_ts) AS last_observation_ts
            FROM resolver_features
            """,
            scope_params,
        ) or {}

        resolver_count = row.get("resolver_count", 0) or 0

        def distribution_metric(primary_count_key: str, categories: list[tuple[str, str | None]]) -> dict:
            category_values = {}
            assigned_count = 0
            for category_key, count_key in categories:
                if count_key is None:
                    category_count = max(resolver_count - assigned_count, 0)
                else:
                    category_count = row.get(count_key, 0) or 0
                    assigned_count += category_count
                category_values[category_key] = {
                    "count": category_count,
                    "percent": self._pc(category_count, resolver_count),
                }
            primary_count = row.get(primary_count_key, 0) or 0
            return {
                "count": primary_count,
                "percent": self._pc(primary_count, resolver_count),
                "observed_count": resolver_count - category_values.get("unknown", {}).get("count", 0),
                "categories": category_values,
            }

        return {
            "entity_type": normalized_type,
            "target": str(normalized_target),
            "display_target": display_target,
            "resolver_count": resolver_count,
            "last_observation_ts": row.get("last_observation_ts"),
            "metrics": {
                "open_resolvers": distribution_metric("open_resolver_count", [
                    ("open", "open_resolver_count"),
                    ("closed", None),
                ]),
                "dnssec_validation": distribution_metric("dnssec_validating_count", [
                    ("validating", "dnssec_validating_count"),
                    ("not_validating", "dnssec_not_validating_count"),
                    ("unknown", None),
                ]),
                "qmin": distribution_metric("proper_qmin_count", [
                    ("proper", "proper_qmin_count"),
                    ("too_many_queries", "qmin_risk_count"),
                    ("not_implemented", "qmin_not_implemented_count"),
                    ("unstable", "qmin_unstable_count"),
                    ("unknown", None),
                ]),
                "anycast": distribution_metric("anycast_count", [
                    ("enabled", "anycast_count"),
                    ("not_enabled", None),
                ]),
                "dual_stack": distribution_metric("dual_stack_count", [
                    ("dual_stack", "dual_stack_count"),
                    ("not_dual_stack", None),
                ]),
                "secure_protocols": distribution_metric("secure_protocol_count", [
                    ("supported", "secure_protocol_count"),
                    ("not_supported", "secure_protocol_unsupported_count"),
                    ("unknown", None),
                ]),
                "bcp38": distribution_metric("spoofing_blocking_count", [
                    ("allows_spoofing", "spoofing_allowing_count"),
                    ("blocks_spoofing", "spoofing_blocking_count"),
                    ("unknown", None),
                ]),
                "rpki": distribution_metric("rpki_valid_count", [
                    ("valid", "rpki_valid_count"),
                    ("invalid", "rpki_invalid_count"),
                    ("unknown", None),
                ]),
            },
            "manrs": manrs,
            "country_dnssec": country_dnssec,
        }

    @cached()
    def get_resolvers_by_ip(self, ip: str, limit: int = 100) -> list[dict]:
        normalized = self.validate_ip_address(ip)
        sql, params = self._resolver_select("r.ip = %s::inet", limit=limit)
        return self._fetchall(sql, [normalized, *params])

    @cached()
    def get_resolvers_by_prefix(self, prefix: str, limit: int = 100) -> list[dict]:
        normalized = self.validate_network_prefix(prefix)
        sql, params = self._resolver_select("rp.prefix = %s::cidr", limit=limit)
        return self._fetchall(sql, [normalized, *params])

    @cached()
    def get_resolvers_by_asn(self, asn: str, limit: int = 100) -> list[dict]:
        normalized = self.validate_asn(asn)
        sql, params = self._resolver_select("ra.asn = %s", limit=limit)
        return self._fetchall(sql, [normalized, *params])

    @cached()
    def get_resolvers_by_country(self, country: str, limit: int = 100) -> list[dict]:
        normalized = self.validate_country_code(country)
        sql, params = self._resolver_select("rl.country = %s", limit=limit)
        return self._fetchall(sql, [normalized, *params])

    @cached()
    def get_resolvers_by_scope(self, scope: str, limit: int = 100) -> tuple[str, list[dict]]:
        normalized = (scope or "").strip().lower()
        if normalized == "public":
            normalized = "open"
        if normalized not in {"open", "closed"}:
            raise ValidationError("Resolver scope must be 'open' or 'closed'")
        sql, params = self._resolver_select("r.is_public = %s", limit=limit)
        return normalized, self._fetchall(sql, [normalized == "open", *params])

    @cached()
    def get_resolvers_by_organization(self, organization: str, limit: int = 100) -> tuple[str, list[dict]]:
        normalized = self.validate_organization(organization)
        escaped = normalized.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        sql, params = self._resolver_select(
            "ro.org ILIKE %s ESCAPE '\\'",
            order_sql="ro.org, r.ip",
            limit=limit,
        )
        return normalized, self._fetchall(sql, [f"%{escaped}%", *params])

    @cached()
    def get_resolvers_by_domain(self, domain: str, limit: int = 100) -> list[dict]:
        normalized = self.validate_domain(domain)
        sql, params = self._resolver_select("LOWER(rd.domain) = LOWER(%s)", limit=limit)
        return self._fetchall(sql, [normalized, *params])

    @cached()
    def get_resolvers_by_service(self, service: str, limit: int = 100) -> tuple[str, list[dict]]:
        protocol, port = self.validate_resolver_service(service)
        if port is None:
            sql, params = self._resolver_select(
                "LOWER(rs.protocol) = %s AND rs.supported IS TRUE",
                limit=limit,
            )
            return protocol, self._fetchall(sql, [protocol, *params])
        sql, params = self._resolver_select(
            "LOWER(rs.protocol) = %s AND rs.port = %s AND rs.supported IS TRUE",
            limit=limit,
        )
        return f"{protocol}:{port}", self._fetchall(sql, [protocol, port, *params])

    @cached()
    def get_resolvers_by_port(self, port: int | str, limit: int = 100) -> tuple[int, list[dict]]:
        normalized = self.validate_port(port)
        sql, params = self._resolver_select("rs.port = %s AND rs.supported IS TRUE", limit=limit)
        return normalized, self._fetchall(sql, [normalized, *params])

    @cached()
    def get_resolver_core(self, ip: str) -> dict:
        normalized = self.validate_ip_address(ip)
        rows = self.get_resolvers_by_ip(normalized, limit=1)
        return {"resolver_ip": normalized, "found": bool(rows), "resolver": rows[0] if rows else None}

    @cached()
    def get_resolver_alternative_ips(self, resolver_id: int | None) -> list[dict]:
        if not resolver_id:
            return []
        return self._fetchall(
            """
            WITH target_domain AS (
                SELECT DISTINCT LOWER(domain) AS domain
                FROM resolver_domain
                WHERE resolver_id = %s
                  AND domain IS NOT NULL
            ),
            related_resolver AS (
                SELECT %s::BIGINT AS resolver_id
                UNION
                SELECT rd.resolver_id
                FROM resolver_domain rd
                JOIN target_domain td ON LOWER(rd.domain) = td.domain
            )
            SELECT DISTINCT
                host(r.ip) AS ip,
                family(r.ip)::INTEGER AS family
            FROM resolver r
            JOIN related_resolver rr ON rr.resolver_id = r.resolver_id
            ORDER BY family(r.ip), host(r.ip)
            """,
            [resolver_id, resolver_id],
        )

    @cached()
    def get_resolver_sibling_ips(self, resolver_id: int | None, current_ip: str | None) -> list[dict]:
        if not resolver_id:
            return []
        normalized_current = self.validate_ip_address(current_ip) if current_ip else None
        return self._fetchall(
            """
            WITH target_domain AS (
                SELECT LOWER(domain) AS domain
                FROM resolver_domain
                WHERE resolver_id = %s
                  AND domain IS NOT NULL
            ),
            sibling_resolver AS (
                SELECT %s::BIGINT AS resolver_id
                UNION
                SELECT rd.resolver_id
                FROM resolver_domain rd
                JOIN target_domain td ON LOWER(rd.domain) = td.domain
            )
            SELECT DISTINCT
                host(r.ip) AS ip,
                family(r.ip)::INTEGER AS family
            FROM resolver r
            JOIN sibling_resolver sr ON sr.resolver_id = r.resolver_id
            WHERE (%s::inet IS NULL OR r.ip <> %s::inet)
            ORDER BY family(r.ip), host(r.ip)
            """,
            [resolver_id, resolver_id, normalized_current, normalized_current],
        )

    @cached()
    def get_resolver_domains(self, resolver_id: int | None) -> list[str]:
        if not resolver_id:
            return []
        rows = self._fetchall(
            """
            SELECT domain
            FROM resolver_domain
            WHERE resolver_id = %s
              AND domain IS NOT NULL
            ORDER BY LOWER(domain)
            """,
            [resolver_id],
        )
        return [row["domain"] for row in rows]

    @cached()
    def get_resolver_dohpath(self, resolver_id: int | None) -> str | None:
        if not resolver_id:
            return None
        row = self._fetchone(
            """
            SELECT dohpath
            FROM resolver_dohpath
            WHERE resolver_id = %s
            """,
            [resolver_id],
        )
        return row.get("dohpath") if row else None

    @cached()
    def get_resolver_services(self, resolver_id: int | None) -> list[str]:
        if not resolver_id:
            return []
        rows = self._fetchall(
            """
            SELECT protocol, port
            FROM resolver_service
            WHERE resolver_id = %s
              AND supported IS TRUE
            ORDER BY protocol, port
            """,
            [resolver_id],
        )
        return [f"{row['protocol']}:{row['port']}" for row in rows]

    @cached()
    def get_resolver_protocol_results(self, resolver_id: int | None) -> list[dict]:
        if not resolver_id:
            return []
        return self._fetchall(
            """
            SELECT
                protocol,
                port,
                supported,
                last_update_ts
            FROM resolver_service
            WHERE resolver_id = %s
            ORDER BY protocol, port
            """,
            [resolver_id],
        )

    @cached()
    def get_resolver_qmin(self, ip: str) -> dict:
        normalized = self.validate_ip_address(ip)
        row = self._fetchone(
            """
            SELECT
                r.ip::TEXT AS resolver_ip,
                q.qmin,
                q.max_minimise_count,
                q.minimize_one_lab,
                q.first_qmin_observation,
                q.last_qmin_observation,
                q.last_update_ts,
                q.source
            FROM resolver r
            LEFT JOIN qmin_resolver q ON q.resolver_id = r.resolver_id
            WHERE r.ip = %s::inet
            """,
            [normalized],
        )
        return row or {"resolver_ip": normalized, "qmin": None}

    @cached()
    def get_resolver_dnssec(self, ip: str) -> dict:
        normalized = self.validate_ip_address(ip)
        row = self._fetchone(
            """
            SELECT
                validates AS resolver_dnssec_validates,
                last_update_ts AS resolver_dnssec_last_update_ts
            FROM dnssec_resolver
            WHERE ip = %s::inet
            """,
            [normalized],
        )
        return row or {
            "resolver_dnssec_validates": None,
            "resolver_dnssec_last_update_ts": None,
        }

    @cached()
    def get_resolver_anycast(self, ip: str) -> dict:
        normalized = self.validate_ip_address(ip)
        row = self._fetchone(
            """
            SELECT
                %s::inet::TEXT AS ip,
                COUNT(*)::INTEGER AS prefix_count,
                BOOL_OR(a.partial)::BOOLEAN AS partial,
                MAX(a.last_update_ts) AS last_update_ts
            FROM anycast a
            WHERE %s::inet <<= a.prefix
            """,
            [normalized, normalized],
        )
        prefix_count = row["prefix_count"] if row else 0
        return {
            "ip": normalized,
            "anycast_found": bool(prefix_count),
            "prefix_count": prefix_count,
            "partial": row["partial"] if row else None,
            "last_update_ts": row["last_update_ts"] if row else None,
        }

    @cached()
    def get_resolver_anycast_sites(self, ip: str) -> dict:
        normalized = self.validate_ip_address(ip)
        countries = self._fetchall(
            """
            SELECT
                ac.country,
                SUM(ac.country_count)::INTEGER AS count,
                MAX(cl.latitude) AS latitude,
                MAX(cl.longitude) AS longitude,
                MAX(ac.last_update_ts) AS last_update_ts
            FROM anycast a
            JOIN anycast_country_backend ac ON ac.prefix = a.prefix
            LEFT JOIN country_location cl ON cl.country = ac.country
            WHERE %s::inet <<= a.prefix
            GROUP BY ac.country
            ORDER BY count DESC, ac.country
            """,
            [normalized],
        )
        asns = self._fetchall(
            """
            SELECT
                ab.asn,
                SUM(ab.asn_count)::INTEGER AS count,
                MAX(ab.last_update_ts) AS last_update_ts
            FROM anycast a
            JOIN anycast_asn_backend ab ON ab.prefix = a.prefix
            WHERE %s::inet <<= a.prefix
            GROUP BY ab.asn
            ORDER BY count DESC, ab.asn
            """,
            [normalized],
        )
        return {
            "ip": normalized,
            "anycast_found": bool(countries or asns),
            "countries": countries,
            "asns": asns,
        }

    @cached()
    def get_resolver_spoofing(self, ip: str) -> dict:
        normalized = self.validate_ip_address(ip)
        row = self._fetchone(
            """
            WITH matching AS (
                SELECT
                    prefix,
                    privatespoof,
                    routedspoof,
                    last_update_ts
                FROM spoofing
                WHERE %s::inet <<= prefix
            )
            SELECT
                COUNT(*)::INTEGER AS spoofing_prefix_count,
                COUNT(*) FILTER (
                    WHERE LOWER(COALESCE(privatespoof, '')) IN ('received', 'rewritten')
                       OR LOWER(COALESCE(routedspoof, '')) IN ('received', 'rewritten')
                )::INTEGER AS spoofing_allow_count,
                COUNT(*) FILTER (
                    WHERE LOWER(COALESCE(privatespoof, '')) = 'received'
                       OR LOWER(COALESCE(routedspoof, '')) = 'received'
                )::INTEGER AS spoofing_received_count,
                COUNT(*) FILTER (
                    WHERE NOT (
                        LOWER(COALESCE(privatespoof, '')) IN ('received', 'rewritten')
                        OR LOWER(COALESCE(routedspoof, '')) IN ('received', 'rewritten')
                    )
                    AND (
                        LOWER(COALESCE(privatespoof, '')) = 'blocked'
                        OR LOWER(COALESCE(routedspoof, '')) = 'blocked'
                    )
                )::INTEGER AS spoofing_blocked_count,
                COUNT(*) FILTER (
                    WHERE NOT (
                        LOWER(COALESCE(privatespoof, '')) IN ('received', 'rewritten')
                        OR LOWER(COALESCE(routedspoof, '')) IN ('received', 'rewritten')
                        OR LOWER(COALESCE(privatespoof, '')) = 'blocked'
                        OR LOWER(COALESCE(routedspoof, '')) = 'blocked'
                    )
                )::INTEGER AS spoofing_unknown_count,
                MAX(last_update_ts) AS spoofing_last_update_ts
            FROM matching
            """,
            [normalized],
        ) or {}
        prefixes = self._fetchall(
            """
            SELECT prefix::TEXT AS prefix, privatespoof, routedspoof
            FROM spoofing
            WHERE %s::inet <<= prefix
              AND (
                  LOWER(COALESCE(privatespoof, '')) IN ('received', 'rewritten')
                  OR LOWER(COALESCE(routedspoof, '')) IN ('received', 'rewritten')
              )
            ORDER BY masklen(prefix) DESC, prefix::TEXT
            LIMIT 10
            """,
            [normalized],
        )
        total = row.get("spoofing_prefix_count", 0) or 0
        allow = row.get("spoofing_allow_count", 0) or 0
        return {
            "spoofing_prefix_count": total,
            "spoofing_allow_count": allow,
            "spoofing_received_count": row.get("spoofing_received_count", 0) or 0,
            "spoofing_blocked_count": row.get("spoofing_blocked_count", 0) or 0,
            "spoofing_unknown_count": row.get("spoofing_unknown_count", 0) or 0,
            "spoofing_allow_pc": self._pc(allow, total),
            "spoofing_last_update_ts": row.get("spoofing_last_update_ts"),
            "spoofing_allow_prefixes": prefixes,
        }

    @cached()
    def get_asn_spoofing(self, asn: str) -> dict:
        normalized = self.validate_asn(asn)
        return self._spoofing_scope_summary(
            """
            SELECT DISTINCT s.prefix, s.privatespoof, s.routedspoof, s.last_update_ts
            FROM spoofing s
            JOIN spoofing_asn sa ON sa.prefix = s.prefix
            WHERE sa.asn = %s
            """,
            [normalized],
        )

    @cached()
    def get_country_spoofing(self, country: str) -> dict:
        normalized = self.validate_country_code(country)
        return self._spoofing_scope_summary(
            """
            SELECT DISTINCT s.prefix, s.privatespoof, s.routedspoof, s.last_update_ts
            FROM spoofing s
            JOIN spoofing_country sc ON sc.prefix = s.prefix
            WHERE sc.country = %s
            """,
            [normalized],
        )

    @cached()
    def get_country_dnssec(self, country: str) -> dict:
        normalized = self.validate_country_code(country)
        row = self._fetchone(
            """
            SELECT
                validating_pc::DOUBLE PRECISION AS dnssec_validating_pc,
                partial_validating_pc::DOUBLE PRECISION AS dnssec_partial_validating_pc,
                last_update_ts AS dnssec_last_update_ts
            FROM dnssec_country
            WHERE country = %s
            """,
            [normalized],
        )
        if not row:
            return {
                "dnssec_validating_pc": None,
                "dnssec_partial_validating_pc": None,
                "dnssec_last_update_ts": None,
            }
        return row

    def _spoofing_scope_summary(self, scope_sql: str, params: list) -> dict:
        row = self._fetchone(
            f"""
            WITH scoped_spoofing AS ({scope_sql})
            SELECT
                COUNT(*)::INTEGER AS spoofing_prefix_count,
                COUNT(*) FILTER (
                    WHERE LOWER(COALESCE(privatespoof, '')) IN ('received', 'rewritten')
                       OR LOWER(COALESCE(routedspoof, '')) IN ('received', 'rewritten')
                )::INTEGER AS spoofing_allow_count,
                COUNT(*) FILTER (
                    WHERE NOT (
                        LOWER(COALESCE(privatespoof, '')) IN ('received', 'rewritten')
                        OR LOWER(COALESCE(routedspoof, '')) IN ('received', 'rewritten')
                    )
                    AND (
                        LOWER(COALESCE(privatespoof, '')) = 'blocked'
                        OR LOWER(COALESCE(routedspoof, '')) = 'blocked'
                    )
                )::INTEGER AS spoofing_blocked_count,
                COUNT(*) FILTER (
                    WHERE NOT (
                        LOWER(COALESCE(privatespoof, '')) IN ('received', 'rewritten')
                        OR LOWER(COALESCE(routedspoof, '')) IN ('received', 'rewritten')
                        OR LOWER(COALESCE(privatespoof, '')) = 'blocked'
                        OR LOWER(COALESCE(routedspoof, '')) = 'blocked'
                    )
                )::INTEGER AS spoofing_unknown_count,
                MAX(last_update_ts) AS spoofing_last_update_ts
            FROM scoped_spoofing
            """,
            params,
        ) or {}
        total = row.get("spoofing_prefix_count", 0) or 0
        allow = row.get("spoofing_allow_count", 0) or 0
        return {
            "spoofing_prefix_count": total,
            "spoofing_allow_count": allow,
            "spoofing_blocked_count": row.get("spoofing_blocked_count", 0) or 0,
            "spoofing_unknown_count": row.get("spoofing_unknown_count", 0) or 0,
            "spoofing_allow_pc": self._pc(allow, total),
            "spoofing_last_update_ts": row.get("spoofing_last_update_ts"),
        }

    @cached()
    def get_asn_qmin(self, asn: str) -> dict:
        normalized = self.validate_asn(asn)
        summary = self._qmin_scope_summary(
            "SELECT DISTINCT resolver_id FROM resolver_asn WHERE asn = %s",
            [normalized],
        )
        return {"asn": normalized, **summary}

    @cached()
    def get_country_qmin(self, country: str) -> dict:
        normalized = self.validate_country_code(country)
        summary = self._qmin_scope_summary(
            "SELECT DISTINCT resolver_id FROM resolver_location WHERE country = %s",
            [normalized],
        )
        return {"country": normalized, **summary}

    @cached()
    def get_prefix_qmin(self, prefix: str) -> dict:
        normalized = self.validate_network_prefix(prefix)
        summary = self._qmin_scope_summary(
            "SELECT DISTINCT resolver_id FROM resolver_prefix WHERE prefix = %s::cidr",
            [normalized],
        )
        return {"prefix": normalized, **summary}

    def _qmin_scope_summary(self, scope_sql: str, params: list) -> dict:
        row = self._fetchone(
            f"""
            WITH scoped_resolver AS ({scope_sql})
            SELECT
                COUNT(q.resolver_id)::INTEGER AS measured_count,
                COUNT(q.resolver_id) FILTER (WHERE q.qmin = 'yes')::INTEGER AS yes_count,
                COUNT(q.resolver_id) FILTER (WHERE q.qmin = 'no')::INTEGER AS no_count,
                COUNT(q.resolver_id) FILTER (WHERE q.qmin = 'unstable')::INTEGER AS unstable_count,
                COUNT(q.resolver_id) FILTER (WHERE q.max_minimise_count > 10)::INTEGER
                    AS amplification_risk_count,
                MAX(q.last_update_ts) AS last_update_ts
            FROM scoped_resolver sr
            LEFT JOIN qmin_resolver q ON q.resolver_id = sr.resolver_id
            """,
            params,
        ) or {}
        max_distribution = self._fetchall(
            f"""
            WITH scoped_resolver AS ({scope_sql})
            , distribution AS (
                SELECT q.max_minimise_count AS value, COUNT(*)::INTEGER AS count
                FROM scoped_resolver sr
                JOIN qmin_resolver q ON q.resolver_id = sr.resolver_id
                WHERE q.max_minimise_count IS NOT NULL
                GROUP BY q.max_minimise_count
            )
            SELECT value, count,
                   ROUND(count * 100.0 / NULLIF(SUM(count) OVER (), 0), 2)::DOUBLE PRECISION AS percent
            FROM distribution
            ORDER BY count DESC, value
            LIMIT 10
            """,
            params,
        )
        one_label_distribution = self._fetchall(
            f"""
            WITH scoped_resolver AS ({scope_sql})
            , distribution AS (
                SELECT q.minimize_one_lab AS value, COUNT(*)::INTEGER AS count
                FROM scoped_resolver sr
                JOIN qmin_resolver q ON q.resolver_id = sr.resolver_id
                WHERE q.minimize_one_lab IS NOT NULL
                GROUP BY q.minimize_one_lab
            )
            SELECT value, count,
                   ROUND(count * 100.0 / NULLIF(SUM(count) OVER (), 0), 2)::DOUBLE PRECISION AS percent
            FROM distribution
            ORDER BY count DESC, value
            LIMIT 10
            """,
            params,
        )
        measured = row.get("measured_count", 0) or 0
        yes = row.get("yes_count", 0) or 0
        no = row.get("no_count", 0) or 0
        risk = row.get("amplification_risk_count", 0) or 0
        return {
            "measured_count": measured,
            "yes_count": yes,
            "no_count": no,
            "unstable_count": row.get("unstable_count", 0) or 0,
            "yes_pc": self._pc(yes, measured),
            "no_pc": self._pc(no, measured),
            "amplification_risk_count": risk,
            "amplification_risk_pc": self._pc(risk, measured),
            "max_minimise_distribution": max_distribution,
            "minimize_one_lab_distribution": one_label_distribution,
            "last_update_ts": row.get("last_update_ts"),
        }

    def _prefix_page(
        self,
        *,
        scope_sql: str,
        params: list,
        target: str,
        target_type: str,
        page: int,
        page_size: int,
    ) -> dict:
        totals = self._fetchone(
            f"""
            WITH scoped_resolver AS ({scope_sql})
            SELECT
                COUNT(DISTINCT sr.resolver_id)::INTEGER AS matched_resolver_count,
                COUNT(DISTINCT rp.resolver_id)::INTEGER AS mapped_resolver_count,
                COUNT(DISTINCT rp.prefix)::INTEGER AS total_prefixes
            FROM scoped_resolver sr
            LEFT JOIN resolver_prefix rp ON rp.resolver_id = sr.resolver_id
            """,
            params,
        ) or {}
        rows = self._fetchall(
            f"""
            WITH scoped_resolver AS ({scope_sql})
            SELECT rp.prefix::TEXT AS prefix, COUNT(DISTINCT sr.resolver_id)::INTEGER AS resolver_count
            FROM scoped_resolver sr
            JOIN resolver_prefix rp ON rp.resolver_id = sr.resolver_id
            GROUP BY rp.prefix
            ORDER BY resolver_count DESC, rp.prefix::TEXT
            LIMIT %s OFFSET %s
            """,
            [*params, page_size, (page - 1) * page_size],
        )
        matched = totals.get("matched_resolver_count", 0) or 0
        mapped = totals.get("mapped_resolver_count", 0) or 0
        return {
            "target": target,
            "target_type": target_type,
            "page": page,
            "page_size": page_size,
            "total_prefixes": totals.get("total_prefixes", 0) or 0,
            "matched_resolver_count": matched,
            "unmapped_resolver_count": max(matched - mapped, 0),
            "prefixes": rows,
        }

    @cached()
    def get_asn_prefixes(self, asn: str, page: int = 1, page_size: int = 25) -> dict:
        normalized = self.validate_asn(asn)
        return self._prefix_page(
            scope_sql="SELECT DISTINCT resolver_id FROM resolver_asn WHERE asn = %s",
            params=[normalized], target=f"AS{normalized}", target_type="asn", page=page, page_size=page_size,
        )

    @cached()
    def get_country_prefixes(self, country: str, page: int = 1, page_size: int = 25) -> dict:
        normalized = self.validate_country_code(country)
        return self._prefix_page(
            scope_sql="SELECT DISTINCT resolver_id FROM resolver_location WHERE country = %s",
            params=[normalized], target=normalized, target_type="country", page=page, page_size=page_size,
        )

    @cached()
    def get_qmin_state_prefixes(self, state: str, page: int = 1, page_size: int = 25) -> dict:
        normalized = state.strip().lower()
        states = {"enabled": "yes", "disabled": "no"}
        if normalized not in states:
            raise ValidationError("QMIN state must be 'enabled' or 'disabled'")
        return self._prefix_page(
            scope_sql="SELECT DISTINCT resolver_id FROM qmin_resolver WHERE qmin = %s",
            params=[states[normalized]], target=f"qmin:{normalized}", target_type="qmin",
            page=page, page_size=page_size,
        )

    def _qmin_risk_prefixes(
        self, scope_sql: str, params: list, target: str, target_type: str, page: int, page_size: int
    ) -> dict:
        return self._prefix_page(
            scope_sql=f"""
                WITH base_scope AS ({scope_sql})
                SELECT DISTINCT bs.resolver_id
                FROM base_scope bs
                JOIN qmin_resolver q ON q.resolver_id = bs.resolver_id
                WHERE q.max_minimise_count > 10
            """,
            params=params, target=target, target_type=target_type, page=page, page_size=page_size,
        )

    @cached()
    def get_global_qmin_risk_prefixes(self, page: int = 1, page_size: int = 25) -> dict:
        return self._qmin_risk_prefixes(
            "SELECT resolver_id FROM resolver", [], "global", "global", page, page_size
        )

    @cached()
    def get_asn_qmin_risk_prefixes(self, asn: str, page: int = 1, page_size: int = 25) -> dict:
        normalized = self.validate_asn(asn)
        return self._qmin_risk_prefixes(
            "SELECT resolver_id FROM resolver_asn WHERE asn = %s", [normalized], f"AS{normalized}", "asn", page, page_size
        )

    @cached()
    def get_country_qmin_risk_prefixes(self, country: str, page: int = 1, page_size: int = 25) -> dict:
        normalized = self.validate_country_code(country)
        return self._qmin_risk_prefixes(
            "SELECT resolver_id FROM resolver_location WHERE country = %s", [normalized], normalized, "country", page, page_size
        )

    @cached()
    def get_prefix_qmin_risk_prefixes(self, prefix: str, page: int = 1, page_size: int = 25) -> dict:
        normalized = self.validate_network_prefix(prefix)
        return self._qmin_risk_prefixes(
            "SELECT resolver_id FROM resolver_prefix WHERE prefix = %s::cidr", [normalized], normalized, "prefix", page, page_size
        )

    @cached()
    def get_asn_anycast(self, asn: str) -> dict:
        normalized = self.validate_asn(asn)
        row = self._fetchone(
            """
            SELECT
                %s::BIGINT AS asn,
                COUNT(DISTINCT a.prefix)::INTEGER AS prefix_count,
                MAX(a.last_update_ts) AS last_update_ts
            FROM anycast a
            LEFT JOIN anycast_asn aa ON aa.prefix = a.prefix
            LEFT JOIN anycast_asn_backend ab ON ab.prefix = a.prefix
            WHERE aa.asn = %s OR ab.asn = %s
            """,
            [normalized, normalized, normalized],
        )
        prefix_count = row["prefix_count"] if row else 0
        return {"asn": normalized, "anycast_found": bool(prefix_count), **(row or {"prefix_count": 0})}

    @cached()
    def get_country_anycast(self, country: str) -> dict:
        normalized = self.validate_country_code(country)
        row = self._fetchone(
            """
            SELECT
                %s AS country,
                COUNT(DISTINCT a.prefix)::INTEGER AS prefix_count,
                SUM(ac.country_count)::INTEGER AS site_count,
                MAX(ac.last_update_ts) AS last_update_ts
            FROM anycast a
            JOIN anycast_country_backend ac ON ac.prefix = a.prefix
            WHERE ac.country = %s
            """,
            [normalized, normalized],
        )
        prefix_count = row["prefix_count"] if row else 0
        return {"country": normalized, "anycast_found": bool(prefix_count), **(row or {"prefix_count": 0})}

    @cached()
    def get_asn_anycast_sites(self, asn: str) -> dict:
        normalized = self.validate_asn(asn)
        countries = self._fetchall(
            """
            SELECT
                ac.country,
                SUM(ac.country_count)::INTEGER AS count,
                MAX(cl.latitude) AS latitude,
                MAX(cl.longitude) AS longitude
            FROM anycast a
            JOIN anycast_country_backend ac ON ac.prefix = a.prefix
            LEFT JOIN country_location cl ON cl.country = ac.country
            WHERE EXISTS (
                SELECT 1 FROM anycast_asn aa WHERE aa.prefix = a.prefix AND aa.asn = %s
            ) OR EXISTS (
                SELECT 1 FROM anycast_asn_backend ab WHERE ab.prefix = a.prefix AND ab.asn = %s
            )
            GROUP BY ac.country
            ORDER BY count DESC, ac.country
            """,
            [normalized, normalized],
        )
        asns = self._fetchall(
            """
            SELECT ab.asn, SUM(ab.asn_count)::INTEGER AS count
            FROM anycast a
            JOIN anycast_asn_backend ab ON ab.prefix = a.prefix
            WHERE EXISTS (
                SELECT 1 FROM anycast_asn aa WHERE aa.prefix = a.prefix AND aa.asn = %s
            ) OR EXISTS (
                SELECT 1 FROM anycast_asn_backend ab2 WHERE ab2.prefix = a.prefix AND ab2.asn = %s
            )
            GROUP BY ab.asn
            ORDER BY count DESC, ab.asn
            """,
            [normalized, normalized],
        )
        return {"asn": normalized, "countries": countries, "asns": asns}

    @cached()
    def get_country_anycast_sites(self, country: str) -> dict:
        normalized = self.validate_country_code(country)
        countries = self._fetchall(
            """
            SELECT
                ac.country,
                SUM(ac.country_count)::INTEGER AS count,
                MAX(cl.latitude) AS latitude,
                MAX(cl.longitude) AS longitude
            FROM anycast_country_backend ac
            LEFT JOIN country_location cl ON cl.country = ac.country
            WHERE ac.country = %s
            GROUP BY ac.country
            """,
            [normalized],
        )
        asns = self._fetchall(
            """
            SELECT ab.asn, SUM(ab.asn_count)::INTEGER AS count
            FROM anycast_country_backend ac
            JOIN anycast_asn_backend ab ON ab.prefix = ac.prefix
            WHERE ac.country = %s
            GROUP BY ab.asn
            ORDER BY count DESC, ab.asn
            """,
            [normalized],
        )
        return {"country": normalized, "countries": countries, "asns": asns}

    @cached()
    def get_country_counts(self, country: str) -> dict:
        normalized = self.validate_country_code(country)
        summary = self._scoped_summary(
            resolver_scope_sql="""
                SELECT DISTINCT r.resolver_id, r.ip, r.is_public
                FROM resolver r
                JOIN resolver_location rl ON rl.resolver_id = r.resolver_id
                WHERE rl.country = %s
            """,
            resolver_params=[normalized],
            forwarder_scope_sql="""
                SELECT DISTINCT f.forwarder_id, f.type
                FROM forwarder f
                JOIN forwarder_location fl ON fl.forwarder_id = f.forwarder_id
                WHERE fl.country = %s
            """,
            forwarder_params=[normalized],
            anycast_sql="""
                SELECT
                    (SELECT COUNT(DISTINCT prefix) FROM anycast_country_backend WHERE country = %s)::INTEGER
                        AS anycast_prefix_count,
                    (SELECT COALESCE(SUM(country_count), 0) FROM anycast_country_backend WHERE country = %s)::INTEGER
                        AS anycast_country_instance_count,
                    (
                        SELECT COALESCE(SUM(ab.asn_count), 0)
                        FROM anycast_asn_backend ab
                        WHERE EXISTS (
                            SELECT 1
                            FROM anycast_country_backend ac
                            WHERE ac.prefix = ab.prefix
                              AND ac.country = %s
                        )
                    )::INTEGER AS anycast_asn_instance_count
                FROM anycast_country_backend ac
                WHERE ac.country = %s
                LIMIT 1
            """,
            anycast_params=[normalized, normalized, normalized, normalized],
        )
        summary.update(self.get_country_spoofing(normalized))
        summary.update(self.get_country_dnssec(normalized))
        return summary

    @cached()
    def get_asn_counts(self, asn: str) -> dict:
        normalized = self.validate_asn(asn)
        summary = self._scoped_summary(
            resolver_scope_sql="""
                SELECT DISTINCT r.resolver_id, r.ip, r.is_public
                FROM resolver r
                JOIN resolver_asn ra ON ra.resolver_id = r.resolver_id
                WHERE ra.asn = %s
            """,
            resolver_params=[normalized],
            forwarder_scope_sql="""
                SELECT DISTINCT f.forwarder_id, f.type
                FROM forwarder f
                JOIN forwarder_asn fa ON fa.forwarder_id = f.forwarder_id
                WHERE fa.asn = %s
            """,
            forwarder_params=[normalized],
            anycast_sql="""
                WITH scoped_prefix AS (
                    SELECT DISTINCT prefix FROM anycast_asn WHERE asn = %s
                    UNION
                    SELECT DISTINCT prefix FROM anycast_asn_backend WHERE asn = %s
                )
                SELECT
                    COUNT(DISTINCT sp.prefix)::INTEGER AS anycast_prefix_count,
                    (
                        SELECT COALESCE(SUM(ac.country_count), 0)
                        FROM anycast_country_backend ac
                        JOIN scoped_prefix sp2 ON sp2.prefix = ac.prefix
                    )::INTEGER AS anycast_country_instance_count,
                    (
                        SELECT COALESCE(SUM(ab.asn_count), 0)
                        FROM anycast_asn_backend ab
                        WHERE ab.asn = %s
                    )::INTEGER AS anycast_asn_instance_count
                FROM scoped_prefix sp
            """,
            anycast_params=[normalized, normalized, normalized],
        )
        summary.update(self.get_asn_spoofing(str(normalized)))
        return summary

    @cached()
    def get_prefix_counts(self, prefix: str) -> dict:
        normalized = self.validate_network_prefix(prefix)
        return self._target_counts("rp.prefix = %s::cidr", [normalized])

    def _target_counts(self, where_sql: str, params: list) -> dict:
        row = self._fetchone(
            f"""
            SELECT
                COUNT(DISTINCT r.resolver_id)::INTEGER AS country_resolver_count,
                COUNT(DISTINCT r.resolver_id) FILTER (WHERE r.is_public IS TRUE)::INTEGER AS public_resolver_count,
                COUNT(DISTINCT r.resolver_id) FILTER (WHERE r.is_public IS FALSE)::INTEGER AS closed_resolver_count,
                COUNT(DISTINCT r.resolver_id) FILTER (
                    WHERE EXISTS (SELECT 1 FROM anycast a WHERE r.ip <<= a.prefix)
                )::INTEGER AS anycast_resolver_count
            FROM resolver r
            LEFT JOIN resolver_asn ra ON ra.resolver_id = r.resolver_id
            LEFT JOIN resolver_prefix rp ON rp.resolver_id = r.resolver_id
            LEFT JOIN resolver_location rl ON rl.resolver_id = r.resolver_id
            WHERE {where_sql}
            """,
            params,
        ) or {}
        return {
            "country_resolver_count": row.get("country_resolver_count", 0) or 0,
            "public_resolver_count": row.get("public_resolver_count", 0) or 0,
            "closed_resolver_count": row.get("closed_resolver_count", 0) or 0,
            "anycast_resolver_count": row.get("anycast_resolver_count", 0) or 0,
            "forwarder_count": None,
            "dnssec_validating_pc": None,
            "dnssec_partial_validating_pc": None,
        }

    def _pc(self, part: int, whole: int) -> float:
        return round((part / whole) * 100, 2) if whole else 0.0

    def _spoofing_entity_page(self, entity_type: str, page: int, page_size: int) -> dict:
        if entity_type == "country":
            entity_key = "country"
            target_type = "spoofing_countries"
            grouped_sql = f"""
                affected_resolver AS MATERIALIZED (
                    SELECT DISTINCT r.resolver_id
                    FROM resolver r
                    WHERE EXISTS (
                        SELECT 1 FROM spoofing s
                        WHERE r.ip <<= s.prefix AND {self._SPOOFING_ALLOW_SQL}
                    )
                ),
                grouped_entity AS (
                    SELECT
                        rl.country,
                        COUNT(DISTINCT ar.resolver_id)::INTEGER AS resolver_count,
                        COUNT(DISTINCT rp.prefix)::INTEGER AS prefix_count
                    FROM affected_resolver ar
                    JOIN resolver_location rl ON rl.resolver_id = ar.resolver_id
                    LEFT JOIN resolver_prefix rp ON rp.resolver_id = ar.resolver_id
                    GROUP BY rl.country
                )
            """
        else:
            entity_key = "asn"
            target_type = "spoofing_asns"
            grouped_sql = f"""
                qualifying_asn AS MATERIALIZED (
                    SELECT DISTINCT sa.asn
                    FROM spoofing_asn sa
                    JOIN spoofing s ON s.prefix = sa.prefix
                    WHERE {self._SPOOFING_ALLOW_SQL}
                ),
                grouped_entity AS (
                    SELECT
                        ra.asn,
                        COUNT(ra.resolver_id)::INTEGER AS resolver_count,
                        COUNT(DISTINCT rp.prefix)::INTEGER AS prefix_count
                    FROM qualifying_asn qa
                    JOIN resolver_asn ra ON ra.asn = qa.asn
                    LEFT JOIN resolver_prefix rp ON rp.resolver_id = ra.resolver_id
                    GROUP BY ra.asn
                )
            """
        rows = self._fetchall(
            f"""
            WITH {grouped_sql},
            paged_entity AS (
                SELECT *
                FROM grouped_entity
                ORDER BY resolver_count DESC, {entity_key}
                LIMIT %s OFFSET %s
            ),
            totals AS (
                SELECT
                    COUNT(*)::INTEGER AS total_entities,
                    COALESCE(SUM(resolver_count), 0)::BIGINT AS matched_resolver_count
                FROM grouped_entity
            )
            SELECT
                p.{entity_key}, p.resolver_count, p.prefix_count,
                t.total_entities, t.matched_resolver_count
            FROM totals t
            LEFT JOIN paged_entity p ON TRUE
            ORDER BY p.resolver_count DESC, p.{entity_key}
            """,
            [page_size, (page - 1) * page_size],
        )
        total_entities = rows[0].get("total_entities", 0) if rows else 0
        matched_resolver_count = rows[0].get("matched_resolver_count", 0) if rows else 0
        entities = [
            {key: value for key, value in row.items() if key not in {"total_entities", "matched_resolver_count"}}
            for row in rows
            if row.get(entity_key) is not None
        ]
        return {
            "target_type": target_type,
            "page": page,
            "page_size": page_size,
            "total_entities": total_entities or 0,
            "matched_resolver_count": matched_resolver_count or 0,
            "entities": entities,
        }

    @cached()
    def get_spoofing_countries(self, page: int = 1, page_size: int = 25) -> dict:
        return self._spoofing_entity_page("country", page, page_size)

    @cached()
    def get_spoofing_asns(self, page: int = 1, page_size: int = 25) -> dict:
        return self._spoofing_entity_page("asn", page, page_size)

    @cached()
    def get_country_spoofing_prefixes(self, country: str, page: int = 1, page_size: int = 25) -> dict:
        normalized = self.validate_country_code(country)
        return self._prefix_page(
            scope_sql=f"""
                SELECT DISTINCT r.resolver_id
                FROM resolver r
                JOIN resolver_location rl ON rl.resolver_id = r.resolver_id
                WHERE rl.country = %s
                  AND EXISTS (
                      SELECT 1 FROM spoofing s
                      WHERE r.ip <<= s.prefix AND {self._SPOOFING_ALLOW_SQL}
                  )
            """,
            params=[normalized], target=normalized, target_type="spoofing_country",
            page=page, page_size=page_size,
        )

    @cached()
    def get_asn_spoofing_prefixes(self, asn: str, page: int = 1, page_size: int = 25) -> dict:
        normalized = self.validate_asn(asn)
        return self._prefix_page(
            scope_sql=f"""
                SELECT DISTINCT ra.resolver_id
                FROM resolver_asn ra
                JOIN spoofing_asn sa ON sa.asn = ra.asn
                JOIN spoofing s ON s.prefix = sa.prefix
                WHERE ra.asn = %s AND {self._SPOOFING_ALLOW_SQL}
            """,
            params=[normalized], target=f"AS{normalized}", target_type="spoofing_asn",
            page=page, page_size=page_size,
        )

    def _scoped_summary(
        self,
        *,
        resolver_scope_sql: str,
        resolver_params: list,
        forwarder_scope_sql: str,
        forwarder_params: list,
        anycast_sql: str,
        anycast_params: list,
    ) -> dict:
        resolver_row = self._fetchone(
            f"""
            WITH scoped_resolver AS ({resolver_scope_sql})
            SELECT
                COUNT(*)::INTEGER AS country_resolver_count,
                COUNT(*) FILTER (WHERE is_public IS TRUE)::INTEGER AS public_resolver_count,
                COUNT(*) FILTER (WHERE is_public IS FALSE)::INTEGER AS closed_resolver_count,
                COUNT(*) FILTER (
                    WHERE EXISTS (SELECT 1 FROM anycast a WHERE scoped_resolver.ip <<= a.prefix)
                )::INTEGER AS anycast_resolver_count
            FROM scoped_resolver
            """,
            resolver_params,
        ) or {}
        qmin_row = self._fetchone(
            f"""
            WITH scoped_resolver AS ({resolver_scope_sql})
            SELECT
                COUNT(q.resolver_id)::INTEGER AS qmin_measured_count,
                COUNT(q.resolver_id) FILTER (WHERE q.qmin = 'yes')::INTEGER AS qmin_yes_count,
                COUNT(q.resolver_id) FILTER (WHERE q.qmin = 'no')::INTEGER AS qmin_no_count,
                COUNT(q.resolver_id) FILTER (WHERE q.qmin = 'unstable')::INTEGER AS qmin_unstable_count
            FROM scoped_resolver sr
            LEFT JOIN qmin_resolver q ON q.resolver_id = sr.resolver_id
            """,
            resolver_params,
        ) or {}
        forwarder_row = self._fetchone(
            f"""
            WITH scoped_forwarder AS ({forwarder_scope_sql})
            SELECT
                COUNT(*)::INTEGER AS forwarder_count,
                COUNT(*) FILTER (WHERE LOWER(type) = 'recursive')::INTEGER AS recursive_forwarder_count,
                COUNT(*) FILTER (WHERE LOWER(type) = 'transparent')::INTEGER AS transparent_forwarder_count
            FROM scoped_forwarder
            """,
            forwarder_params,
        ) or {}
        anycast_row = self._fetchone(anycast_sql, anycast_params) or {}

        resolver_count = resolver_row.get("country_resolver_count", 0) or 0
        qmin_measured = qmin_row.get("qmin_measured_count", 0) or 0
        anycast_resolver_count = resolver_row.get("anycast_resolver_count", 0) or 0
        qmin_yes = qmin_row.get("qmin_yes_count", 0) or 0
        qmin_no = qmin_row.get("qmin_no_count", 0) or 0

        return {
            "country_resolver_count": resolver_count,
            "public_resolver_count": resolver_row.get("public_resolver_count", 0) or 0,
            "closed_resolver_count": resolver_row.get("closed_resolver_count", 0) or 0,
            "anycast_resolver_count": anycast_resolver_count,
            "anycast_resolver_pc": self._pc(anycast_resolver_count, resolver_count),
            "forwarder_count": forwarder_row.get("forwarder_count", 0) or 0,
            "recursive_forwarder_count": forwarder_row.get("recursive_forwarder_count", 0) or 0,
            "transparent_forwarder_count": forwarder_row.get("transparent_forwarder_count", 0) or 0,
            "qmin_measured_count": qmin_measured,
            "qmin_yes_count": qmin_yes,
            "qmin_no_count": qmin_no,
            "qmin_unstable_count": qmin_row.get("qmin_unstable_count", 0) or 0,
            "qmin_yes_pc": self._pc(qmin_yes, qmin_measured),
            "qmin_no_pc": self._pc(qmin_no, qmin_measured),
            "anycast_prefix_count": anycast_row.get("anycast_prefix_count", 0) or 0,
            "anycast_country_instance_count": anycast_row.get("anycast_country_instance_count", 0) or 0,
            "anycast_asn_instance_count": anycast_row.get("anycast_asn_instance_count", 0) or 0,
            "dnssec_validating_pc": None,
            "dnssec_partial_validating_pc": None,
        }

    @cached(ttl=120)
    def get_global_ip_version_summary(self, family: int) -> dict:
        row = self._fetchone(
            """
            SELECT
                COUNT(*)::INTEGER AS resolver_count,
                COUNT(*) FILTER (WHERE is_public IS TRUE)::INTEGER AS public_count,
                MAX(last_update_ts) AS last_observation_ts
            FROM resolver
            WHERE family(ip) = %s
            """,
            [family],
        ) or {}
        resolver_count = row.get("resolver_count", 0) or 0
        public_count = row.get("public_count", 0) or 0
        return {
            "family": family,
            "resolver_count": resolver_count,
            "public_count": public_count,
            "public_percent": self._pc(public_count, resolver_count),
            "last_observation_ts": row.get("last_observation_ts"),
        }

    @cached(ttl=120)
    def get_global_dual_stack_summary(self) -> dict:
        row = self._fetchone(
            """
            SELECT COUNT(*)::INTEGER AS dual_stack_count
            FROM (
                SELECT resolver_id
                FROM resolver
                GROUP BY resolver_id
                HAVING BOOL_OR(family(ip) = 4) AND BOOL_OR(family(ip) = 6)
            ) dual_stack
            """
        ) or {}
        return {"dual_stack_count": row.get("dual_stack_count", 0) or 0}

    @cached(ttl=120)
    def get_global_scope_summary(self) -> dict:
        row = self._fetchone(
            """
            SELECT
                (SELECT COUNT(*)::INTEGER FROM resolver) AS resolver_count,
                (SELECT COUNT(DISTINCT asn)::INTEGER FROM resolver_asn WHERE asn IS NOT NULL) AS resolver_unique_asn_count,
                (SELECT COUNT(DISTINCT country)::INTEGER FROM resolver_location WHERE country IS NOT NULL) AS resolver_unique_country_count,
                (SELECT MAX(last_update_ts) FROM resolver) AS last_observation_ts
            """
        ) or {}
        return {
            "resolver_count": row.get("resolver_count", 0) or 0,
            "resolver_unique_asn_count": row.get("resolver_unique_asn_count", 0) or 0,
            "resolver_unique_country_count": row.get("resolver_unique_country_count", 0) or 0,
            "last_observation_ts": row.get("last_observation_ts"),
        }

    @cached(ttl=900)
    def get_global_data_source_summary(self) -> dict:
        source_rows = self._fetchall(
            """
            SELECT
                ds.source,
                ds.url,
                ds.description,
                COUNT(r.ip)::INTEGER AS resolver_count
            FROM data_source ds
            LEFT JOIN resolver r ON r.source = ds.source
            GROUP BY ds.source, ds.url, ds.description
            ORDER BY resolver_count DESC, ds.source
            """
        )
        resolver_count = sum((row.get("resolver_count", 0) or 0) for row in source_rows)
        distribution = [
            {
                "source": row["source"],
                "url": row.get("url"),
                "description": row.get("description"),
                "resolver_count": row.get("resolver_count", 0) or 0,
                "resolver_pc": self._pc(row.get("resolver_count", 0) or 0, resolver_count),
            }
            for row in source_rows
            if (row.get("resolver_count", 0) or 0) > 0
        ]

        github_rows = self._fetchall(
            """
            SELECT source, url, api_endpoint, documentation_endpoint, description
            FROM data_source
            WHERE LOWER(COALESCE(url, '')) LIKE '%%github%%'
               OR LOWER(COALESCE(api_endpoint, '')) LIKE '%%github%%'
               OR LOWER(COALESCE(documentation_endpoint, '')) LIKE '%%github%%'
            ORDER BY source
            """
        )

        def github_repository_url(row: dict) -> str | None:
            candidates = [
                row.get("documentation_endpoint"),
                row.get("url"),
                row.get("api_endpoint"),
            ]
            for candidate in candidates:
                if not candidate or "github" not in candidate.lower():
                    continue
                parsed = urllib.parse.urlparse(candidate)
                hostname = (parsed.hostname or "").lower()
                path_parts = [part for part in parsed.path.split("/") if part]
                if hostname in {"github.com", "www.github.com", "raw.githubusercontent.com"} and len(path_parts) >= 2:
                    return f"https://github.com/{path_parts[0]}/{path_parts[1].removesuffix('.git')}"
            return None

        github_repositories = []
        seen_repositories = set()
        for row in github_rows:
            source = (row.get("source") or "").lower()
            if source.startswith("measurements.") or source.startswith("zdns."):
                continue
            repository_url = github_repository_url(row)
            if not repository_url or repository_url in seen_repositories:
                continue
            seen_repositories.add(repository_url)
            parsed = urllib.parse.urlparse(repository_url)
            repository_name = parsed.path.strip("/")
            github_repositories.append(
                {
                    "name": repository_name,
                    "url": repository_url,
                    "description": row.get("description"),
                }
            )

        return {
            "resolver_count": resolver_count,
            "sources": [
                {
                    "source": row["source"],
                    "url": row.get("url"),
                    "description": row.get("description"),
                }
                for row in source_rows
            ],
            "distribution": distribution,
            "github_repositories": github_repositories,
        }

    @cached(ttl=900)
    def get_global_resolver_practice_summary(self) -> dict:
        rows = self._fetchall(
            """
            WITH dual_stack_resolver AS MATERIALIZED (
                SELECT resolver_id
                FROM resolver
                GROUP BY resolver_id
                HAVING BOOL_OR(family(ip) = 4) AND BOOL_OR(family(ip) = 6)
            ),
            safe_qmin_resolver AS MATERIALIZED (
                SELECT resolver_id
                FROM qmin_resolver
                WHERE LOWER(COALESCE(qmin, '')) = 'yes'
                  AND max_minimise_count <= 10
            ),
            secure_protocol_resolver AS MATERIALIZED (
                SELECT DISTINCT resolver_id
                FROM resolver_service
                WHERE supported IS TRUE
                  AND (
                      LOWER(TRIM(protocol)) IN ('doq', 'dot')
                      OR LOWER(TRIM(protocol)) LIKE 'doh%%'
                  )
            ),
            resolver_feature AS (
                SELECT
                    r.is_public,
                    dr.validates IS TRUE AS validates_dnssec,
                    EXISTS (
                        SELECT 1
                        FROM anycast a
                        WHERE r.ip <<= a.prefix
                    ) AS is_anycast,
                    sq.resolver_id IS NOT NULL AS has_safe_qmin,
                    ds.resolver_id IS NOT NULL AS is_dual_stack,
                    sp.resolver_id IS NOT NULL AS has_secure_protocol
                FROM resolver r
                LEFT JOIN dnssec_resolver dr ON dr.ip = r.ip
                LEFT JOIN safe_qmin_resolver sq ON sq.resolver_id = r.resolver_id
                LEFT JOIN dual_stack_resolver ds ON ds.resolver_id = r.resolver_id
                LEFT JOIN secure_protocol_resolver sp ON sp.resolver_id = r.resolver_id
            )
            SELECT
                is_public,
                COUNT(*)::INTEGER AS resolver_count,
                COUNT(*) FILTER (WHERE validates_dnssec)::INTEGER AS dnssec_validating_count,
                COUNT(*) FILTER (WHERE is_anycast)::INTEGER AS anycast_count,
                COUNT(*) FILTER (WHERE has_safe_qmin)::INTEGER AS qmin_safe_count,
                COUNT(*) FILTER (WHERE is_dual_stack)::INTEGER AS dual_stack_count,
                COUNT(*) FILTER (WHERE has_secure_protocol)::INTEGER AS secure_protocol_count
            FROM resolver_feature
            GROUP BY is_public
            """
        )

        def empty_scope() -> dict:
            return {
                "resolver_count": 0,
                "dnssec_validating_count": 0,
                "dnssec_validating_pc": 0.0,
                "anycast_count": 0,
                "anycast_pc": 0.0,
                "qmin_safe_count": 0,
                "qmin_safe_pc": 0.0,
                "dual_stack_count": 0,
                "dual_stack_pc": 0.0,
                "secure_protocol_count": 0,
                "secure_protocol_pc": 0.0,
            }

        summary = {"open": empty_scope(), "closed": empty_scope()}
        for row in rows:
            resolver_count = row.get("resolver_count", 0) or 0
            dnssec_count = row.get("dnssec_validating_count", 0) or 0
            anycast_count = row.get("anycast_count", 0) or 0
            qmin_safe_count = row.get("qmin_safe_count", 0) or 0
            dual_stack_count = row.get("dual_stack_count", 0) or 0
            secure_protocol_count = row.get("secure_protocol_count", 0) or 0
            scope = "open" if row.get("is_public") is True else "closed"
            summary[scope] = {
                "resolver_count": resolver_count,
                "dnssec_validating_count": dnssec_count,
                "dnssec_validating_pc": self._pc(dnssec_count, resolver_count),
                "anycast_count": anycast_count,
                "anycast_pc": self._pc(anycast_count, resolver_count),
                "qmin_safe_count": qmin_safe_count,
                "qmin_safe_pc": self._pc(qmin_safe_count, resolver_count),
                "dual_stack_count": dual_stack_count,
                "dual_stack_pc": self._pc(dual_stack_count, resolver_count),
                "secure_protocol_count": secure_protocol_count,
                "secure_protocol_pc": self._pc(secure_protocol_count, resolver_count),
            }
        return summary

    @cached(ttl=900)
    def get_global_resolver_practice_metric(self, scope: str, metric: str) -> dict:
        normalized_scope = scope.strip().lower()
        if normalized_scope not in {"open", "closed"}:
            raise ValidationError("Resolver scope must be 'open' or 'closed'")

        predicates = {
            "dnssec-validation": """
                EXISTS (
                    SELECT 1
                    FROM dnssec_resolver dr
                    WHERE dr.ip = r.ip AND dr.validates IS TRUE
                )
            """,
            "anycast": """
                EXISTS (
                    SELECT 1
                    FROM anycast a
                    WHERE r.ip <<= a.prefix
                )
            """,
            "proper-qmin": """
                EXISTS (
                    SELECT 1
                    FROM qmin_resolver q
                    WHERE q.resolver_id = r.resolver_id
                      AND LOWER(COALESCE(q.qmin, '')) = 'yes'
                      AND q.max_minimise_count <= 10
                )
            """,
            "dual-stack": """
                EXISTS (
                    SELECT 1 FROM resolver r4
                    WHERE r4.resolver_id = r.resolver_id AND family(r4.ip) = 4
                )
                AND EXISTS (
                    SELECT 1 FROM resolver r6
                    WHERE r6.resolver_id = r.resolver_id AND family(r6.ip) = 6
                )
            """,
            "secure-protocols": """
                EXISTS (
                    SELECT 1
                    FROM resolver_service rs
                    WHERE rs.resolver_id = r.resolver_id
                      AND rs.supported IS TRUE
                      AND (
                          LOWER(TRIM(rs.protocol)) IN ('doq', 'dot')
                          OR LOWER(TRIM(rs.protocol)) LIKE 'doh%%'
                      )
                )
            """,
        }
        normalized_metric = metric.strip().lower()
        if normalized_metric != "resolver-count" and normalized_metric not in predicates:
            raise ValidationError(f"Unsupported resolver practice metric: {metric}")

        is_public = normalized_scope == "open"
        if normalized_metric == "resolver-count":
            row = self._fetchone(
                "SELECT COUNT(*)::INTEGER AS resolver_count FROM resolver WHERE is_public = %s",
                [is_public],
            ) or {}
            resolver_count = row.get("resolver_count", 0) or 0
            return {
                "scope": normalized_scope,
                "metric": normalized_metric,
                "resolver_count": resolver_count,
                "count": resolver_count,
                "percent": 100.0 if resolver_count else 0.0,
            }

        row = self._fetchone(
            f"""
            SELECT
                COUNT(*)::INTEGER AS resolver_count,
                COUNT(*) FILTER (WHERE {predicates[normalized_metric]})::INTEGER AS metric_count
            FROM resolver r
            WHERE r.is_public = %s
            """,
            [is_public],
        ) or {}
        resolver_count = row.get("resolver_count", 0) or 0
        metric_count = row.get("metric_count", 0) or 0
        return {
            "scope": normalized_scope,
            "metric": normalized_metric,
            "resolver_count": resolver_count,
            "count": metric_count,
            "percent": self._pc(metric_count, resolver_count),
        }

    @cached(ttl=900)
    def get_global_dnssec_practice_detail(self, scope: str) -> dict:
        normalized_scope = scope.strip().lower()
        if normalized_scope == "country":
            row = self._fetchone(
                """
                SELECT
                    COUNT(*)::INTEGER AS country_count,
                    COALESCE(AVG(validating_pc), 0)::DOUBLE PRECISION AS validating_pc,
                    COALESCE(AVG(partial_validating_pc), 0)::DOUBLE PRECISION AS unknown_pc
                FROM dnssec_country
                """
            ) or {}
            validating_pc = max(0.0, min(100.0, float(row.get("validating_pc", 0) or 0)))
            unknown_pc = max(
                0.0,
                min(100.0 - validating_pc, float(row.get("unknown_pc", 0) or 0)),
            )
            not_validating_pc = max(0.0, 100.0 - validating_pc - unknown_pc)
            return {
                "scope": normalized_scope,
                "country_count": row.get("country_count", 0) or 0,
                "validating_pc": round(validating_pc, 2),
                "not_validating_pc": round(not_validating_pc, 2),
                "unknown_pc": round(unknown_pc, 2),
            }

        if normalized_scope not in {"open", "closed"}:
            raise ValidationError("DNSSEC detail scope must be 'open', 'closed', or 'country'")
        row = self._fetchone(
            """
            SELECT
                COUNT(*)::INTEGER AS resolver_count,
                COUNT(*) FILTER (WHERE dr.validates IS TRUE)::INTEGER AS validating_count,
                COUNT(*) FILTER (WHERE dr.validates IS FALSE)::INTEGER AS not_validating_count,
                COUNT(*) FILTER (WHERE dr.ip IS NULL OR dr.validates IS NULL)::INTEGER AS unknown_count
            FROM resolver r
            LEFT JOIN dnssec_resolver dr ON dr.ip = r.ip
            WHERE r.is_public = %s
            """,
            [normalized_scope == "open"],
        ) or {}
        resolver_count = row.get("resolver_count", 0) or 0
        validating_count = row.get("validating_count", 0) or 0
        not_validating_count = row.get("not_validating_count", 0) or 0
        unknown_count = row.get("unknown_count", 0) or 0
        return {
            "scope": normalized_scope,
            "resolver_count": resolver_count,
            "validating_count": validating_count,
            "not_validating_count": not_validating_count,
            "unknown_count": unknown_count,
            "validating_pc": self._pc(validating_count, resolver_count),
            "not_validating_pc": self._pc(not_validating_count, resolver_count),
            "unknown_pc": self._pc(unknown_count, resolver_count),
        }

    @cached(ttl=900)
    def get_global_qmin_practice_detail(self, scope: str) -> dict:
        normalized_scope = scope.strip().lower()
        if normalized_scope not in {"open", "closed"}:
            raise ValidationError("QMIN detail scope must be 'open' or 'closed'")
        row = self._fetchone(
            """
            SELECT
                COUNT(*)::INTEGER AS resolver_count,
                COUNT(*) FILTER (
                    WHERE LOWER(TRIM(COALESCE(q.qmin, ''))) = 'yes'
                      AND q.max_minimise_count <= 10
                )::INTEGER AS proper_count,
                COUNT(*) FILTER (
                    WHERE LOWER(TRIM(COALESCE(q.qmin, ''))) = 'yes'
                      AND q.max_minimise_count > 10
                )::INTEGER AS risk_count,
                COUNT(*) FILTER (
                    WHERE LOWER(TRIM(COALESCE(q.qmin, ''))) = 'no'
                )::INTEGER AS not_implemented_count,
                COUNT(*) FILTER (
                    WHERE LOWER(TRIM(COALESCE(q.qmin, ''))) = 'unstable'
                )::INTEGER AS unstable_count
            FROM resolver r
            LEFT JOIN qmin_resolver q ON q.resolver_id = r.resolver_id
            WHERE r.is_public = %s
            """,
            [normalized_scope == "open"],
        ) or {}
        resolver_count = row.get("resolver_count", 0) or 0
        proper_count = row.get("proper_count", 0) or 0
        risk_count = row.get("risk_count", 0) or 0
        not_implemented_count = row.get("not_implemented_count", 0) or 0
        unstable_count = row.get("unstable_count", 0) or 0
        unknown_count = max(
            resolver_count
            - proper_count
            - risk_count
            - not_implemented_count
            - unstable_count,
            0,
        )
        return {
            "scope": normalized_scope,
            "resolver_count": resolver_count,
            "proper_count": proper_count,
            "risk_count": risk_count,
            "not_implemented_count": not_implemented_count,
            "unstable_count": unstable_count,
            "unknown_count": unknown_count,
            "proper_pc": self._pc(proper_count, resolver_count),
            "risk_pc": self._pc(risk_count, resolver_count),
            "not_implemented_pc": self._pc(not_implemented_count, resolver_count),
            "unstable_pc": self._pc(unstable_count, resolver_count),
            "unknown_pc": self._pc(unknown_count, resolver_count),
        }

    @cached(ttl=900)
    def get_global_manrs_practice_detail(self, entity_type: str, scope: str) -> dict:
        normalized_entity_type = entity_type.strip().lower()
        normalized_scope = scope.strip().lower()
        if normalized_entity_type not in {"asn", "country"}:
            raise ValidationError("MANRS entity type must be 'asn' or 'country'")
        if normalized_scope not in {"open", "closed"}:
            raise ValidationError("MANRS resolver scope must be 'open' or 'closed'")

        if normalized_entity_type == "asn":
            entity_sql = """
                SELECT DISTINCT ra.asn::BIGINT AS entity
                FROM resolver r
                JOIN resolver_asn ra ON ra.resolver_id = r.resolver_id
                WHERE r.is_public = %s AND ra.asn > 0
            """
            score_table = "manrs_asn"
            score_key = "asn"
        else:
            entity_sql = """
                SELECT DISTINCT UPPER(rl.country) AS entity
                FROM resolver r
                JOIN resolver_location rl ON rl.resolver_id = r.resolver_id
                WHERE r.is_public = %s AND rl.country ~ '^[A-Za-z]{3}$'
            """
            score_table = "manrs_country"
            score_key = "country"

        row = self._fetchone(
            f"""
            WITH scoped_entities AS (
                {entity_sql}
            ),
            entity_scores AS (
                SELECT
                    scoped.entity,
                    (
                        SELECT AVG(metric.score)
                        FROM (
                            VALUES
                                (scores.anti_spoofing_score),
                                (scores.coordination_score),
                                (scores.filtering_score),
                                (scores.routing_information_irr_score),
                                (scores.routing_information_rpki_score)
                        ) AS metric(score)
                        WHERE metric.score IS NOT NULL
                    ) AS readiness_score
                FROM scoped_entities scoped
                LEFT JOIN {score_table} scores ON scores.{score_key} = scoped.entity
            )
            SELECT
                COUNT(*)::INTEGER AS entity_count,
                COUNT(readiness_score)::INTEGER AS scored_entity_count,
                COALESCE(AVG(readiness_score) * 100.0, 0)::DOUBLE PRECISION
                    AS average_readiness_pc
            FROM entity_scores
            """,
            [normalized_scope == "open"],
        ) or {}
        entity_count = row.get("entity_count", 0) or 0
        scored_entity_count = row.get("scored_entity_count", 0) or 0
        average_readiness_pc = max(
            0.0,
            min(100.0, float(row.get("average_readiness_pc", 0) or 0)),
        )
        return {
            "entity_type": normalized_entity_type,
            "scope": normalized_scope,
            "entity_count": entity_count,
            "scored_entity_count": scored_entity_count,
            "unscored_entity_count": max(entity_count - scored_entity_count, 0),
            "average_readiness_pc": round(average_readiness_pc, 2),
        }

    @cached(ttl=900)
    def get_global_bcp38_practice_detail(self, scope: str) -> dict:
        normalized_scope = scope.strip().lower()
        if normalized_scope not in {"open", "closed"}:
            raise ValidationError("BCP38 resolver scope must be 'open' or 'closed'")

        row = self._fetchone(
            f"""
            WITH scoped_resolvers AS MATERIALIZED (
                SELECT DISTINCT
                    r.resolver_id,
                    ra.asn
                FROM resolver r
                LEFT JOIN resolver_asn ra ON ra.resolver_id = r.resolver_id
                WHERE r.is_public = %s
            ),
            caida_allowing_asns AS MATERIALIZED (
                SELECT DISTINCT sa.asn
                FROM spoofing_asn sa
                JOIN spoofing s ON s.prefix = sa.prefix
                WHERE s.source = 'caida-spoofer'
                  AND {self._SPOOFING_ALLOW_SQL}
            ),
            transparent_forwarder_asns AS MATERIALIZED (
                SELECT DISTINCT fa.asn::BIGINT AS asn
                FROM forwarder f
                JOIN forwarder_asn fa ON fa.forwarder_id = f.forwarder_id
                WHERE (
                        LOWER(TRIM(f.type)) = 'transparent'
                        OR f.transparent_count > 0
                    )
                  AND fa.asn > 0
                  AND f.source = 'odns-api'
            ),
            allowing_asns AS MATERIALIZED (
                SELECT asn FROM caida_allowing_asns
                UNION
                SELECT asn FROM transparent_forwarder_asns
            ),
            caida_blocking_asns AS MATERIALIZED (
                SELECT DISTINCT sa.asn
                FROM spoofing_asn sa
                JOIN spoofing s ON s.prefix = sa.prefix
                WHERE s.source = 'caida-spoofer'
                  AND NOT {self._SPOOFING_ALLOW_SQL}
                  AND (
                      LOWER(COALESCE(s.privatespoof, '')) = 'blocked'
                      OR LOWER(COALESCE(s.routedspoof, '')) = 'blocked'
                  )
            ),
            resolver_evidence AS MATERIALIZED (
                SELECT
                    sr.resolver_id,
                    BOOL_OR(allowing.asn IS NOT NULL) AS allows_spoofing,
                    BOOL_OR(blocking.asn IS NOT NULL) AS blocks_spoofing
                FROM scoped_resolvers sr
                LEFT JOIN allowing_asns allowing ON allowing.asn = sr.asn
                LEFT JOIN caida_blocking_asns blocking ON blocking.asn = sr.asn
                GROUP BY sr.resolver_id
            )
            SELECT
                COUNT(*)::INTEGER AS resolver_count,
                COUNT(*) FILTER (WHERE allows_spoofing)::INTEGER
                    AS allowing_resolver_count,
                COUNT(*) FILTER (
                    WHERE NOT allows_spoofing AND blocks_spoofing
                )::INTEGER AS blocking_resolver_count,
                (SELECT COUNT(*)::INTEGER FROM caida_allowing_asns)
                    AS caida_allowing_asn_count,
                (SELECT COUNT(*)::INTEGER FROM transparent_forwarder_asns)
                    AS transparent_forwarder_asn_count,
                (SELECT COUNT(*)::INTEGER FROM caida_blocking_asns)
                    AS caida_blocking_asn_count
            FROM resolver_evidence
            """,
            [normalized_scope == "open"],
        ) or {}
        resolver_count = row.get("resolver_count", 0) or 0
        allowing_resolver_count = row.get("allowing_resolver_count", 0) or 0
        blocking_resolver_count = row.get("blocking_resolver_count", 0) or 0
        unknown_resolver_count = max(
            resolver_count - allowing_resolver_count - blocking_resolver_count,
            0,
        )
        return {
            "scope": normalized_scope,
            "resolver_count": resolver_count,
            "allowing_resolver_count": allowing_resolver_count,
            "allowing_resolver_pc": self._pc(allowing_resolver_count, resolver_count),
            "blocking_resolver_count": blocking_resolver_count,
            "blocking_resolver_pc": self._pc(blocking_resolver_count, resolver_count),
            "unknown_resolver_count": unknown_resolver_count,
            "unknown_resolver_pc": self._pc(unknown_resolver_count, resolver_count),
            "caida_allowing_asn_count": row.get("caida_allowing_asn_count", 0) or 0,
            "transparent_forwarder_asn_count": row.get("transparent_forwarder_asn_count", 0) or 0,
            "caida_blocking_asn_count": row.get("caida_blocking_asn_count", 0) or 0,
        }

    @cached(ttl=900)
    def get_global_anycast_summary(self) -> dict:
        row = self._fetchone(
            """
            SELECT
                COUNT(*)::INTEGER AS resolver_count,
                COUNT(*) FILTER (
                    WHERE EXISTS (SELECT 1 FROM anycast a WHERE resolver.ip <<= a.prefix)
                )::INTEGER AS resolver_anycast_count
            FROM resolver
            """
        ) or {}
        rankings = self._fetchone(
            """
            WITH resolver_anycast_prefix AS (
                SELECT DISTINCT r.resolver_id, r.ip, a.prefix
                FROM resolver r
                JOIN anycast a ON r.ip <<= a.prefix
            ),
            country_agg AS (
                SELECT
                    rap.resolver_id,
                    rap.ip,
                    COALESCE(SUM(ac.country_count), 0)::INTEGER AS anycast_site_count,
                    COUNT(DISTINCT ac.country)::INTEGER AS anycast_country_count
                FROM resolver_anycast_prefix rap
                LEFT JOIN anycast_country_backend ac ON ac.prefix = rap.prefix
                GROUP BY rap.resolver_id, rap.ip
            ),
            asn_agg AS (
                SELECT
                    rap.resolver_id,
                    rap.ip,
                    COUNT(DISTINCT ab.asn)::INTEGER AS anycast_asn_count
                FROM resolver_anycast_prefix rap
                LEFT JOIN anycast_asn_backend ab ON ab.prefix = rap.prefix
                GROUP BY rap.resolver_id, rap.ip
            ),
            resolver_stats AS MATERIALIZED (
                SELECT
                    host(c.ip) AS ip,
                    COALESCE(NULLIF(TRIM(ro.org), ''), 'Unknown') AS company,
                    c.anycast_site_count,
                    c.anycast_country_count,
                    COALESCE(a.anycast_asn_count, 0)::INTEGER AS anycast_asn_count
                FROM country_agg c
                LEFT JOIN asn_agg a
                    ON a.resolver_id = c.resolver_id
                   AND a.ip = c.ip
                LEFT JOIN resolver_org ro ON ro.resolver_id = c.resolver_id
            ),
            company_prefixes AS MATERIALIZED (
                SELECT DISTINCT
                    TRIM(ro.org) AS company,
                    rap.prefix
                FROM resolver_anycast_prefix rap
                JOIN resolver_org ro ON ro.resolver_id = rap.resolver_id
                WHERE NULLIF(TRIM(ro.org), '') IS NOT NULL
            ),
            company_site_stats AS MATERIALIZED (
                SELECT
                    cp.company,
                    COALESCE(SUM(ac.country_count), 0)::BIGINT AS anycast_site_count
                FROM company_prefixes cp
                LEFT JOIN anycast_country_backend ac ON ac.prefix = cp.prefix
                GROUP BY cp.company
            ),
            company_ip_stats AS MATERIALIZED (
                SELECT
                    TRIM(ro.org) AS company,
                    COUNT(DISTINCT rap.ip)::INTEGER AS anycast_ip_count
                FROM resolver_anycast_prefix rap
                JOIN resolver_org ro ON ro.resolver_id = rap.resolver_id
                WHERE NULLIF(TRIM(ro.org), '') IS NOT NULL
                GROUP BY TRIM(ro.org)
            ),
            company_stats AS MATERIALIZED (
                SELECT
                    sites.company,
                    sites.anycast_site_count,
                    ips.anycast_ip_count
                FROM company_site_stats sites
                JOIN company_ip_stats ips ON ips.company = sites.company
            )
            SELECT
                COALESCE((
                    SELECT JSONB_AGG(
                        TO_JSONB(ranked)
                        ORDER BY ranked.anycast_site_count DESC,
                                 ranked.anycast_country_count DESC,
                                 ranked.anycast_asn_count DESC,
                                 ranked.ip
                    )
                    FROM (
                        SELECT
                            ip,
                            company,
                            anycast_site_count,
                            anycast_country_count,
                            anycast_asn_count
                        FROM resolver_stats
                        ORDER BY anycast_site_count DESC,
                                 anycast_country_count DESC,
                                 anycast_asn_count DESC,
                                 ip
                        LIMIT 5
                    ) ranked
                ), '[]'::JSONB) AS top_anycast_resolvers,
                COALESCE((
                    SELECT JSONB_AGG(
                        TO_JSONB(ranked_company)
                        ORDER BY ranked_company.anycast_site_count DESC,
                                 ranked_company.anycast_ip_count DESC,
                                 ranked_company.company
                    )
                    FROM (
                        SELECT
                            company,
                            anycast_site_count,
                            anycast_ip_count
                        FROM company_stats
                        ORDER BY anycast_site_count DESC,
                                 anycast_ip_count DESC,
                                 company
                        LIMIT 5
                    ) ranked_company
                ), '[]'::JSONB) AS top_anycast_companies
            """
        ) or {}
        top_anycast_resolvers = rankings.get("top_anycast_resolvers", []) or []
        top_anycast_companies = rankings.get("top_anycast_companies", []) or []
        if isinstance(top_anycast_resolvers, str):
            top_anycast_resolvers = json.loads(top_anycast_resolvers)
        if isinstance(top_anycast_companies, str):
            top_anycast_companies = json.loads(top_anycast_companies)
        resolver_count = row.get("resolver_count", 0) or 0
        resolver_anycast_count = row.get("resolver_anycast_count", 0) or 0
        return {
            "resolver_count": resolver_count,
            "resolver_anycast_count": resolver_anycast_count,
            "resolver_anycast_pc": self._pc(resolver_anycast_count, resolver_count),
            "top_anycast_resolvers": top_anycast_resolvers,
            "top_anycast_companies": top_anycast_companies,
        }

    @cached(ttl=900)
    def get_global_qmin_summary(self) -> dict:
        row = self._fetchone(
            """
            SELECT
                COUNT(DISTINCT resolver_id)::INTEGER AS qmin_measured_count,
                COUNT(DISTINCT resolver_id) FILTER (WHERE qmin = 'yes')::INTEGER AS qmin_enabled_count,
                COUNT(DISTINCT resolver_id) FILTER (WHERE max_minimise_count > 10)::INTEGER AS qmin_amplification_risk_count
            FROM qmin_resolver
            """
        ) or {}
        qmin_max_minimise = self._fetchall(
            """
            WITH distribution AS (
                SELECT max_minimise_count AS value, COUNT(*)::INTEGER AS count
                FROM qmin_resolver
                WHERE max_minimise_count IS NOT NULL
                GROUP BY max_minimise_count
            )
            SELECT value, count,
                   ROUND(count * 100.0 / NULLIF(SUM(count) OVER (), 0), 2)::DOUBLE PRECISION AS percent
            FROM distribution
            ORDER BY count DESC, value
            LIMIT 10
            """
        )
        qmin_minimize_one_lab = self._fetchall(
            """
            WITH distribution AS (
                SELECT minimize_one_lab AS value, COUNT(*)::INTEGER AS count
                FROM qmin_resolver
                WHERE minimize_one_lab IS NOT NULL
                GROUP BY minimize_one_lab
            )
            SELECT value, count,
                   ROUND(count * 100.0 / NULLIF(SUM(count) OVER (), 0), 2)::DOUBLE PRECISION AS percent
            FROM distribution
            ORDER BY count DESC, value
            LIMIT 10
            """
        )
        measured = row.get("qmin_measured_count", 0) or 0
        enabled = row.get("qmin_enabled_count", 0) or 0
        risk = row.get("qmin_amplification_risk_count", 0) or 0
        return {
            "qmin_measured_count": measured,
            "qmin_enabled_count": enabled,
            "qmin_enabled_pc": self._pc(enabled, measured),
            "qmin_amplification_risk_count": risk,
            "qmin_amplification_risk_pc": self._pc(risk, measured),
            "qmin_max_minimise_distribution": qmin_max_minimise,
            "qmin_minimize_one_lab_distribution": qmin_minimize_one_lab,
        }

    @cached(ttl=900)
    def get_global_protocol_summary(self) -> dict:
        total_row = self._fetchone("SELECT COUNT(DISTINCT resolver_id)::INTEGER AS resolver_count FROM resolver") or {}
        resolver_count = total_row.get("resolver_count", 0) or 0
        protocol_rows = self._fetchall(
            """
            WITH per_resolver_protocol AS (
                SELECT resolver_id, protocol, BOOL_OR(supported)::BOOLEAN AS supported
                FROM resolver_service
                WHERE protocol IS NOT NULL AND TRIM(protocol) <> ''
                GROUP BY resolver_id, protocol
            )
            SELECT
                protocol,
                COUNT(*)::INTEGER AS tested_count,
                COUNT(*) FILTER (WHERE supported IS TRUE)::INTEGER AS count,
                COUNT(*) FILTER (WHERE supported IS FALSE)::INTEGER AS unsupported_count
            FROM per_resolver_protocol
            GROUP BY protocol
            ORDER BY count DESC, protocol
            """
        )
        port_rows = self._fetchall(
            """
            WITH per_resolver_port AS (
                SELECT resolver_id, port, BOOL_OR(supported)::BOOLEAN AS supported
                FROM resolver_service
                WHERE port IS NOT NULL
                GROUP BY resolver_id, port
            )
            SELECT
                port,
                COUNT(*)::INTEGER AS tested_count,
                COUNT(*) FILTER (WHERE supported IS TRUE)::INTEGER AS count,
                COUNT(*) FILTER (WHERE supported IS FALSE)::INTEGER AS unsupported_count
            FROM per_resolver_port
            GROUP BY port
            ORDER BY count DESC, port
            """
        )
        service_rows = self._fetchall(
            """
            SELECT
                protocol,
                port,
                COUNT(DISTINCT resolver_id)::INTEGER AS tested_count,
                COUNT(DISTINCT resolver_id) FILTER (WHERE supported IS TRUE)::INTEGER AS count,
                COUNT(DISTINCT resolver_id) FILTER (WHERE supported IS FALSE)::INTEGER AS unsupported_count
            FROM resolver_service
            WHERE protocol IS NOT NULL
              AND TRIM(protocol) <> ''
              AND port IS NOT NULL
            GROUP BY protocol, port
            ORDER BY count DESC, protocol, port
            """
        )
        return {
            "resolver_count": resolver_count,
            "protocols": [
                {
                    "protocol": row["protocol"],
                    "count": row["count"],
                    "tested_count": row["tested_count"],
                    "unsupported_count": row["unsupported_count"],
                    "percent": self._pc(row["count"], resolver_count),
                    "tested_percent": self._pc(row["tested_count"], resolver_count),
                    "support_rate_pc": self._pc(row["count"], row["tested_count"]),
                }
                for row in protocol_rows
            ],
            "ports": [
                {
                    "port": row["port"],
                    "count": row["count"],
                    "tested_count": row["tested_count"],
                    "unsupported_count": row["unsupported_count"],
                    "percent": self._pc(row["count"], resolver_count),
                    "tested_percent": self._pc(row["tested_count"], resolver_count),
                    "support_rate_pc": self._pc(row["count"], row["tested_count"]),
                }
                for row in port_rows
            ],
            "services": [
                {
                    "protocol": row["protocol"],
                    "port": row["port"],
                    "count": row["count"],
                    "tested_count": row["tested_count"],
                    "unsupported_count": row["unsupported_count"],
                    "percent": self._pc(row["count"], resolver_count),
                    "tested_percent": self._pc(row["tested_count"], resolver_count),
                    "support_rate_pc": self._pc(row["count"], row["tested_count"]),
                }
                for row in service_rows
            ],
        }

    @cached(ttl=120)
    def get_global_spoofing_environment_summary(self) -> dict:
        total_row = self._fetchone("SELECT COUNT(*)::INTEGER AS resolver_count FROM resolver") or {}
        row = self._fetchone(
            f"""
            SELECT
                (
                    SELECT COUNT(*)::INTEGER
                    FROM resolver r
                    WHERE EXISTS (
                        SELECT 1
                        FROM spoofing s
                        WHERE r.ip <<= s.prefix
                          AND {self._SPOOFING_ALLOW_SQL}
                    )
                ) AS resolver_spoofing_allow_count,
                (
                    SELECT COUNT(*)::INTEGER
                    FROM resolver r
                    WHERE EXISTS (
                        SELECT 1
                        FROM spoofing s
                        WHERE r.ip <<= s.prefix
                          AND NOT {self._SPOOFING_ALLOW_SQL}
                          AND (
                              LOWER(COALESCE(s.privatespoof, '')) = 'blocked'
                              OR LOWER(COALESCE(s.routedspoof, '')) = 'blocked'
                          )
                    )
                ) AS resolver_spoofing_blocked_count,
                (
                    SELECT COUNT(DISTINCT ra.resolver_id)::INTEGER
                    FROM resolver_asn ra
                    WHERE EXISTS (
                        SELECT 1
                        FROM spoofing_asn sa
                        JOIN spoofing s ON s.prefix = sa.prefix
                        WHERE sa.asn = ra.asn
                          AND {self._SPOOFING_ALLOW_SQL}
                    )
                ) AS resolver_spoofing_allow_asn_resolver_count,
                (
                    SELECT COUNT(DISTINCT ra.asn)::INTEGER
                    FROM resolver_asn ra
                    WHERE EXISTS (
                        SELECT 1
                        FROM spoofing_asn sa
                        JOIN spoofing s ON s.prefix = sa.prefix
                        WHERE sa.asn = ra.asn
                          AND {self._SPOOFING_ALLOW_SQL}
                    )
                ) AS spoofing_allow_asn_match_count
            """
        ) or {}
        resolver_count = total_row.get("resolver_count", 0) or 0
        allow_count = row.get("resolver_spoofing_allow_count", 0) or 0
        blocked_count = row.get("resolver_spoofing_blocked_count", 0) or 0
        asn_resolver_count = row.get("resolver_spoofing_allow_asn_resolver_count", 0) or 0
        return {
            "resolver_count": resolver_count,
            "resolver_spoofing_allow_count": allow_count,
            "resolver_spoofing_allow_pc": self._pc(allow_count, resolver_count),
            "resolver_spoofing_blocked_count": blocked_count,
            "resolver_spoofing_blocked_pc": self._pc(blocked_count, resolver_count),
            "resolver_spoofing_allow_asn_resolver_count": asn_resolver_count,
            "resolver_spoofing_allow_asn_resolver_pc": self._pc(asn_resolver_count, resolver_count),
            "spoofing_allow_asn_match_count": row.get("spoofing_allow_asn_match_count", 0) or 0,
        }

    @cached(ttl=120)
    def get_global_country_summary(self) -> dict:
        countries = self._fetchall(
            """
            SELECT
                rl.country,
                COUNT(*)::INTEGER AS count,
                COUNT(*) FILTER (WHERE r.is_public IS TRUE)::INTEGER AS public_count,
                COUNT(*) FILTER (WHERE r.is_public IS FALSE)::INTEGER AS closed_count,
                MAX(cl.latitude) AS latitude,
                MAX(cl.longitude) AS longitude
            FROM resolver_location rl
            JOIN resolver r ON r.resolver_id = rl.resolver_id
            LEFT JOIN country_location cl ON cl.country = rl.country
            GROUP BY rl.country
            ORDER BY count DESC, rl.country
            LIMIT 250
            """
        )
        return {"countries": countries, "top_countries": countries[:10]}

    @cached(ttl=120)
    def get_global_asn_summary(self) -> dict:
        rows = self._fetchall(
            """
            SELECT asn, COUNT(DISTINCT resolver_id)::INTEGER AS count
            FROM resolver_asn
            WHERE asn IS NOT NULL
            GROUP BY asn
            ORDER BY count DESC, asn
            LIMIT 10
            """
        )
        return {"top_asns": rows}

    @cached(ttl=120)
    def get_global_dnssec_summary(self) -> dict:
        row = self._fetchone(
            """
            SELECT
                COUNT(DISTINCT country)::INTEGER AS dnssec_country_count,
                COALESCE(AVG(validating_pc), 0)::DOUBLE PRECISION AS dnssec_validating_avg,
                MAX(last_update_ts) AS last_update_ts
            FROM dnssec_country
            """
        ) or {}
        return {
            "dnssec_country_count": row.get("dnssec_country_count", 0) or 0,
            "dnssec_validating_avg": round(float(row.get("dnssec_validating_avg", 0) or 0), 2),
            "last_update_ts": row.get("last_update_ts"),
        }

    @cached()
    def get_forwarder_relay_summary_by_ip(self, ip: str) -> dict:
        normalized = self.validate_ip_address(ip)
        row = self._fetchone(
            """
            WITH target_resolver AS (
                SELECT resolver_id
                FROM resolver
                WHERE ip = %s::inet
            ),
            relaying_forwarders AS (
                SELECT DISTINCT fru.forwarder_id
                FROM forwarder_resolver_upstream fru
                JOIN target_resolver tr ON tr.resolver_id = fru.upstream_resolver_id
            )
            SELECT
                COUNT(DISTINCT rf.forwarder_id)::INTEGER AS forwarder_entry_count,
                COUNT(DISTINCT fa.asn)::INTEGER AS forwarder_asn_count,
                COUNT(DISTINCT fl.country)::INTEGER AS forwarder_country_count,
                COUNT(DISTINCT rf.forwarder_id) FILTER (
                    WHERE EXISTS (
                        SELECT 1
                        FROM forwarder_protocol fp
                        WHERE fp.forwarder_id = rf.forwarder_id
                          AND LOWER(fp.protocol) = 'tcp'
                          AND fp.supported IS TRUE
                    )
                )::INTEGER AS forwarder_tcp_count,
                COUNT(DISTINCT rf.forwarder_id) FILTER (
                    WHERE EXISTS (
                        SELECT 1
                        FROM forwarder_protocol fp
                        WHERE fp.forwarder_id = rf.forwarder_id
                          AND LOWER(fp.protocol) = 'udp'
                          AND fp.supported IS TRUE
                    )
                )::INTEGER AS forwarder_udp_count,
                COUNT(DISTINCT rf.forwarder_id) FILTER (
                    WHERE EXISTS (
                        SELECT 1
                        FROM forwarder_protocol fp
                        WHERE fp.forwarder_id = rf.forwarder_id
                          AND LOWER(fp.protocol) = 'tcp'
                          AND fp.supported IS TRUE
                    )
                    AND EXISTS (
                        SELECT 1
                        FROM forwarder_protocol fp
                        WHERE fp.forwarder_id = rf.forwarder_id
                          AND LOWER(fp.protocol) = 'udp'
                          AND fp.supported IS TRUE
                    )
                )::INTEGER AS forwarder_tcp_udp_count
            FROM relaying_forwarders rf
            LEFT JOIN forwarder_asn fa ON fa.forwarder_id = rf.forwarder_id
            LEFT JOIN forwarder_location fl ON fl.forwarder_id = rf.forwarder_id
            """,
            [normalized],
        ) or {}
        countries = self._fetchall(
            """
            WITH target_resolver AS (
                SELECT resolver_id
                FROM resolver
                WHERE ip = %s::inet
            ),
            relaying_forwarders AS (
                SELECT DISTINCT fru.forwarder_id
                FROM forwarder_resolver_upstream fru
                JOIN target_resolver tr ON tr.resolver_id = fru.upstream_resolver_id
            )
            SELECT
                fl.country,
                COUNT(DISTINCT rf.forwarder_id)::INTEGER AS count
            FROM relaying_forwarders rf
            JOIN forwarder_location fl ON fl.forwarder_id = rf.forwarder_id
            WHERE fl.country IS NOT NULL
            GROUP BY fl.country
            ORDER BY count DESC, fl.country
            """,
            [normalized],
        )
        asns = self._fetchall(
            """
            WITH target_resolver AS (
                SELECT resolver_id
                FROM resolver
                WHERE ip = %s::inet
            ),
            relaying_forwarders AS (
                SELECT DISTINCT fru.forwarder_id
                FROM forwarder_resolver_upstream fru
                JOIN target_resolver tr ON tr.resolver_id = fru.upstream_resolver_id
            )
            SELECT
                fa.asn,
                COUNT(DISTINCT rf.forwarder_id)::INTEGER AS count
            FROM relaying_forwarders rf
            JOIN forwarder_asn fa ON fa.forwarder_id = rf.forwarder_id
            WHERE fa.asn IS NOT NULL
            GROUP BY fa.asn
            ORDER BY count DESC, fa.asn
            """,
            [normalized],
        )
        return {
            "forwarder_entry_count": row.get("forwarder_entry_count", 0) or 0,
            "forwarder_asn_count": row.get("forwarder_asn_count", 0) or 0,
            "forwarder_country_count": row.get("forwarder_country_count", 0) or 0,
            "forwarder_tcp_count": row.get("forwarder_tcp_count", 0) or 0,
            "forwarder_udp_count": row.get("forwarder_udp_count", 0) or 0,
            "forwarder_tcp_udp_count": row.get("forwarder_tcp_udp_count", 0) or 0,
            "forwarder_countries": countries,
            "forwarder_asns": asns,
        }

    @cached()
    def get_upstream_forwarder_lists_by_ip(
        self,
        ip: str,
        page: int = 1,
        page_size: int = 100,
    ) -> dict:
        normalized = self.validate_ip_address(ip)
        total_row = self._fetchone(
            """
            SELECT COUNT(DISTINCT fru.forwarder_id)::INTEGER AS total_forwarders
            FROM forwarder_resolver_upstream fru
            JOIN resolver r ON r.resolver_id = fru.upstream_resolver_id
            WHERE r.ip = %s::INET
            """,
            [normalized],
        )
        forwarders = self._fetchall(
            """
            WITH target_resolver AS (
                SELECT resolver_id
                FROM resolver
                WHERE ip = %s::INET
            ),
            relaying_forwarders AS (
                SELECT DISTINCT fru.forwarder_id
                FROM forwarder_resolver_upstream fru
                JOIN target_resolver tr ON tr.resolver_id = fru.upstream_resolver_id
            )
            SELECT
                host(f.ip) AS ip,
                f.type,
                f.is_public,
                f.last_update_ts
            FROM relaying_forwarders rf
            JOIN forwarder f ON f.forwarder_id = rf.forwarder_id
            ORDER BY f.ip
            LIMIT %s OFFSET %s
            """,
            [normalized, page_size, (page - 1) * page_size],
        )
        countries = self._fetchall(
            """
            WITH target_resolver AS (
                SELECT resolver_id
                FROM resolver
                WHERE ip = %s::INET
            ),
            relaying_forwarders AS (
                SELECT DISTINCT fru.forwarder_id
                FROM forwarder_resolver_upstream fru
                JOIN target_resolver tr ON tr.resolver_id = fru.upstream_resolver_id
            )
            SELECT
                fl.country,
                COUNT(DISTINCT rf.forwarder_id)::INTEGER AS count
            FROM relaying_forwarders rf
            JOIN forwarder_location fl ON fl.forwarder_id = rf.forwarder_id
            WHERE fl.country IS NOT NULL AND fl.country <> ''
            GROUP BY fl.country
            ORDER BY count DESC, fl.country
            """,
            [normalized],
        )
        asns = self._fetchall(
            """
            WITH target_resolver AS (
                SELECT resolver_id
                FROM resolver
                WHERE ip = %s::INET
            ),
            relaying_forwarders AS (
                SELECT DISTINCT fru.forwarder_id
                FROM forwarder_resolver_upstream fru
                JOIN target_resolver tr ON tr.resolver_id = fru.upstream_resolver_id
            )
            SELECT
                fa.asn,
                COUNT(DISTINCT rf.forwarder_id)::INTEGER AS count
            FROM relaying_forwarders rf
            JOIN forwarder_asn fa ON fa.forwarder_id = rf.forwarder_id
            WHERE fa.asn IS NOT NULL
            GROUP BY fa.asn
            ORDER BY count DESC, fa.asn
            """,
            [normalized],
        )
        return {
            "resolver_ip": normalized,
            "page": page,
            "page_size": page_size,
            "total_forwarders": (total_row or {}).get("total_forwarders", 0) or 0,
            "forwarders": [
                {
                    "ip": row["ip"],
                    "type": row.get("type"),
                    "is_public": row.get("is_public"),
                    "last_update_ts": row.get("last_update_ts"),
                }
                for row in forwarders
            ],
            "countries": countries,
            "asns": asns,
        }

    @cached()
    def get_anycast_summary_by_ip(self, ip: str) -> dict:
        core = self.get_resolver_core(ip)
        anycast = self.get_resolver_anycast(ip)
        sites = self.get_resolver_anycast_sites(ip)
        qmin = self.get_resolver_qmin(ip)
        dnssec = self.get_resolver_dnssec(ip)
        spoofing = self.get_resolver_spoofing(ip)
        forwarders = self.get_forwarder_relay_summary_by_ip(ip)
        resolver = core.get("resolver") or {}
        qmin_value = qmin.get("qmin")
        alternative_ips = self.get_resolver_alternative_ips(resolver.get("id"))
        sibling_ips = self.get_resolver_sibling_ips(resolver.get("id"), core["resolver_ip"])
        resolver_domains = self.get_resolver_domains(resolver.get("id"))
        resolver_services = self.get_resolver_services(resolver.get("id"))
        resolver_protocol_results = self.get_resolver_protocol_results(resolver.get("id"))
        resolver_dohpath = self.get_resolver_dohpath(resolver.get("id"))
        tokens = self._protocol_tokens(",".join(resolver_services) or resolver.get("supported_protocols"))
        return {
            "resolver_ip": core["resolver_ip"],
            "resolver_found": core["found"],
            "resolver_asn": resolver.get("asn"),
            "resolver_prefix": resolver.get("bgp_prefix"),
            "resolver_country": resolver.get("country"),
            "resolver_city": resolver.get("city"),
            "resolver_org": resolver.get("org"),
            "resolver_domain": ", ".join(resolver_domains) if resolver_domains else resolver.get("domain"),
            "resolver_domains": resolver_domains,
            "resolver_qmin": qmin_value,
            "resolver_qmin_max_minimise_count": qmin.get("max_minimise_count"),
            "resolver_dohpath": resolver_dohpath,
            "resolver_qmin_minimize_one_lab": qmin.get("minimize_one_lab"),
            "resolver_dnssec_validates": dnssec.get("resolver_dnssec_validates"),
            "resolver_is_public": resolver.get("is_public"),
            "resolver_supported_protocols": ",".join(resolver_services) if resolver_services else resolver.get("supported_protocols"),
            "resolver_services": resolver_services,
            "resolver_protocol_results": resolver_protocol_results,
            "resolver_supports_tcp": "dotcp" in tokens,
            "resolver_supports_udp": "doudp" in tokens,
            "resolver_supports_ipv4": any(row.get("family") == 4 for row in alternative_ips),
            "resolver_supports_ipv6": any(row.get("family") == 6 for row in alternative_ips),
            "alternative_resolver_ips": [row["ip"] for row in alternative_ips],
            "sibling_resolver_ips": [row["ip"] for row in sibling_ips],
            **spoofing,
            "anycast_found": anycast["anycast_found"],
            "anycast_site_count": sum(item.get("count") or 0 for item in sites["countries"]),
            "anycast_country_count": len(sites["countries"]),
            "anycast_asn_count": len(sites["asns"]),
            "anycast_countries": [
                {
                    "country": item["country"],
                    "site_count": item["count"],
                    "latitude": item.get("latitude"),
                    "longitude": item.get("longitude"),
                }
                for item in sites["countries"]
            ],
            "last_observation_ts": resolver.get("last_observation_ts") or qmin.get("last_update_ts") or anycast.get("last_update_ts"),
            **forwarders,
        }


dns_resilience_service = DNSResilienceService()
