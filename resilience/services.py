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
                ) FILTER (WHERE rs.protocol IS NOT NULL AND rs.port IS NOT NULL) AS supported_protocols
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
    def get_resolvers_by_domain(self, domain: str, limit: int = 100) -> list[dict]:
        normalized = self.validate_domain(domain)
        sql, params = self._resolver_select("LOWER(rd.domain) = LOWER(%s)", limit=limit)
        return self._fetchall(sql, [normalized, *params])

    @cached()
    def get_resolvers_by_service(self, service: str, limit: int = 100) -> tuple[str, list[dict]]:
        protocol, port = self.validate_resolver_service(service)
        if port is None:
            sql, params = self._resolver_select("LOWER(rs.protocol) = %s", limit=limit)
            return protocol, self._fetchall(sql, [protocol, *params])
        sql, params = self._resolver_select("LOWER(rs.protocol) = %s AND rs.port = %s", limit=limit)
        return f"{protocol}:{port}", self._fetchall(sql, [protocol, port, *params])

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
            SELECT
                host(ip) AS ip,
                family(ip)::INTEGER AS family
            FROM resolver
            WHERE resolver_id = %s
            ORDER BY family(ip), ip::TEXT
            """,
            [resolver_id],
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
    def get_resolver_services(self, resolver_id: int | None) -> list[str]:
        if not resolver_id:
            return []
        rows = self._fetchall(
            """
            SELECT protocol, port
            FROM resolver_service
            WHERE resolver_id = %s
            ORDER BY protocol, port
            """,
            [resolver_id],
        )
        return [f"{row['protocol']}:{row['port']}" for row in rows]

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
        row = self._fetchone(
            """
            SELECT
                %s::BIGINT AS asn,
                COUNT(q.resolver_id)::INTEGER AS measured_count,
                COUNT(*) FILTER (WHERE q.qmin = 'yes')::INTEGER AS yes_count,
                COUNT(*) FILTER (WHERE q.qmin = 'no')::INTEGER AS no_count,
                COUNT(*) FILTER (WHERE q.qmin = 'unstable')::INTEGER AS unstable_count,
                MAX(q.last_update_ts) AS last_update_ts
            FROM resolver_asn ra
            JOIN resolver r ON r.resolver_id = ra.resolver_id
            LEFT JOIN qmin_resolver q ON q.resolver_id = r.resolver_id
            WHERE ra.asn = %s
            """,
            [normalized, normalized],
        )
        return row or {"asn": normalized, "measured_count": 0}

    @cached()
    def get_country_qmin(self, country: str) -> dict:
        normalized = self.validate_country_code(country)
        row = self._fetchone(
            """
            SELECT
                %s AS country,
                COUNT(q.resolver_id)::INTEGER AS measured_count,
                COUNT(*) FILTER (WHERE q.qmin = 'yes')::INTEGER AS yes_count,
                COUNT(*) FILTER (WHERE q.qmin = 'no')::INTEGER AS no_count,
                COUNT(*) FILTER (WHERE q.qmin = 'unstable')::INTEGER AS unstable_count,
                MAX(q.last_update_ts) AS last_update_ts
            FROM resolver_location rl
            JOIN resolver r ON r.resolver_id = rl.resolver_id
            LEFT JOIN qmin_resolver q ON q.resolver_id = r.resolver_id
            WHERE rl.country = %s
            """,
            [normalized, normalized],
        )
        return row or {"country": normalized, "measured_count": 0}

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

    @cached(ttl=120)
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
        top_anycast_resolvers = self._fetchall(
            """
            WITH resolver_anycast_prefix AS (
                SELECT r.ip, a.prefix
                FROM resolver r
                JOIN anycast a ON r.ip <<= a.prefix
            ),
            country_agg AS (
                SELECT
                    rap.ip,
                    COALESCE(SUM(ac.country_count), 0)::INTEGER AS anycast_site_count,
                    COUNT(DISTINCT ac.country)::INTEGER AS anycast_country_count
                FROM resolver_anycast_prefix rap
                LEFT JOIN anycast_country_backend ac ON ac.prefix = rap.prefix
                GROUP BY rap.ip
            ),
            asn_agg AS (
                SELECT
                    rap.ip,
                    COUNT(DISTINCT ab.asn)::INTEGER AS anycast_asn_count
                FROM resolver_anycast_prefix rap
                LEFT JOIN anycast_asn_backend ab ON ab.prefix = rap.prefix
                GROUP BY rap.ip
            )
            SELECT
                host(c.ip) AS ip,
                c.anycast_site_count,
                c.anycast_country_count,
                COALESCE(a.anycast_asn_count, 0)::INTEGER AS anycast_asn_count
            FROM country_agg c
            LEFT JOIN asn_agg a ON a.ip = c.ip
            ORDER BY c.anycast_site_count DESC, c.anycast_country_count DESC, COALESCE(a.anycast_asn_count, 0) DESC, host(c.ip)
            LIMIT 5
            """
        )
        resolver_count = row.get("resolver_count", 0) or 0
        resolver_anycast_count = row.get("resolver_anycast_count", 0) or 0
        return {
            "resolver_count": resolver_count,
            "resolver_anycast_count": resolver_anycast_count,
            "resolver_anycast_pc": self._pc(resolver_anycast_count, resolver_count),
            "top_anycast_resolvers": top_anycast_resolvers,
        }

    @cached(ttl=120)
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
            SELECT max_minimise_count AS value, COUNT(*)::INTEGER AS count
            FROM qmin_resolver
            WHERE max_minimise_count IS NOT NULL
            GROUP BY max_minimise_count
            ORDER BY count DESC, max_minimise_count
            LIMIT 8
            """
        )
        qmin_minimize_one_lab = self._fetchall(
            """
            SELECT minimize_one_lab AS value, COUNT(*)::INTEGER AS count
            FROM qmin_resolver
            WHERE minimize_one_lab IS NOT NULL
            GROUP BY minimize_one_lab
            ORDER BY count DESC, minimize_one_lab
            LIMIT 8
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

    @cached(ttl=120)
    def get_global_protocol_summary(self) -> dict:
        total_row = self._fetchone("SELECT COUNT(DISTINCT resolver_id)::INTEGER AS resolver_count FROM resolver") or {}
        resolver_count = total_row.get("resolver_count", 0) or 0
        protocol_rows = self._fetchall(
            """
            SELECT protocol, COUNT(DISTINCT resolver_id)::INTEGER AS count
            FROM resolver_service
            WHERE protocol IS NOT NULL AND TRIM(protocol) <> ''
            GROUP BY protocol
            ORDER BY count DESC, protocol
            """
        )
        port_rows = self._fetchall(
            """
            SELECT port, COUNT(DISTINCT resolver_id)::INTEGER AS count
            FROM resolver_service
            WHERE port IS NOT NULL
            GROUP BY port
            ORDER BY count DESC, port
            """
        )
        service_rows = self._fetchall(
            """
            SELECT protocol, port, COUNT(DISTINCT resolver_id)::INTEGER AS count
            FROM resolver_service
            WHERE protocol IS NOT NULL AND TRIM(protocol) <> '' AND port IS NOT NULL
            GROUP BY protocol, port
            ORDER BY count DESC, protocol, port
            """
        )
        return {
            "resolver_count": resolver_count,
            "protocols": [
                {"protocol": row["protocol"], "count": row["count"], "percent": self._pc(row["count"], resolver_count)}
                for row in protocol_rows
            ],
            "ports": [
                {"port": row["port"], "count": row["count"], "percent": self._pc(row["count"], resolver_count)}
                for row in port_rows
            ],
            "services": [
                {
                    "protocol": row["protocol"],
                    "port": row["port"],
                    "count": row["count"],
                    "percent": self._pc(row["count"], resolver_count),
                }
                for row in service_rows
            ],
        }

    @cached(ttl=120)
    def get_global_spoofing_environment_summary(self) -> dict:
        total_row = self._fetchone("SELECT COUNT(*)::INTEGER AS resolver_count FROM resolver") or {}
        row = self._fetchone(
            """
            SELECT
                (
                    SELECT COUNT(*)::INTEGER
                    FROM resolver r
                    WHERE EXISTS (
                        SELECT 1
                        FROM spoofing s
                        WHERE r.ip <<= s.prefix
                          AND LOWER(COALESCE(s.routedspoof, '')) = 'received'
                    )
                ) AS resolver_spoofing_allow_count,
                (
                    SELECT COUNT(*)::INTEGER
                    FROM resolver r
                    WHERE EXISTS (
                        SELECT 1
                        FROM spoofing s
                        WHERE r.ip <<= s.prefix
                          AND LOWER(COALESCE(s.routedspoof, '')) = 'blocked'
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
                          AND LOWER(COALESCE(s.routedspoof, '')) = 'received'
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
                          AND LOWER(COALESCE(s.routedspoof, '')) = 'received'
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
            target_forwarder AS (
                SELECT forwarder_id
                FROM forwarder
                WHERE ip = %s::inet
            ),
            relaying_forwarders AS (
                SELECT DISTINCT fru.forwarder_id
                FROM forwarder_resolver_upstream fru
                JOIN target_resolver tr ON tr.resolver_id = fru.upstream_resolver_id
                UNION
                SELECT DISTINCT ffu.forwarder_id
                FROM forwarder_forwarder_upstream ffu
                JOIN target_forwarder tf ON tf.forwarder_id = ffu.upstream_forwarder_id
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
                    )
                )::INTEGER AS forwarder_tcp_count,
                COUNT(DISTINCT rf.forwarder_id) FILTER (
                    WHERE EXISTS (
                        SELECT 1
                        FROM forwarder_protocol fp
                        WHERE fp.forwarder_id = rf.forwarder_id
                          AND LOWER(fp.protocol) = 'udp'
                    )
                )::INTEGER AS forwarder_udp_count,
                COUNT(DISTINCT rf.forwarder_id) FILTER (
                    WHERE EXISTS (
                        SELECT 1
                        FROM forwarder_protocol fp
                        WHERE fp.forwarder_id = rf.forwarder_id
                          AND LOWER(fp.protocol) = 'tcp'
                    )
                    AND EXISTS (
                        SELECT 1
                        FROM forwarder_protocol fp
                        WHERE fp.forwarder_id = rf.forwarder_id
                          AND LOWER(fp.protocol) = 'udp'
                    )
                )::INTEGER AS forwarder_tcp_udp_count
            FROM relaying_forwarders rf
            LEFT JOIN forwarder_asn fa ON fa.forwarder_id = rf.forwarder_id
            LEFT JOIN forwarder_location fl ON fl.forwarder_id = rf.forwarder_id
            """,
            [normalized, normalized],
        ) or {}
        countries = self._fetchall(
            """
            WITH target_resolver AS (
                SELECT resolver_id
                FROM resolver
                WHERE ip = %s::inet
            ),
            target_forwarder AS (
                SELECT forwarder_id
                FROM forwarder
                WHERE ip = %s::inet
            ),
            relaying_forwarders AS (
                SELECT DISTINCT fru.forwarder_id
                FROM forwarder_resolver_upstream fru
                JOIN target_resolver tr ON tr.resolver_id = fru.upstream_resolver_id
                UNION
                SELECT DISTINCT ffu.forwarder_id
                FROM forwarder_forwarder_upstream ffu
                JOIN target_forwarder tf ON tf.forwarder_id = ffu.upstream_forwarder_id
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
            [normalized, normalized],
        )
        asns = self._fetchall(
            """
            WITH target_resolver AS (
                SELECT resolver_id
                FROM resolver
                WHERE ip = %s::inet
            ),
            target_forwarder AS (
                SELECT forwarder_id
                FROM forwarder
                WHERE ip = %s::inet
            ),
            relaying_forwarders AS (
                SELECT DISTINCT fru.forwarder_id
                FROM forwarder_resolver_upstream fru
                JOIN target_resolver tr ON tr.resolver_id = fru.upstream_resolver_id
                UNION
                SELECT DISTINCT ffu.forwarder_id
                FROM forwarder_forwarder_upstream ffu
                JOIN target_forwarder tf ON tf.forwarder_id = ffu.upstream_forwarder_id
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
            [normalized, normalized],
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
    def get_anycast_summary_by_ip(self, ip: str) -> dict:
        core = self.get_resolver_core(ip)
        anycast = self.get_resolver_anycast(ip)
        sites = self.get_resolver_anycast_sites(ip)
        qmin = self.get_resolver_qmin(ip)
        spoofing = self.get_resolver_spoofing(ip)
        forwarders = self.get_forwarder_relay_summary_by_ip(ip)
        resolver = core.get("resolver") or {}
        qmin_value = qmin.get("qmin")
        alternative_ips = self.get_resolver_alternative_ips(resolver.get("id"))
        sibling_ips = self.get_resolver_sibling_ips(resolver.get("id"), core["resolver_ip"])
        resolver_domains = self.get_resolver_domains(resolver.get("id"))
        resolver_services = self.get_resolver_services(resolver.get("id"))
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
            "resolver_is_public": resolver.get("is_public"),
            "resolver_supported_protocols": ",".join(resolver_services) if resolver_services else resolver.get("supported_protocols"),
            "resolver_services": resolver_services,
            "resolver_supports_tcp": "tcp" in tokens or "dotcp" in tokens,
            "resolver_supports_udp": "udp" in tokens or "doudp" in tokens,
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
