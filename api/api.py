import logging
from django.core.exceptions import ValidationError
from ninja import NinjaAPI, Query

from api.schemas import (
    DNSResilienceResponse,
    ResolverAnycastSummaryResponse,
    ResolverPrefixPage,
    SpoofingEntityPage,
)
from resilience.services import dns_resilience_service

logger = logging.getLogger("api")

api = NinjaAPI(
    title="DNS Resilience Observatory API",
    version="1.0.0",
    description="API for resilience assessment of DNS resolvers based on the backend dataset.",
    docs_url="/docs",
)


@api.exception_handler(ValidationError)
def validation_error_handler(request, exc):
    return api.create_response(
        request,
        {"error": "Validation Error", "detail": str(exc)},
        status=400,
    )


@api.get(
    "/dns-resilience/resolver/{resolver_ip}",
    response=DNSResilienceResponse,
    summary="Get base resolver data for a resolver IP",
)
def get_dns_resilience_by_resolver(request, resolver_ip: str, limit: int = Query(100, ge=1, le=1000)):
    logger.info("DNS resilience request for resolver IP: %s", resolver_ip)
    resolvers = dns_resilience_service.get_resolvers_by_ip(resolver_ip, limit=limit)
    return DNSResilienceResponse(
        target=resolver_ip,
        target_type="resolver",
        total=len(resolvers),
        resolvers=resolvers,
    )


@api.get(
    "/dns-resilience/resolver/{resolver_ip}/qmin",
    summary="Get QMIN data for a resolver IP",
)
def get_resolver_qmin(request, resolver_ip: str):
    logger.info("QMIN request for resolver IP: %s", resolver_ip)
    return dns_resilience_service.get_resolver_qmin(resolver_ip)


@api.get(
    "/dns-resilience/resolver/{resolver_ip}/anycast",
    summary="Check anycast prefix coverage for a resolver IP",
)
def get_resolver_anycast(request, resolver_ip: str):
    logger.info("Anycast request for resolver IP: %s", resolver_ip)
    return dns_resilience_service.get_resolver_anycast(resolver_ip)


@api.get(
    "/dns-resilience/resolver/{resolver_ip}/anycast/sites",
    summary="Get anycast backend sites for a resolver IP",
)
def get_resolver_anycast_sites(request, resolver_ip: str):
    logger.info("Anycast sites request for resolver IP: %s", resolver_ip)
    return dns_resilience_service.get_resolver_anycast_sites(resolver_ip)


@api.get(
    "/dns-resilience/resolver/{resolver_ip}/spoofing",
    summary="Get spoofing prefix data for a resolver IP",
)
def get_resolver_spoofing(request, resolver_ip: str):
    logger.info("Spoofing request for resolver IP: %s", resolver_ip)
    return dns_resilience_service.get_resolver_spoofing(resolver_ip)


@api.get(
    "/dns-resilience/resolver/{resolver_ip}/manrs",
    summary="Get MANRS readiness inherited from a resolver IP's ASN",
)
def get_resolver_manrs(request, resolver_ip: str):
    logger.info("MANRS readiness request for resolver IP: %s", resolver_ip)
    return dns_resilience_service.get_resolver_manrs(resolver_ip)


@api.get(
    "/dns-resilience/resolver/{resolver_ip}/forwarders",
    summary="List forwarders that have a recursive DNS resolver configured as upstream",
)
def get_resolver_upstream_forwarders(
    request,
    resolver_ip: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=250),
):
    logger.info(
        "Upstream forwarder list request: resolver_ip=%s page=%s page_size=%s",
        resolver_ip,
        page,
        page_size,
    )
    return dns_resilience_service.get_upstream_forwarder_lists_by_ip(
        resolver_ip,
        page,
        page_size,
    )


@api.get(
    "/dns-resilience/compare/{entity_type}/{target}",
    summary="Get normalized comparison metrics for a country, ASN, or resolver IP",
)
def get_comparison_metrics(request, entity_type: str, target: str):
    logger.info("Comparison metric request: entity_type=%s target=%s", entity_type, target)
    return dns_resilience_service.get_comparison_metrics(entity_type, target)


@api.get(
    "/dns-resilience/prefix/{network_prefix}",
    response=DNSResilienceResponse,
    summary="Get DNS resilience data for a network prefix",
)
def get_dns_resilience_by_prefix(request, network_prefix: str, limit: int = Query(100, ge=1, le=1000)):
    logger.info("DNS resilience request for prefix: %s", network_prefix)
    normalized_prefix = dns_resilience_service.validate_network_prefix(network_prefix)
    resolvers = dns_resilience_service.get_resolvers_by_prefix(network_prefix, limit=limit)
    counts = dns_resilience_service.get_prefix_counts(network_prefix)
    return DNSResilienceResponse(
        target=normalized_prefix,
        target_type="prefix",
        total=len(resolvers),
        resolvers=resolvers,
        **counts,
    )


@api.get("/dns-resilience/prefix/{network_prefix}/qmin", summary="Get QMIN aggregate data for a prefix")
def get_prefix_qmin(request, network_prefix: str):
    return dns_resilience_service.get_prefix_qmin(network_prefix)


@api.get(
    "/dns-resilience/prefix/{network_prefix}/qmin/amplification-risk/prefixes",
    response=ResolverPrefixPage,
    summary="Get BGP prefixes for amplification-risk resolvers in a prefix",
)
def get_prefix_qmin_risk_prefixes(
    request, network_prefix: str, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)
):
    return dns_resilience_service.get_prefix_qmin_risk_prefixes(network_prefix, page, page_size)


@api.get(
    "/dns-resilience/ASN/{asn}",
    response=DNSResilienceResponse,
    summary="Get DNS resilience data for an ASN",
)
def get_dns_resilience_by_asn(request, asn: str, limit: int = Query(100, ge=1, le=1000)):
    logger.info("DNS resilience request for ASN: %s", asn)
    resolvers = dns_resilience_service.get_resolvers_by_asn(asn, limit=limit)
    counts = dns_resilience_service.get_asn_counts(asn)
    return DNSResilienceResponse(
        target=asn,
        target_type="asn",
        total=len(resolvers),
        resolvers=resolvers,
        **counts,
    )


@api.get(
    "/dns-resilience/ASN/{asn}/qmin",
    summary="Get QMIN aggregate data for an ASN",
)
def get_asn_qmin(request, asn: str):
    logger.info("QMIN request for ASN: %s", asn)
    return dns_resilience_service.get_asn_qmin(asn)


@api.get(
    "/dns-resilience/ASN/{asn}/qmin/amplification-risk/prefixes",
    response=ResolverPrefixPage,
    summary="Get BGP prefixes for amplification-risk resolvers in an ASN",
)
def get_asn_qmin_risk_prefixes(
    request, asn: str, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)
):
    return dns_resilience_service.get_asn_qmin_risk_prefixes(asn, page, page_size)


@api.get(
    "/dns-resilience/ASN/{asn}/prefixes",
    response=ResolverPrefixPage,
    summary="Get database BGP prefixes containing resolvers in an ASN",
)
def get_asn_prefixes(
    request, asn: str, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)
):
    return dns_resilience_service.get_asn_prefixes(asn, page, page_size)


@api.get(
    "/dns-resilience/ASN/{asn}/anycast",
    summary="Get anycast prefix coverage for an ASN",
)
def get_asn_anycast(request, asn: str):
    logger.info("Anycast request for ASN: %s", asn)
    return dns_resilience_service.get_asn_anycast(asn)


@api.get(
    "/dns-resilience/ASN/{asn}/anycast/sites",
    summary="Get anycast backend sites for an ASN",
)
def get_asn_anycast_sites(request, asn: str):
    logger.info("Anycast sites request for ASN: %s", asn)
    return dns_resilience_service.get_asn_anycast_sites(asn)


@api.get(
    "/dns-resilience/ASN/{asn}/spoofing",
    summary="Get spoofing aggregate data for an ASN",
)
def get_asn_spoofing(request, asn: str):
    logger.info("Spoofing request for ASN: %s", asn)
    return dns_resilience_service.get_asn_spoofing(asn)


@api.get(
    "/dns-resilience/ASN/{asn}/manrs",
    summary="Get MANRS readiness for an ASN",
)
def get_asn_manrs(request, asn: str):
    logger.info("MANRS readiness request for ASN: %s", asn)
    return dns_resilience_service.get_asn_manrs(asn)


@api.get(
    "/dns-resilience/ASN/{asn}/spoofing/resolver-prefixes",
    response=ResolverPrefixPage,
    summary="Get resolver BGP prefixes for an ASN allowing spoofing",
)
def get_asn_spoofing_prefixes(
    request, asn: str, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)
):
    return dns_resilience_service.get_asn_spoofing_prefixes(asn, page, page_size)


@api.get(
    "/dns-resilience/country/{country}",
    response=DNSResilienceResponse,
    summary="Get DNS resilience data for a country",
)
def get_dns_resilience_by_country(request, country: str, limit: int = Query(100, ge=1, le=1000)):
    logger.info("DNS resilience request for country: %s", country)
    resolvers = dns_resilience_service.get_resolvers_by_country(country, limit=limit)
    counts = dns_resilience_service.get_country_counts(country)
    return DNSResilienceResponse(
        target=country,
        target_type="country",
        total=len(resolvers),
        resolvers=resolvers,
        **counts,
    )


@api.get(
    "/dns-resilience/scope/{scope}",
    response=DNSResilienceResponse,
    summary="Find open or closed recursive DNS resolvers",
)
def get_dns_resilience_by_scope(request, scope: str, limit: int = Query(100, ge=1, le=1000)):
    logger.info("DNS resilience request for resolver scope: %s", scope)
    normalized, resolvers = dns_resilience_service.get_resolvers_by_scope(scope, limit=limit)
    return DNSResilienceResponse(
        target=f"resolver:{normalized}",
        target_type="scope",
        total=len(resolvers),
        resolvers=resolvers,
    )


@api.get(
    "/dns-resilience/organization",
    response=DNSResilienceResponse,
    summary="Find recursive DNS resolvers by organization name",
)
def get_dns_resilience_by_organization(
    request,
    organization: str = Query(...),
    limit: int = Query(100, ge=1, le=1000),
):
    logger.info("DNS resilience request for organization: %s", organization)
    normalized, resolvers = dns_resilience_service.get_resolvers_by_organization(
        organization,
        limit=limit,
    )
    return DNSResilienceResponse(
        target=normalized,
        target_type="organization",
        total=len(resolvers),
        resolvers=resolvers,
    )


@api.get("/dns-resilience/domain/{domain}/summary", response=dict, summary="Get aggregated resolver data for a domain")
def get_dns_resilience_domain_summary(request, domain: str):
    normalized_domain = dns_resilience_service.validate_domain(domain)
    resolvers = dns_resilience_service.get_resolvers_by_domain(normalized_domain, limit=1000)
    details = [dns_resilience_service.get_anycast_summary_by_ip(row["ip"]) for row in resolvers]
    ips = [row["ip"] for row in resolvers]
    services = sorted({service for row in resolvers for service in (row.get("supported_protocols") or "").split(",") if service})
    public_count = sum(1 for row in resolvers if row.get("is_public"))
    countries = {row["country"] for row in resolvers if row.get("country")}
    asns = {row["asn"] for row in resolvers if row.get("asn") is not None}
    prefixes = {row["bgp_prefix"] for row in resolvers if row.get("bgp_prefix")}
    organizations = {row["org"] for row in resolvers if row.get("org")}
    anycast_countries = {entry["country"] for detail in details for entry in detail.get("anycast_countries", [])}
    qmin_measured = sum(1 for detail in details if detail.get("resolver_qmin") is not None)
    dnssec_values = {detail.get("resolver_dnssec_validates") for detail in details if detail.get("resolver_dnssec_validates") is not None}
    dohpaths = sorted({path for row in resolvers if (path := dns_resilience_service.get_resolver_dohpath(row.get("id")))})
    return {
        "is_domain_summary": True, "resolver_ip": normalized_domain, "resolver_found": bool(resolvers),
        "resolver_asn": len(asns), "resolver_prefix": len(prefixes), "resolver_country": len(countries), "resolver_city": None,
        "resolver_org": len(organizations), "resolver_domain": normalized_domain, "resolver_domains": [normalized_domain], "resolver_dohpath": dohpaths[0] if dohpaths else None,
        "resolver_qmin": f"Measured {qmin_measured}/{len(resolvers)}" if qmin_measured else None,
        "resolver_qmin_max_minimise_count": None, "resolver_qmin_minimize_one_lab": None,
        "resolver_dnssec_validates": next(iter(dnssec_values)) if len(dnssec_values) == 1 else None,
        "resolver_is_public": public_count > 0, "resolver_services": services, "resolver_supported_protocols": ",".join(services),
        "resolver_supports_tcp": any(detail.get("resolver_supports_tcp") for detail in details), "resolver_supports_udp": any(detail.get("resolver_supports_udp") for detail in details),
        "resolver_supports_ipv4": any(":" not in ip for ip in ips), "resolver_supports_ipv6": any(":" in ip for ip in ips),
        "alternative_resolver_ips": ips, "sibling_resolver_ips": [],
        "spoofing_prefix_count": sum(detail.get("spoofing_prefix_count", 0) for detail in details), "spoofing_allow_count": sum(detail.get("spoofing_allow_count", 0) for detail in details),
        "spoofing_received_count": sum(detail.get("spoofing_received_count", 0) for detail in details), "spoofing_blocked_count": sum(detail.get("spoofing_blocked_count", 0) for detail in details), "spoofing_unknown_count": sum(detail.get("spoofing_unknown_count", 0) for detail in details),
        "spoofing_allow_pc": 0, "spoofing_last_update_ts": None, "spoofing_allow_prefixes": [],
        "anycast_found": any(detail.get("anycast_found") for detail in details), "anycast_site_count": sum(detail.get("anycast_site_count", 0) for detail in details),
        "anycast_country_count": len(anycast_countries), "anycast_asn_count": sum(detail.get("anycast_asn_count", 0) for detail in details), "anycast_countries": [],
        "last_observation_ts": max((row.get("last_observation_ts") for row in resolvers if row.get("last_observation_ts")), default=None),
        "forwarder_asn_count": 0, "forwarder_country_count": 0, "forwarder_entry_count": 0, "forwarder_tcp_count": 0, "forwarder_udp_count": 0, "forwarder_tcp_udp_count": 0,
        "forwarder_countries": [], "forwarder_asns": [], "domain_public_count": public_count, "domain_resolver_count": len(resolvers),
        "domain_is_dual_stack": any(":" not in ip for ip in ips) and any(":" in ip for ip in ips),
    }

@api.get(
    "/dns-resilience/domain/{domain}",
    response=DNSResilienceResponse,
    summary="Get DNS resilience data for a resolver domain",
)
def get_dns_resilience_by_domain(request, domain: str, limit: int = Query(100, ge=1, le=1000)):
    logger.info("DNS resilience request for domain: %s", domain)
    normalized_domain = dns_resilience_service.validate_domain(domain)
    resolvers = dns_resilience_service.get_resolvers_by_domain(domain, limit=limit)
    return DNSResilienceResponse(
        target=normalized_domain,
        target_type="domain",
        total=len(resolvers),
        resolvers=resolvers,
    )


@api.get(
    "/dns-resilience/protocol/{service}",
    response=DNSResilienceResponse,
    summary="Get DNS resilience data for a resolver protocol or protocol:port service",
)
def get_dns_resilience_by_protocol(request, service: str, limit: int = Query(100, ge=1, le=1000)):
    logger.info("DNS resilience request for resolver service: %s", service)
    normalized_service, resolvers = dns_resilience_service.get_resolvers_by_service(service, limit=limit)
    return DNSResilienceResponse(
        target=normalized_service,
        target_type="protocol",
        total=len(resolvers),
        resolvers=resolvers,
    )


@api.get(
    "/dns-resilience/port/{port}",
    response=DNSResilienceResponse,
    summary="Get DNS resilience data for recursive DNS resolvers using a port",
)
def get_dns_resilience_by_port(request, port: int, limit: int = Query(100, ge=1, le=1000)):
    logger.info("DNS resilience request for resolver port: %s", port)
    normalized_port, resolvers = dns_resilience_service.get_resolvers_by_port(port, limit=limit)
    return DNSResilienceResponse(
        target=f"port:{normalized_port}",
        target_type="port",
        total=len(resolvers),
        resolvers=resolvers,
    )


@api.get(
    "/dns-resilience/country/{country}/qmin",
    summary="Get QMIN aggregate data for a country",
)
def get_country_qmin(request, country: str):
    logger.info("QMIN request for country: %s", country)
    return dns_resilience_service.get_country_qmin(country)


@api.get(
    "/dns-resilience/country/{country}/qmin/amplification-risk/prefixes",
    response=ResolverPrefixPage,
    summary="Get BGP prefixes for amplification-risk resolvers in a country",
)
def get_country_qmin_risk_prefixes(
    request, country: str, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)
):
    return dns_resilience_service.get_country_qmin_risk_prefixes(country, page, page_size)


@api.get(
    "/dns-resilience/country/{country}/prefixes",
    response=ResolverPrefixPage,
    summary="Get database BGP prefixes containing resolvers in a country",
)
def get_country_prefixes(
    request, country: str, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)
):
    return dns_resilience_service.get_country_prefixes(country, page, page_size)


@api.get(
    "/dns-resilience/country/{country}/anycast",
    summary="Get anycast prefix coverage for a country",
)
def get_country_anycast(request, country: str):
    logger.info("Anycast request for country: %s", country)
    return dns_resilience_service.get_country_anycast(country)


@api.get(
    "/dns-resilience/country/{country}/anycast/sites",
    summary="Get anycast backend sites for a country",
)
def get_country_anycast_sites(request, country: str):
    logger.info("Anycast sites request for country: %s", country)
    return dns_resilience_service.get_country_anycast_sites(country)


@api.get(
    "/dns-resilience/country/{country}/spoofing",
    summary="Get spoofing aggregate data for a country",
)
def get_country_spoofing(request, country: str):
    logger.info("Spoofing request for country: %s", country)
    return dns_resilience_service.get_country_spoofing(country)


@api.get(
    "/dns-resilience/country/{country}/manrs",
    summary="Get MANRS readiness for a country",
)
def get_country_manrs(request, country: str):
    logger.info("MANRS readiness request for country: %s", country)
    return dns_resilience_service.get_country_manrs(country)


@api.get(
    "/dns-resilience/country/{country}/spoofing/resolver-prefixes",
    response=ResolverPrefixPage,
    summary="Get resolver BGP prefixes for spoofing environments in a country",
)
def get_country_spoofing_prefixes(
    request, country: str, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)
):
    return dns_resilience_service.get_country_spoofing_prefixes(country, page, page_size)


@api.get(
    "/dns-resilience/country/{country}/dnssec",
    summary="Get DNSSEC validation data for a country",
)
def get_country_dnssec(request, country: str):
    logger.info("DNSSEC request for country: %s", country)
    return dns_resilience_service.get_country_dnssec(country)


@api.get(
    "/dns-resilience/country/{country}/resolver-usage-apnic",
    summary="Get APNIC recursive DNS resolver usage for a country",
)
def get_country_resolver_usage_apnic(request, country: str):
    logger.info("APNIC resolver usage request for country: %s", country)
    return dns_resilience_service.get_resolver_usage_apnic(country)


@api.get(
    "/dns-resilience/country/{country}/forwarder-resolver-usage",
    summary="Get forwarder-centric upstream recursive DNS resolver usage for a country",
)
def get_country_forwarder_resolver_usage(request, country: str):
    logger.info("Country forwarder-centric resolver usage request for country: %s", country)
    return dns_resilience_service.get_country_forwarder_resolver_usage(country)


@api.get("/dns-resilience/global/ipv4", summary="Get global IPv4 resolver summary")
def get_global_ipv4(request):
    logger.info("Global IPv4 resolver summary request")
    return dns_resilience_service.get_global_ip_version_summary(4)


@api.get("/dns-resilience/global/ipv6", summary="Get global IPv6 resolver summary")
def get_global_ipv6(request):
    logger.info("Global IPv6 resolver summary request")
    return dns_resilience_service.get_global_ip_version_summary(6)


@api.get("/dns-resilience/global/dual-stack", summary="Get global dual-stack resolver summary")
def get_global_dual_stack(request):
    logger.info("Global dual-stack resolver summary request")
    return dns_resilience_service.get_global_dual_stack_summary()


@api.get("/dns-resilience/global/scope", summary="Get global observatory scope summary")
def get_global_scope(request):
    logger.info("Global observatory scope summary request")
    return dns_resilience_service.get_global_scope_summary()


@api.get(
    "/dns-resilience/global/resolver-usage-apnic",
    summary="Get APNIC world recursive DNS resolver usage",
)
def get_global_resolver_usage_apnic(request):
    logger.info("APNIC world resolver usage request")
    return dns_resilience_service.get_resolver_usage_apnic("XA")


@api.get(
    "/dns-resilience/global/forwarder-resolver-usage",
    summary="Get forwarder-centric upstream recursive DNS resolver usage",
)
def get_global_forwarder_resolver_usage(request):
    logger.info("Global forwarder-centric resolver usage request")
    return dns_resilience_service.get_global_forwarder_resolver_usage()


@api.get(
    "/dns-resilience/global/data-sources",
    summary="Get public data-source links, GitHub repositories, and resolver source distribution",
)
def get_global_data_sources(request):
    logger.info("Global resolver data-source summary request")
    return dns_resilience_service.get_global_data_source_summary()


@api.get(
    "/dns-resilience/global/practice-summary",
    summary="Get measurable-practice percentages for open and closed recursive DNS resolvers",
)
def get_global_resolver_practice_summary(request, ip_version: str = "all"):
    logger.info("Global open and closed resolver practice summary request: ip_version=%s", ip_version)
    return dns_resilience_service.get_global_resolver_practice_summary(ip_version)


@api.get(
    "/dns-resilience/global/practice-summary/{scope}/{metric}",
    summary="Get one measurable-practice value for open or closed recursive DNS resolvers",
)
def get_global_resolver_practice_metric(
    request, scope: str, metric: str, ip_version: str = "all"
):
    logger.info(
        "Global resolver practice metric request: scope=%s metric=%s ip_version=%s",
        scope,
        metric,
        ip_version,
    )
    return dns_resilience_service.get_global_resolver_practice_metric(scope, metric, ip_version)


@api.get(
    "/dns-resilience/global/practice-details/dnssec/{scope}",
    summary="Get DNSSEC validation detail for open resolvers, closed resolvers, or countries",
)
def get_global_dnssec_practice_detail(request, scope: str, ip_version: str = "all"):
    logger.info("Global DNSSEC practice detail request: scope=%s ip_version=%s", scope, ip_version)
    return dns_resilience_service.get_global_dnssec_practice_detail(scope, ip_version)


@api.get(
    "/dns-resilience/global/practice-details/qmin/{scope}",
    summary="Get QMIN implementation detail for open or closed recursive DNS resolvers",
)
def get_global_qmin_practice_detail(request, scope: str, ip_version: str = "all"):
    logger.info("Global QMIN practice detail request: scope=%s ip_version=%s", scope, ip_version)
    return dns_resilience_service.get_global_qmin_practice_detail(scope, ip_version)


@api.get(
    "/dns-resilience/global/practice-details/manrs/{entity_type}/{scope}",
    summary="Get average MANRS readiness for resolver-linked ASNs or countries",
)
def get_global_manrs_practice_detail(
    request, entity_type: str, scope: str, ip_version: str = "all"
):
    logger.info(
        "Global MANRS practice detail request: entity_type=%s scope=%s ip_version=%s",
        entity_type,
        scope,
        ip_version,
    )
    return dns_resilience_service.get_global_manrs_practice_detail(
        entity_type, scope, ip_version
    )


@api.get(
    "/dns-resilience/global/practice-details/bcp38/{scope}",
    summary="Get BCP38 evidence for open or closed recursive DNS resolvers",
)
def get_global_bcp38_practice_detail(request, scope: str, ip_version: str = "all"):
    logger.info("Global BCP38 practice detail request: scope=%s ip_version=%s", scope, ip_version)
    return dns_resilience_service.get_global_bcp38_practice_detail(scope, ip_version)


@api.get("/dns-resilience/global/anycast", summary="Get global resolver anycast summary")
def get_global_anycast(request, ip_version: str = "all"):
    logger.info("Global anycast resolver summary request: ip_version=%s", ip_version)
    return dns_resilience_service.get_global_anycast_summary(ip_version)


@api.get("/dns-resilience/global/qmin", summary="Get global resolver QMIN summary")
def get_global_qmin(request, ip_version: str = "all"):
    logger.info("Global QMIN resolver summary request: ip_version=%s", ip_version)
    return dns_resilience_service.get_global_qmin_summary(ip_version)


@api.get(
    "/dns-resilience/global/qmin/amplification-risk/prefixes",
    response=ResolverPrefixPage,
    summary="Get BGP prefixes for all amplification-risk resolvers",
)
def get_global_qmin_risk_prefixes(
    request, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)
):
    return dns_resilience_service.get_global_qmin_risk_prefixes(page, page_size)


@api.get(
    "/dns-resilience/qmin/{state}/prefixes",
    response=ResolverPrefixPage,
    summary="Get BGP prefixes for resolvers with QMIN enabled or disabled",
)
def get_qmin_state_prefixes(
    request, state: str, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)
):
    return dns_resilience_service.get_qmin_state_prefixes(state, page, page_size)


@api.get("/dns-resilience/global/protocols", summary="Get global resolver protocol summary")
def get_global_protocols(request, ip_version: str = "all"):
    logger.info("Global resolver protocol summary request: ip_version=%s", ip_version)
    return dns_resilience_service.get_global_protocol_summary(ip_version)


@api.get("/dns-resilience/global/spoofing", summary="Get global resolver spoofing-environment summary")
def get_global_spoofing(request):
    logger.info("Global resolver spoofing summary request")
    return dns_resilience_service.get_global_spoofing_environment_summary()


@api.get(
    "/dns-resilience/spoofing/countries",
    response=SpoofingEntityPage,
    summary="Get countries with resolvers in spoofing environments",
)
def get_spoofing_countries(
    request, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)
):
    return dns_resilience_service.get_spoofing_countries(page, page_size)


@api.get(
    "/dns-resilience/spoofing/ASNs",
    response=SpoofingEntityPage,
    summary="Get ASNs allowing spoofing that contain resolvers",
)
def get_spoofing_asns(
    request, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)
):
    return dns_resilience_service.get_spoofing_asns(page, page_size)


@api.get("/dns-resilience/global/countries", summary="Get global resolver country summary")
def get_global_countries(request):
    logger.info("Global resolver country summary request")
    return dns_resilience_service.get_global_country_summary()


@api.get("/dns-resilience/global/asns", summary="Get global resolver ASN summary")
def get_global_asns(request):
    logger.info("Global resolver ASN summary request")
    return dns_resilience_service.get_global_asn_summary()


@api.get("/dns-resilience/global/dnssec", summary="Get global DNSSEC country validation summary")
def get_global_dnssec(request):
    logger.info("Global DNSSEC country summary request")
    return dns_resilience_service.get_global_dnssec_summary()


@api.get(
    "/dns-resilience/resolver/{resolver_ip}/summary",
    response=ResolverAnycastSummaryResponse,
    summary="Get resolver anycast summary by IP",
)
def get_resolver_anycast_summary(request, resolver_ip: str):
    logger.info("Anycast summary request for resolver IP: %s", resolver_ip)
    summary = dns_resilience_service.get_anycast_summary_by_ip(resolver_ip)
    return ResolverAnycastSummaryResponse(**summary)
