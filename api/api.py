import logging
from django.core.exceptions import ValidationError
from ninja import NinjaAPI, Query

from api.schemas import DNSResilienceResponse, ResolverAnycastSummaryResponse
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
    "/dns-resilience/country/{country}/qmin",
    summary="Get QMIN aggregate data for a country",
)
def get_country_qmin(request, country: str):
    logger.info("QMIN request for country: %s", country)
    return dns_resilience_service.get_country_qmin(country)


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
    "/dns-resilience/country/{country}/dnssec",
    summary="Get DNSSEC validation data for a country",
)
def get_country_dnssec(request, country: str):
    logger.info("DNSSEC request for country: %s", country)
    return dns_resilience_service.get_country_dnssec(country)


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


@api.get("/dns-resilience/global/anycast", summary="Get global resolver anycast summary")
def get_global_anycast(request):
    logger.info("Global anycast resolver summary request")
    return dns_resilience_service.get_global_anycast_summary()


@api.get("/dns-resilience/global/qmin", summary="Get global resolver QMIN summary")
def get_global_qmin(request):
    logger.info("Global QMIN resolver summary request")
    return dns_resilience_service.get_global_qmin_summary()


@api.get("/dns-resilience/global/protocols", summary="Get global resolver protocol summary")
def get_global_protocols(request):
    logger.info("Global resolver protocol summary request")
    return dns_resilience_service.get_global_protocol_summary()


@api.get("/dns-resilience/global/spoofing", summary="Get global resolver spoofing-environment summary")
def get_global_spoofing(request):
    logger.info("Global resolver spoofing summary request")
    return dns_resilience_service.get_global_spoofing_environment_summary()


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
