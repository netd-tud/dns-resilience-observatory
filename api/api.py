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
