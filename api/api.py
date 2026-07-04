import logging
from django.core.exceptions import ValidationError
from ninja import NinjaAPI, Query

from api.schemas import DNSResilienceResponse, ResolverAnycastSummaryResponse, ResolverDashboardSummaryResponse
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
    "/dns-resilience/dashboard/summary",
    response=ResolverDashboardSummaryResponse,
    summary="Get DNS resilience dashboard summary",
)
def get_dashboard_summary(request):
    logger.info("DNS resilience dashboard summary request")
    summary = dns_resilience_service.get_dashboard_summary()
    return ResolverDashboardSummaryResponse(**summary)


@api.get(
    "/dns-resilience/resolver/{resolver_ip}/summary",
    response=ResolverAnycastSummaryResponse,
    summary="Get resolver anycast summary by IP",
)
def get_resolver_anycast_summary(request, resolver_ip: str):
    logger.info("Anycast summary request for resolver IP: %s", resolver_ip)
    summary = dns_resilience_service.get_anycast_summary_by_ip(resolver_ip)
    return ResolverAnycastSummaryResponse(**summary)
