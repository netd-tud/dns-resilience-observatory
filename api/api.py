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
    summary="Get DNS resilience data for a resolver IP",
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
