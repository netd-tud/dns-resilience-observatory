from datetime import datetime
from typing import List, Optional
from ninja import Schema
from pydantic import Field


class ResolverRecord(Schema):
    id: int = Field(..., description="Resolver primary key")
    ip: Optional[str] = Field(None, description="Resolver IP address")
    asn: Optional[int] = Field(None, description="Autonomous System Number")
    bgp_prefix: Optional[str] = Field(None, description="BGP prefix")
    org: Optional[str] = Field(None, description="Organization name")
    org_short: Optional[str] = Field(None, description="Organization short name")
    country: Optional[str] = Field(None, description="Country code")
    is_public: Optional[bool] = Field(None, description="Public resolver flag")
    last_observation_ts: Optional[datetime] = Field(None, description="Last observation timestamp")
    source: Optional[str] = Field(None, description="Source tag")


class DNSResilienceResponse(Schema):
    target: str = Field(..., description="The queried target")
    target_type: str = Field(..., description="Type of target (resolver, prefix, asn, country)")
    total: int = Field(..., description="Total number of resolvers found")
    resolvers: List[ResolverRecord] = Field(default_factory=list)
    public_resolver_count: Optional[int] = Field(None, description="Public resolvers in country")
    closed_resolver_count: Optional[int] = Field(None, description="Closed resolvers in country")
    forwarder_count: Optional[int] = Field(None, description="Forwarders in country")
    country_resolver_count: Optional[int] = Field(None, description="All resolvers in country")
    anycast_resolver_count: Optional[int] = Field(None, description="Resolvers in country covered by anycast prefixes")
    dnssec_validating_pc: Optional[float] = Field(None, description="Country DNSSEC validating percentage")
    dnssec_partial_validating_pc: Optional[float] = Field(None, description="Country DNSSEC partial validating percentage")


class AnycastCountrySummary(Schema):
    country: str = Field(..., description="Country code")
    site_count: int = Field(..., description="Unique anycast site count for the country")
    latitude: Optional[float] = Field(None, description="Average latitude for anycast sites")
    longitude: Optional[float] = Field(None, description="Average longitude for anycast sites")


class ForwarderCountrySummary(Schema):
    country: str = Field(..., description="Country code")
    count: int = Field(..., description="Forwarder count for the country")


class ResolverCountryDashboard(Schema):
    country: str = Field(..., description="Country code")
    count: int = Field(..., description="Resolver count")
    public_count: int = Field(..., description="Public resolver count")
    closed_count: int = Field(..., description="Closed resolver count")
    latitude: Optional[float] = Field(None, description="Country latitude")
    longitude: Optional[float] = Field(None, description="Country longitude")


class ResolverDashboardSummaryResponse(Schema):
    resolver_count: int = Field(..., description="Total resolver count")
    resolver_ipv4_count: int = Field(..., description="IPv4 resolver count")
    resolver_ipv6_count: int = Field(..., description="IPv6 resolver count")
    resolver_public_count: int = Field(..., description="Public resolver count")
    resolver_closed_count: int = Field(..., description="Closed resolver count")
    resolver_public_pc: float = Field(..., description="Public resolver percentage")
    resolver_closed_pc: float = Field(..., description="Closed resolver percentage")
    resolver_anycast_count: int = Field(..., description="Resolvers covered by anycast prefixes")
    resolver_tcp_count: int = Field(..., description="Resolvers supporting TCP")
    resolver_udp_count: int = Field(..., description="Resolvers supporting UDP")
    resolver_tcp_udp_count: int = Field(..., description="Resolvers supporting both TCP and UDP")
    resolver_countries: List[ResolverCountryDashboard] = Field(default_factory=list)
    forwarder_count: int = Field(..., description="Total forwarder count")
    forwarder_public_count: int = Field(..., description="Public forwarder count")
    forwarder_non_public_count: int = Field(..., description="Non-public forwarder count")
    forwarder_public_pc: float = Field(..., description="Public forwarder percentage")
    forwarder_tcp_count: int = Field(..., description="Forwarders supporting TCP")
    forwarder_udp_count: int = Field(..., description="Forwarders supporting UDP")
    forwarder_tcp_udp_count: int = Field(..., description="Forwarders supporting both TCP and UDP")
    dnssec_country_count: int = Field(..., description="Countries with DNSSEC measurements")
    dnssec_validating_avg: float = Field(..., description="Average country DNSSEC validating percentage")
    dnssec_partial_validating_avg: float = Field(..., description="Average country partial validating percentage")
    last_observation_ts: Optional[datetime] = Field(None, description="Latest dashboard observation timestamp")


class ResolverAnycastSummaryResponse(Schema):
    resolver_ip: str = Field(..., description="Resolver IP address")
    resolver_found: bool = Field(..., description="True if resolver IP exists in resolver table")
    resolver_is_public: Optional[bool] = Field(None, description="Public resolver flag")
    resolver_supported_protocols: Optional[str] = Field(None, description="Supported protocols for the resolver")
    resolver_supports_tcp: bool = Field(..., description="Resolver supports TCP")
    resolver_supports_udp: bool = Field(..., description="Resolver supports UDP")
    anycast_found: bool = Field(..., description="True if anycast entries exist for resolver ID")
    anycast_site_count: int = Field(..., description="Unique anycast site count")
    anycast_country_count: int = Field(..., description="Unique countries with anycast presence")
    anycast_asn_count: int = Field(..., description="Unique ASNs with anycast presence")
    anycast_countries: List[AnycastCountrySummary] = Field(default_factory=list)
    last_observation_ts: Optional[datetime] = Field(None, description="Last observation timestamp")
    forwarder_asn_count: int = Field(..., description="Unique ASNs for matching forwarders")
    forwarder_country_count: int = Field(..., description="Unique countries for matching forwarders")
    forwarder_entry_count: int = Field(..., description="Total forwarder entries for resolver")
    forwarder_tcp_count: int = Field(..., description="Forwarders supporting TCP")
    forwarder_udp_count: int = Field(..., description="Forwarders supporting UDP")
    forwarder_tcp_udp_count: int = Field(..., description="Forwarders supporting both TCP and UDP")
    forwarder_countries: List[ForwarderCountrySummary] = Field(default_factory=list)


class ErrorResponse(Schema):
    error: str = Field(..., description="Error message")
    detail: Optional[str] = Field(None, description="Detailed error information")
