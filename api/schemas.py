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
    recursive_forwarder_count: Optional[int] = Field(None, description="Recursive forwarders")
    transparent_forwarder_count: Optional[int] = Field(None, description="Transparent forwarders")
    country_resolver_count: Optional[int] = Field(None, description="All resolvers in country")
    anycast_resolver_count: Optional[int] = Field(None, description="Resolvers in country covered by anycast prefixes")
    anycast_resolver_pc: Optional[float] = Field(None, description="Share of resolvers covered by anycast prefixes")
    qmin_yes_count: Optional[int] = Field(None, description="Resolvers with QMIN enabled")
    qmin_no_count: Optional[int] = Field(None, description="Resolvers without QMIN")
    qmin_unstable_count: Optional[int] = Field(None, description="Resolvers with unstable QMIN result")
    qmin_measured_count: Optional[int] = Field(None, description="Resolvers with QMIN measurement")
    qmin_yes_pc: Optional[float] = Field(None, description="Share of measured resolvers with QMIN enabled")
    qmin_no_pc: Optional[float] = Field(None, description="Share of measured resolvers without QMIN")
    anycast_prefix_count: Optional[int] = Field(None, description="Anycast prefixes for the target")
    anycast_country_instance_count: Optional[int] = Field(None, description="Anycast country backend instance count")
    anycast_asn_instance_count: Optional[int] = Field(None, description="Anycast ASN backend instance count")
    spoofing_prefix_count: Optional[int] = Field(None, description="Spoofing prefixes for the target")
    spoofing_allow_count: Optional[int] = Field(None, description="Spoofing prefixes that allow spoofing")
    spoofing_blocked_count: Optional[int] = Field(None, description="Spoofing prefixes that block spoofing")
    spoofing_unknown_count: Optional[int] = Field(None, description="Spoofing prefixes with unknown status")
    spoofing_allow_pc: Optional[float] = Field(None, description="Share of spoofing prefixes allowing spoofing")
    spoofing_last_update_ts: Optional[datetime] = Field(None, description="Latest spoofing observation timestamp")
    dnssec_validating_pc: Optional[float] = Field(None, description="Country DNSSEC validating percentage")
    dnssec_partial_validating_pc: Optional[float] = Field(None, description="Country DNSSEC partial validating percentage")
    dnssec_last_update_ts: Optional[datetime] = Field(None, description="Latest country DNSSEC observation timestamp")


class AnycastCountrySummary(Schema):
    country: str = Field(..., description="Country code")
    site_count: int = Field(..., description="Unique anycast site count for the country")
    latitude: Optional[float] = Field(None, description="Average latitude for anycast sites")
    longitude: Optional[float] = Field(None, description="Average longitude for anycast sites")


class ForwarderCountrySummary(Schema):
    country: str = Field(..., description="Country code")
    count: int = Field(..., description="Forwarder count for the country")


class ForwarderAsnSummary(Schema):
    asn: int = Field(..., description="Forwarder ASN")
    count: int = Field(..., description="Forwarder count for the ASN")


class SpoofingPrefixSummary(Schema):
    prefix: str = Field(..., description="Spoofing measurement prefix")
    privatespoof: Optional[str] = Field(None, description="Private spoofing result")
    routedspoof: Optional[str] = Field(None, description="Routed spoofing result")


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
    resolver_asn: Optional[int] = Field(None, description="Resolver ASN")
    resolver_prefix: Optional[str] = Field(None, description="Resolver BGP prefix")
    resolver_country: Optional[str] = Field(None, description="Resolver country")
    resolver_city: Optional[str] = Field(None, description="Resolver city")
    resolver_org: Optional[str] = Field(None, description="Resolver organization")
    resolver_domain: Optional[str] = Field(None, description="Resolver domain")
    resolver_qmin: Optional[str] = Field(None, description="Resolver QMIN state")
    resolver_is_public: Optional[bool] = Field(None, description="Public resolver flag")
    resolver_supported_protocols: Optional[str] = Field(None, description="Supported protocols for the resolver")
    resolver_supports_tcp: bool = Field(..., description="Resolver supports TCP")
    resolver_supports_udp: bool = Field(..., description="Resolver supports UDP")
    resolver_supports_ipv4: bool = Field(..., description="Resolver has an IPv4 address")
    resolver_supports_ipv6: bool = Field(..., description="Resolver has an IPv6 address")
    alternative_resolver_ips: List[str] = Field(default_factory=list)
    spoofing_prefix_count: int = Field(..., description="Spoofing prefixes containing the resolver IP")
    spoofing_allow_count: int = Field(..., description="Containing spoofing prefixes that allow spoofing")
    spoofing_blocked_count: int = Field(..., description="Containing spoofing prefixes that block spoofing")
    spoofing_unknown_count: int = Field(..., description="Containing spoofing prefixes with unknown status")
    spoofing_allow_pc: float = Field(..., description="Share of containing spoofing prefixes allowing spoofing")
    spoofing_last_update_ts: Optional[datetime] = Field(None, description="Latest spoofing observation timestamp")
    spoofing_allow_prefixes: List[SpoofingPrefixSummary] = Field(default_factory=list)
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
    forwarder_asns: List[ForwarderAsnSummary] = Field(default_factory=list)


class ErrorResponse(Schema):
    error: str = Field(..., description="Error message")
    detail: Optional[str] = Field(None, description="Detailed error information")
