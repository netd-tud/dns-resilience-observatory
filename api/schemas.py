from datetime import datetime
from typing import List, Optional
from ninja import Schema
from pydantic import Field


class ResolverRecord(Schema):
    id: int = Field(..., description="Resolver primary key")
    ipv4: Optional[str] = Field(None, description="IPv4 address")
    ipv6: Optional[str] = Field(None, description="IPv6 address")
    asn: Optional[int] = Field(None, description="Autonomous System Number")
    bgp_prefix: Optional[str] = Field(None, description="BGP prefix")
    org: Optional[str] = Field(None, description="Organization name")
    org_short: Optional[str] = Field(None, description="Organization short name")
    country: Optional[str] = Field(None, description="Country code")
    city: Optional[str] = Field(None, description="City")
    latitude: Optional[float] = Field(None, description="Latitude")
    longitude: Optional[float] = Field(None, description="Longitude")
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


class AnycastCountrySummary(Schema):
    country: str = Field(..., description="Country code")
    site_count: int = Field(..., description="Unique anycast site count for the country")
    latitude: Optional[float] = Field(None, description="Average latitude for anycast sites")
    longitude: Optional[float] = Field(None, description="Average longitude for anycast sites")


class ForwarderCountrySummary(Schema):
    country: str = Field(..., description="Country code")
    count: int = Field(..., description="Forwarder count for the country")


class ResolverAnycastSummaryResponse(Schema):
    resolver_ip: str = Field(..., description="Resolver IP address")
    resolver_found: bool = Field(..., description="True if resolver IP exists in resolver table")
    resolver_is_public: Optional[bool] = Field(None, description="Public resolver flag")
    anycast_found: bool = Field(..., description="True if anycast entries exist for resolver ID")
    anycast_site_count: int = Field(..., description="Unique anycast site count")
    anycast_country_count: int = Field(..., description="Unique countries with anycast presence")
    anycast_asn_count: int = Field(..., description="Unique ASNs with anycast presence")
    anycast_countries: List[AnycastCountrySummary] = Field(default_factory=list)
    last_observation_ts: Optional[datetime] = Field(None, description="Last observation timestamp")
    forwarder_asn_count: int = Field(..., description="Unique ASNs for matching forwarders")
    forwarder_country_count: int = Field(..., description="Unique countries for matching forwarders")
    forwarder_entry_count: int = Field(..., description="Total forwarder entries for resolver")
    forwarder_countries: List[ForwarderCountrySummary] = Field(default_factory=list)


class ErrorResponse(Schema):
    error: str = Field(..., description="Error message")
    detail: Optional[str] = Field(None, description="Detailed error information")
