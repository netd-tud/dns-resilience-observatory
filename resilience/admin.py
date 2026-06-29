from django.contrib import admin

from resilience.models import Anycast, CountryLocation, Resolver, Forwarder

"""
Admin configuration for the resilience app. This file defines how the tables are displayed and managed in the Django admin interface.
"""

@admin.register(Resolver)
class ResolverAdmin(admin.ModelAdmin):
    list_display = ("id", "ip", "asn", "country", "org_short", "is_public", "last_observation_ts")
    search_fields = ("ip", "asn", "country", "org", "org_short")
    list_filter = ("country", "is_public")

@admin.register(Forwarder)
class ForwarderAdmin(admin.ModelAdmin):
    list_display = ("id", "ip", "asn", "country", "org_short", "last_observation_ts")
    search_fields = ("ip", "asn", "country", "org", "org_short")
    list_filter = ("country",)

@admin.register(Anycast)
class AnycastAdmin(admin.ModelAdmin):
    list_display = ("prefix", "country", "asn", "org_short", "number_locations", "number_asns", "last_observation_ts")
    search_fields = ("prefix", "country__country", "asn", "org", "org_short")
    list_filter = ("country",)


@admin.register(CountryLocation)
class CountryLocationAdmin(admin.ModelAdmin):
    list_display = ("country", "latitude", "longitude")
    search_fields = ("country",)
