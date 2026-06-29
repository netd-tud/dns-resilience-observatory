from django.db import models


class Resolver(models.Model):
    id = models.BigAutoField(primary_key=True)
    ip = models.GenericIPAddressField()
    asn = models.IntegerField(blank=True, null=True)
    bgp_prefix = models.TextField(blank=True, null=True)
    org = models.TextField(blank=True, null=True)
    org_short = models.TextField(blank=True, null=True)
    country = models.ForeignKey("CountryLocation", db_column="country", on_delete=models.DO_NOTHING, blank=True, null=True)
    is_public = models.BooleanField()
    supported_protocols = models.TextField(blank=True, null=True)
    last_observation_ts = models.DateTimeField()
    source = models.TextField()

    class Meta:
        managed = False
        db_table = "resolver"

class Forwarder(models.Model):
    id = models.BigAutoField(primary_key=True)
    ip = models.GenericIPAddressField()
    resolver_id = models.BigIntegerField(blank=True, null=True)
    forwarder_id = models.BigIntegerField(blank=True, null=True)
    type = models.TextField(blank=True, null=True)
    is_public = models.BooleanField(blank=True, null=True)
    supported_protocols = models.TextField(blank=True, null=True)
    asn = models.IntegerField(blank=True, null=True)
    bgp_prefix = models.TextField(blank=True, null=True)
    org = models.TextField(blank=True, null=True)
    org_short = models.TextField(blank=True, null=True)
    country = models.ForeignKey("CountryLocation", db_column="country", on_delete=models.DO_NOTHING, blank=True, null=True)
    last_observation_ts = models.DateTimeField()
    source = models.TextField()

    class Meta:
        managed = False
        db_table = "forwarder"


class CountryLocation(models.Model):
    country = models.TextField(primary_key=True)
    latitude = models.FloatField()
    longitude = models.FloatField()

    class Meta:
        managed = False
        db_table = "country_location"


class Anycast(models.Model):
    prefix = models.TextField(primary_key=True)
    country = models.ForeignKey(CountryLocation, db_column="country", on_delete=models.DO_NOTHING)
    number_locations = models.IntegerField()
    number_asns = models.IntegerField()
    asn = models.IntegerField(blank=True, null=True)
    org = models.TextField(blank=True, null=True)
    org_short = models.TextField(blank=True, null=True)
    last_observation_ts = models.DateTimeField()

    class Meta:
        managed = False
        db_table = "anycast"
