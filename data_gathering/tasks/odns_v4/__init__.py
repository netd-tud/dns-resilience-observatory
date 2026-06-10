"""
Collect open resolver and forwarder IPv4 data from ODNS-API.
The ODNS-API provides data on open resolvers and forwarders, including their IP addresses, timestamps of requests, and other metadata.
This module fetches the data from the ODNS-API, saves it in JSON format, and then converts it to Parquet format for efficient storage and analysis.
"""
