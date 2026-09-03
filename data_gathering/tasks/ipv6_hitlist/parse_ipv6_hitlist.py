"""Stream IPv6 Hitlist CSV/XZ data into the resolver importer format."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import lzma
import struct
from pathlib import Path

from data_gathering.tasks.ipv6_hitlist.script_config import script_logger


logger = script_logger(__file__)
REQUIRED_COLUMNS = {"saddr", "sport", "classification", "success", "data"}
OUTPUT_COLUMNS = ["resolver_ip", "port", "protocol", "supported"]
DNS_HEADER_SIZE = 12
DNS_NOERROR = 0
DNS_RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


class DnsPayloadError(ValueError):
    """Raised when the data field is not a structurally valid DNS message."""


class DnsQueryPayloadError(DnsPayloadError):
    """Raised when the data field contains a query instead of a response."""


def _skip_dns_name(message: bytes, offset: int) -> int:
    """Return the first byte after one wire-format DNS name."""

    while True:
        if offset >= len(message):
            raise DnsPayloadError("truncated DNS name")
        length = message[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                raise DnsPayloadError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            if pointer >= len(message):
                raise DnsPayloadError("DNS compression pointer is outside the message")
            return offset + 2
        if length & 0xC0:
            raise DnsPayloadError("unsupported DNS label type")
        offset += 1 + length
        if offset > len(message):
            raise DnsPayloadError("truncated DNS label")


def _parse_resource_record(message: bytes, offset: int) -> tuple[int, int, int]:
    offset = _skip_dns_name(message, offset)
    if offset + 10 > len(message):
        raise DnsPayloadError("truncated DNS resource-record header")
    record_type, _record_class, ttl, data_length = struct.unpack_from("!HHIH", message, offset)
    offset += 10
    end = offset + data_length
    if end > len(message):
        raise DnsPayloadError("truncated DNS resource-record data")
    return end, record_type, ttl


def parse_dns_response_rcode(hex_payload: str) -> int:
    """Decode a DNS wire message and return its complete base/EDNS response code."""

    value = (hex_payload or "").strip()
    if value.lower().startswith("0x"):
        value = value[2:]
    try:
        message = bytes.fromhex(value)
    except ValueError as exc:
        raise DnsPayloadError("data is not valid hexadecimal") from exc
    if len(message) < DNS_HEADER_SIZE:
        raise DnsPayloadError("DNS message is shorter than its header")

    _identifier, flags, question_count, answer_count, authority_count, additional_count = struct.unpack_from(
        "!HHHHHH", message
    )
    if not flags & 0x8000:
        raise DnsQueryPayloadError("DNS message does not have the response bit set")

    offset = DNS_HEADER_SIZE
    for _ in range(question_count):
        offset = _skip_dns_name(message, offset)
        if offset + 4 > len(message):
            raise DnsPayloadError("truncated DNS question")
        offset += 4

    for _ in range(answer_count + authority_count):
        offset, _record_type, _ttl = _parse_resource_record(message, offset)

    extended_rcode = 0
    for _ in range(additional_count):
        offset, record_type, ttl = _parse_resource_record(message, offset)
        if record_type == 41:  # OPT pseudo-record: extended RCODE is the high TTL byte.
            extended_rcode = (ttl >> 24) & 0xFF

    return (extended_rcode << 4) | (flags & 0x0F)


def default_output_path(input_path: Path) -> Path:
    name = input_path.name
    if name.endswith(".csv.xz"):
        name = name[: -len(".csv.xz")]
    else:
        name = input_path.stem
    return input_path.with_name(f"{name}.parsed.csv")


def parse_ipv6_hitlist(input_path: Path, output_path: Path | None = None) -> dict[str, object]:
    output_path = output_path or default_output_path(input_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(f".{output_path.name}.part")

    counters = {
        "rows": 0,
        "successful": 0,
        "dns_noerror": 0,
        "dns_non_noerror": 0,
        "dns_not_response": 0,
        "invalid_dns_payload": 0,
        "written": 0,
        "invalid_ip": 0,
        "non_ipv6": 0,
        "invalid_port": 0,
        "missing_protocol": 0,
    }
    rcode_counts: dict[str, int] = {}
    try:
        with lzma.open(input_path, mode="rt", encoding="utf-8", newline="") as source_handle:
            reader = csv.DictReader(source_handle)
            missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
            if missing:
                raise ValueError(f"Input is missing required columns: {', '.join(sorted(missing))}")

            with temporary_path.open("w", encoding="utf-8", newline="") as target_handle:
                writer = csv.DictWriter(target_handle, fieldnames=OUTPUT_COLUMNS)
                writer.writeheader()
                for row in reader:
                    counters["rows"] += 1
                    if (row.get("success") or "").strip() != "1":
                        continue
                    counters["successful"] += 1

                    try:
                        rcode = parse_dns_response_rcode(row.get("data") or "")
                    except DnsQueryPayloadError:
                        counters["dns_not_response"] += 1
                        continue
                    except DnsPayloadError:
                        counters["invalid_dns_payload"] += 1
                        continue
                    rcode_name = DNS_RCODE_NAMES.get(rcode, f"RCODE_{rcode}")
                    rcode_counts[rcode_name] = rcode_counts.get(rcode_name, 0) + 1
                    if rcode != DNS_NOERROR:
                        counters["dns_non_noerror"] += 1
                        continue
                    counters["dns_noerror"] += 1

                    address = (row.get("saddr") or "").strip()
                    try:
                        ip = ipaddress.ip_address(address)
                    except ValueError:
                        counters["invalid_ip"] += 1
                        continue
                    if ip.version != 6:
                        counters["non_ipv6"] += 1
                        continue

                    try:
                        port = int((row.get("sport") or "").strip())
                    except ValueError:
                        counters["invalid_port"] += 1
                        continue
                    if not 1 <= port <= 65535:
                        counters["invalid_port"] += 1
                        continue

                    protocol = (row.get("classification") or "").strip().lower()
                    if not protocol:
                        counters["missing_protocol"] += 1
                        continue

                    writer.writerow(
                        {
                            "resolver_ip": ip.compressed,
                            "port": port,
                            "protocol": protocol,
                            "supported": "1",
                        }
                    )
                    counters["written"] += 1
        temporary_path.replace(output_path)
    finally:
        temporary_path.unlink(missing_ok=True)

    report: dict[str, object] = {
        **counters,
        "dns_rcodes": rcode_counts,
        "output": str(output_path),
    }
    logger.info("IPv6 Hitlist parse complete: {}", report)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Parse a compressed IPv6 Hitlist UDP/53 CSV.")
    parser.add_argument("input", type=Path, help="Input .csv.xz file")
    parser.add_argument("--output", type=Path, help="Parsed CSV output path")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    parse_ipv6_hitlist(args.input, args.output)


if __name__ == "__main__":
    main()
