from __future__ import annotations

import csv
import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from measurements.tasks.dnssec_validation.dnssec_validation import (
    _extract_ip,
    _write_summary_csv,
    classify_dnssec_validation,
    parse_zdns_results,
)


UTC = dt.timezone.utc


class DnssecValidationClassificationTests(unittest.TestCase):
    def test_servfail_validates(self):
        self.assertIs(classify_dnssec_validation("SERVFAIL"), True)

    def test_other_dns_responses_do_not_validate(self):
        for status in ["NOERROR", "FORMERR", "NXDOMAIN", "REFUSED", "TRUNCATED"]:
            with self.subTest(status=status):
                self.assertIs(classify_dnssec_validation(status), False)

    def test_transport_and_tool_failures_are_unknown(self):
        for status in ["TIMEOUT", "ERROR", "ILLEGAL_INPUT", None]:
            with self.subTest(status=status):
                self.assertIsNone(classify_dnssec_validation(status))


class DnssecValidationParsingTests(unittest.TestCase):
    def test_nameserver_ip_supports_ipv4_and_ipv6_ports(self):
        self.assertEqual(_extract_ip("192.0.2.1:53"), "192.0.2.1")
        self.assertEqual(_extract_ip("[2001:db8::1]:53"), "2001:db8::1")

    def test_parser_preserves_order_and_fills_missing_results(self):
        fallback = dt.datetime(2026, 8, 30, tzinfo=UTC)
        rows = [
            {
                "nameserver": "1.1.1.1:53",
                "results": {
                    "A": {
                        "status": "SERVFAIL",
                        "timestamp": "2026-08-30T01:02:03Z",
                        "duration": 0.25,
                    }
                },
            },
            {
                "nameserver": "[2606:4700:4700::1111]:53",
                "results": {"A": {"status": "NOERROR", "timestamp": "2026-08-30T01:02:04Z"}},
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            raw_path = Path(directory) / "results.jsonl"
            raw_path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            observations = parse_zdns_results(
                raw_path,
                ["1.1.1.1", "9.9.9.9", "2606:4700:4700::1111"],
                fallback_timestamp=fallback,
            )

        self.assertEqual([item["resolver_ip"] for item in observations], ["1.1.1.1", "9.9.9.9", "2606:4700:4700::1111"])
        self.assertIs(observations[0]["dnssec_validation"], True)
        self.assertIsNone(observations[1]["dnssec_validation"])
        self.assertEqual(observations[1]["zdns_status"], "MISSING_OUTPUT")
        self.assertIs(observations[2]["dnssec_validation"], False)

    def test_summary_csv_has_exact_columns_and_values(self):
        observed_at = dt.datetime(2026, 8, 30, tzinfo=UTC)
        observations = [
            {
                "resolver_ip": "1.1.1.1",
                "dnssec_validation": True,
                "outcome": "validates",
                "zdns_status": "SERVFAIL",
                "observed_at": observed_at,
                "duration_seconds": 0.1,
            },
            {
                "resolver_ip": "8.8.8.8",
                "dnssec_validation": False,
                "outcome": "does_not_validate",
                "zdns_status": "NOERROR",
                "observed_at": observed_at,
                "duration_seconds": 0.1,
            },
            {
                "resolver_ip": "9.9.9.9",
                "dnssec_validation": None,
                "outcome": "unknown",
                "zdns_status": "TIMEOUT",
                "observed_at": observed_at,
                "duration_seconds": 8.0,
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "dnssec.csv"
            _write_summary_csv(output_path, observations)
            with output_path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(list(rows[0]), ["resolver_ip", "dnssec-validation"])
        self.assertEqual([row["dnssec-validation"] for row in rows], ["true", "false", ""])


if __name__ == "__main__":
    unittest.main()
