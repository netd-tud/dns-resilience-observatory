"""Run host-network IPv6 measurements directly, without Celery."""

from __future__ import annotations

import argparse
import json
import uuid

from measurements.tasks.dnssec_validation.dnssec_validation import run_dnssec_validation
from measurements.tasks.verify_ipv6_resolvers.verify_ipv6_resolvers import (
    run_verify_ipv6_resolvers,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Export IPv6 resolver targets from PostgreSQL, run ZDNS using the shared "
            "host-network configuration, and import the results."
        )
    )
    parser.add_argument(
        "measurement",
        nargs="?",
        choices=("all", "verify", "dnssec"),
        default="all",
        help="Measurement to run (default: all).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    reports: dict[str, object] = {}
    if args.measurement in {"all", "verify"}:
        reports["verify"] = run_verify_ipv6_resolvers()
    if args.measurement in {"all", "dnssec"}:
        reports["dnssec"] = run_dnssec_validation(
            run_key=str(uuid.uuid4()),
            ip_version=6,
        )
    print(json.dumps(reports, default=str, indent=2))


if __name__ == "__main__":
    main()
