#!/usr/bin/env python3
"""Render the pgAdmin server-definition template with Docker environment values."""

import json
import os
import sys
from pathlib import Path
from string import Template


def json_string(value: str) -> str:
    """Return a JSON string value without its surrounding quotes."""
    return json.dumps(value)[1:-1]


def main() -> None:
    output_path = Path(sys.argv[1])
    values = {
        "PGADMIN_HOST": os.environ.get("PGADMIN_HOST", "postgres"),
        "PGADMIN_DATABASE_PORT": os.environ.get("PGADMIN_DATABASE_PORT", "5432"),
        "PGADMIN_DB": os.environ["POSTGRES_DB"],
        "PGADMIN_USER": os.environ["POSTGRES_USER"],
        "PGADMIN_PASSWORD": os.environ["POSTGRES_PASSWORD"],
    }
    try:
        values["PGADMIN_DATABASE_PORT"] = str(int(values["PGADMIN_DATABASE_PORT"]))
    except ValueError as error:
        raise SystemExit("PGADMIN_DATABASE_PORT must be an integer") from error

    template = Template(Path(__file__).with_name("servers.json.tmp").read_text())
    rendered = template.substitute(
        **{
            name: (value if name == "PGADMIN_DATABASE_PORT" else json_string(value))
            for name, value in values.items()
        }
    )
    json.loads(rendered)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(f"{rendered}\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(f"Usage: {Path(sys.argv[0]).name} OUTPUT_PATH")
    main()
