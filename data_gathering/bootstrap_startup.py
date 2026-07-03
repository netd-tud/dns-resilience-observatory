"""Run first-start data-gathering bootstrap prerequisites."""

from __future__ import annotations

from db.data_source import insert_sources


def main() -> None:
    insert_sources()


if __name__ == "__main__":
    main()
