"""Discover and download the newest IPv6 Hitlist UDP/53 result."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

from data_gathering.tools.download_and_import_from_web import download_file, download_text


MONTH_PATTERN = re.compile(r"^(?P<year>\d{4})-(?P<month>0[1-9]|1[0-2])/$")
FILE_PATTERN = re.compile(
    r"^(?P<date>\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01]))-udp53\.csv\.xz$"
)


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href")
        if href:
            self.hrefs.append(href)


@dataclass(frozen=True)
class HitlistFile:
    month: str
    filename: str
    url: str
    measurement_date: date


def _links(document: str) -> list[str]:
    parser = _LinkParser()
    parser.feed(document)
    return parser.hrefs


def _basename(href: str) -> str:
    return Path(urlparse(href).path.rstrip("/")).name


def _month_directories(document: str) -> list[str]:
    months: set[str] = set()
    for href in _links(document):
        name = f"{_basename(href)}/"
        match = MONTH_PATTERN.fullmatch(name)
        if match:
            months.add(name)
    return sorted(months, reverse=True)


def _latest_udp53_file(document: str, directory_url: str, month: str) -> HitlistFile | None:
    candidates: list[HitlistFile] = []
    for href in _links(document):
        filename = _basename(href)
        match = FILE_PATTERN.fullmatch(filename)
        if not match:
            continue
        measurement_date = date.fromisoformat(match.group("date"))
        if measurement_date.strftime("%Y-%m/") != month:
            continue
        candidates.append(
            HitlistFile(
                month=month.rstrip("/"),
                filename=filename,
                url=urljoin(directory_url, href),
                measurement_date=measurement_date,
            )
        )
    return max(candidates, key=lambda item: (item.measurement_date, item.filename), default=None)


def discover_latest_udp53_file(
    base_url: str,
    *,
    username: str,
    password: str,
    timeout: float | None = None,
) -> HitlistFile:
    """Find the newest UDP/53 file, checking the preceding month if necessary."""

    base_url = base_url.rstrip("/") + "/"
    root_document = download_text(base_url, username=username, password=password, timeout=timeout)
    months = _month_directories(root_document)
    if not months:
        raise RuntimeError(f"No YYYY-MM/ directories found at {base_url}")

    for month in months[:2]:
        directory_url = urljoin(base_url, month)
        directory_document = download_text(
            directory_url,
            username=username,
            password=password,
            timeout=timeout,
        )
        selected = _latest_udp53_file(directory_document, directory_url, month)
        if selected is not None:
            return selected

    checked = ", ".join(months[:2])
    raise RuntimeError(f"No YYYY-MM-DD-udp53.csv.xz file found in checked directories: {checked}")


def fetch_latest_udp53_file(
    base_url: str,
    output_dir: Path,
    *,
    username: str,
    password: str,
    timeout: float | None = None,
) -> tuple[HitlistFile, Path]:
    selected = discover_latest_udp53_file(
        base_url,
        username=username,
        password=password,
        timeout=timeout,
    )
    downloaded = download_file(
        selected.url,
        output_dir=output_dir / selected.month,
        username=username,
        password=password,
        timeout=timeout,
        preserve_filename=True,
    )
    return selected, downloaded
