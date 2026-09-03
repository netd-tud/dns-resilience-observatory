"""Download a web file and run the resolver importer."""

from __future__ import annotations

import argparse
import base64
import logging
import shutil
import sys
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen

try:
    from loguru import logger
except ModuleNotFoundError:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    logger = logging.getLogger(__name__)

OBSERVATORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(OBSERVATORY_ROOT))

from data_gathering.imports.resolver.import_resolvers import import_resolvers


SUPPORTED_SUFFIXES = {".csv", ".parquet", ".pq", ".json", ".ndjson"}


def filename_from_url(url: str) -> str:
    path = unquote(urlparse(url).path)
    name = Path(path).name
    return name or "download.csv"


def ensure_supported_suffix(path: Path) -> Path:
    if path.suffix.lower() in SUPPORTED_SUFFIXES:
        return path
    return path.with_suffix(".csv")


def _request(
    url: str,
    *,
    username: str | None = None,
    password: str | None = None,
    accept: str | None = None,
) -> Request:
    if (username is None) != (password is None):
        raise ValueError("username and password must be provided together")

    headers = {"User-Agent": "dns-resilience-observatory/1.0"}
    if accept:
        headers["Accept"] = accept
    if username is not None and password is not None:
        credentials = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {credentials}"
    return Request(url, headers=headers)


def download_text(
    url: str,
    *,
    username: str | None = None,
    password: str | None = None,
    timeout: float | None = None,
) -> str:
    """Download a text response using the same HTTP client as file imports."""

    request = _request(
        url,
        username=username,
        password=password,
        accept="text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
    )
    with urlopen(request, timeout=timeout) as response:
        encoding = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(encoding, errors="replace")


def download_file(
    url: str,
    output_dir: Path | None = None,
    *,
    username: str | None = None,
    password: str | None = None,
    timeout: float | None = None,
    preserve_filename: bool = False,
) -> Path:
    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp(prefix="resolver-import-test-"))
    output_dir.mkdir(parents=True, exist_ok=True)

    target = output_dir / filename_from_url(url)
    if not preserve_filename:
        target = ensure_supported_suffix(target)
    logger.info("Downloading {url} to {path}", url=url, path=target)
    request = _request(url, username=username, password=password)
    temporary_target = target.with_name(f".{target.name}.part")
    try:
        with urlopen(request, timeout=timeout) as response, temporary_target.open("wb") as file_handle:
            shutil.copyfileobj(response, file_handle)
        temporary_target.replace(target)
    finally:
        temporary_target.unlink(missing_ok=True)
    logger.info("Downloaded {size} bytes", size=target.stat().st_size)
    return target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Download a file and run the resolver importer.")
    parser.add_argument("url", help="URL of the input file to download.")
    parser.add_argument(
        "--mapping",
        "-m",
        action="append",
        required=True,
        help="Resolver importer mapping as db_column:file_column. Can be repeated or comma-separated.",
    )
    parser.add_argument(
        "--modules",
        required=True,
        help="Comma-separated resolver modules: resolver,asn,prefix,location,protocol,dohpath,org,domain.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Directory for the downloaded file. Defaults to a temporary directory.",
    )
    parser.add_argument(
        "--verified",
        action="store_true",
        help="Pass verified=true to the resolver dry run.",
    )
    parser.add_argument(
        "--is-public",
        action="store_true",
        help="Set is_public=true when no is_public column is mapped.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Pass force=true to the resolver dry run.",
    )
    parser.add_argument(
        "--no-header",
        action="store_true",
        help="Read downloaded CSV input without a header row. Requires --headers.",
    )
    parser.add_argument(
        "--headers",
        help="Comma-separated CSV column names to use with --no-header.",
    )
    parser.add_argument(
        "--separator",
        default=",",
        help="CSV separator character. Use '\\t' for tab. Default: ','.",
    )
    parser.add_argument(
        "--source",
        help="Default source value when no source column is mapped. Defaults to the downloaded filename.",
    )
    parser.add_argument(
        "--no-dry-run",
        action="store_true",
        help="Write changes to the database. By default the script only reports what would happen.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    downloaded_path = download_file(args.url, output_dir=args.output_dir)
    logger.info("Running resolver import for {path}", path=downloaded_path)
    import_resolvers(
        downloaded_path,
        mapping=args.mapping,
        modules=args.modules,
        dry_run=not args.no_dry_run,
        verified=args.verified,
        force=args.force,
        has_header=not args.no_header,
        headers=args.headers,
        separator=args.separator,
        source=args.source,
        is_public=args.is_public,
    )


if __name__ == "__main__":
    main()
