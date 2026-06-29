"""Download a web file and run the resolver importer."""

from __future__ import annotations

import argparse
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


def download_file(url: str, output_dir: Path | None = None) -> Path:
    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp(prefix="resolver-import-test-"))
    output_dir.mkdir(parents=True, exist_ok=True)

    target = ensure_supported_suffix(output_dir / filename_from_url(url))
    logger.info("Downloading {url} to {path}", url=url, path=target)
    request = Request(url, headers={"User-Agent": "dns-resilience-observatory/1.0"})
    with urlopen(request) as response, target.open("wb") as file_handle:
        shutil.copyfileobj(response, file_handle)
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
        help="Comma-separated resolver modules: resolver,asn,prefix,location,protocol,endpoint,org,domain.",
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
    )


if __name__ == "__main__":
    main()
