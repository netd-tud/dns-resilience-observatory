import datetime as dt
from pathlib import Path
from urllib.request import urlretrieve

from data_gathering.external_sources.config import external_data_dir
from data_gathering.tasks.odns_v4.script_config import required_config_value, script_logger


CONFIG_KEY = "fetch_manycast_data_v4.py"
logger = script_logger(CONFIG_KEY)


def _latest_existing_manycast(output_dir: Path) -> Path | None:
    candidates = [
        *output_dir.glob("manycast-v4-*.pq"),
        *output_dir.glob("manycast_*.pq"),
    ]
    candidates = [path for path in candidates if path.is_file()]
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)


def fetch(
    *,
    output_dir: Path | None = None,
    url: str | None = None,
) -> Path:
    output_dir = output_dir or external_data_dir()
    url = url or required_config_value(CONFIG_KEY, "manycast_api_url")
    output_dir.mkdir(parents=True, exist_ok=True)

    today = dt.datetime.now().strftime("%Y-%m-%d")
    output_path = output_dir / f"manycast-v4-{today}.pq"
    tmp_path = output_path.with_suffix(".tmp")

    logger.info("Manycast: downloading {} to {}", url, output_path)
    try:
        urlretrieve(url, tmp_path)
        tmp_path.replace(output_path)
        logger.info("Manycast: download complete: {}", output_path)
        return output_path
    except Exception as exc:
        if tmp_path.exists():
            tmp_path.unlink()
        fallback_path = _latest_existing_manycast(output_dir)
        if fallback_path is not None:
            logger.warning(
                "Manycast: download failed ({error}); using existing fallback file {path}",
                error=exc,
                path=fallback_path,
            )
            return fallback_path
        raise RuntimeError(
            f"Manycast download failed and no existing manycast parquet file was found in {output_dir}"
        ) from exc
