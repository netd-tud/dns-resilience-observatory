import datetime as dt
from pathlib import Path
from urllib.request import urlretrieve

from data_gathering.tasks.odns_v4.script_config import required_config_value, script_logger


logger = script_logger(__file__)


def _data_dir() -> Path:
    return Path(required_config_value(__file__, "data_dir"))


def fetch_manycast_data_v4(
    *,
    output_dir: Path | None = None,
    url: str | None = None,
) -> Path:
    output_dir = output_dir or _data_dir() / "external"
    url = url or required_config_value(__file__, "manycast_api_url")
    output_dir.mkdir(parents=True, exist_ok=True)

    today = dt.datetime.now().strftime("%Y-%m-%d")
    output_path = output_dir / f"manycast-v4-{today}.pq"
    tmp_path = output_path.with_suffix(".tmp")

    logger.info("Manycast: downloading {} to {}", url, output_path)
    urlretrieve(url, tmp_path)
    tmp_path.replace(output_path)
    logger.info("Manycast: download complete: {}", output_path)
    return output_path
