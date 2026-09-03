import datetime as dt
from pathlib import Path
import tempfile
from urllib.request import urlretrieve

from data_gathering.external_sources.config import external_data_dir
from data_gathering.tasks.manycast.script_config import required_config_value, script_logger


CONFIG_KEY = "fetcher.py"
logger = script_logger(CONFIG_KEY)


def normalize_ip_version(ip_version: int | str) -> int:
    text = str(ip_version).strip().lower().removeprefix("ipv").removeprefix("v")
    if text not in {"4", "6"}:
        raise ValueError(f"Manycast IP version must be 4 or 6, got {ip_version!r}")
    return int(text)


def _latest_existing_manycast(output_dir: Path, ip_version: int) -> Path | None:
    candidates = list(output_dir.glob(f"manycast-v{ip_version}-*.pq"))
    if ip_version == 4:
        candidates.extend(output_dir.glob("manycast_*.pq"))
    candidates = [path for path in candidates if path.is_file()]
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)


def fetch(
    *,
    output_dir: Path | None = None,
    url: str | None = None,
    ip_version: int | str = 4,
) -> Path:
    ip_version = normalize_ip_version(ip_version)
    output_dir = output_dir or external_data_dir()
    url = url or required_config_value(CONFIG_KEY, f"manycast_ipv{ip_version}_url")
    output_dir.mkdir(parents=True, exist_ok=True)

    today = dt.datetime.now().strftime("%Y-%m-%d")
    output_path = output_dir / f"manycast-v{ip_version}-{today}.pq"
    temporary = tempfile.NamedTemporaryFile(
        prefix=f".{output_path.name}.",
        suffix=".tmp",
        dir=output_dir,
        delete=False,
    )
    temporary.close()
    tmp_path = Path(temporary.name)

    logger.info("Manycast IPv{}: downloading {} to {}", ip_version, url, output_path)
    try:
        urlretrieve(url, tmp_path)
        tmp_path.replace(output_path)
        logger.info("Manycast: download complete: {}", output_path)
        return output_path
    except Exception as exc:
        if tmp_path.exists():
            tmp_path.unlink()
        fallback_path = _latest_existing_manycast(output_dir, ip_version)
        if fallback_path is not None:
            logger.warning(
                "Manycast IPv{ip_version}: download failed ({error}); using existing fallback file {path}",
                ip_version=ip_version,
                error=exc,
                path=fallback_path,
            )
            return fallback_path
        raise RuntimeError(
            f"Manycast IPv{ip_version} download failed and no family-matching fallback was found in {output_dir}"
        ) from exc
