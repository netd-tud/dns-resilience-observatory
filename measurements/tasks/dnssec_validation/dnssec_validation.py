"""Measure resolver DNSSEC validation using dnssec-failed.org."""

from __future__ import annotations

import configparser
import csv
import datetime as dt
import ipaddress
import json
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from loguru import logger

from measurements.celery_app import app
from measurements.db import connect
from measurements.scripts.get_resolvers import query_resolvers


BASE_DIR = Path(__file__).resolve().parents[3]
CONFIG_FILE = Path(__file__).with_suffix(".conf")
EXAMPLE_CONFIG_FILE = Path(__file__).with_suffix(".conf.example")
DEFAULT_DOMAIN = "dnssec-failed.org"
DEFAULT_SOURCE = "measurements.zdns.dnssec"
DNS_RESPONSE_STATUSES = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "REFUSED", "TRUNCATED"}


def _optional_bool(value: str | None) -> bool | None:
    if value is None or not value.strip():
        return None
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y"}:
        return True
    if normalized in {"0", "false", "no", "n"}:
        return False
    raise ValueError(f"Invalid boolean config value: {value}")


def _optional_int(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    return int(value)


def load_config(path: Path = CONFIG_FILE) -> dict[str, str]:
    parser = configparser.ConfigParser()
    read_files = parser.read(path)
    if not read_files and path == CONFIG_FILE:
        read_files = parser.read(EXAMPLE_CONFIG_FILE)
    if not read_files:
        raise FileNotFoundError(f"Missing dnssec_validation config: {path}")
    return dict(parser["dnssec_validation"])


def _resolve_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else BASE_DIR / path


def _resolver_ips(rows: list[dict[str, Any]]) -> tuple[list[str], int]:
    resolver_ips: list[str] = []
    skipped = 0
    for row in rows:
        ip = ipaddress.ip_interface(str(row["resolver_ip"])).ip
        if not ip.is_global:
            skipped += 1
            continue
        resolver_ips.append(str(ip))
    return resolver_ips, skipped


def classify_dnssec_validation(status: str | None) -> bool | None:
    """Map a ZDNS result status to the dnssec-failed.org validation heuristic."""

    normalized = str(status or "").upper()
    if normalized == "SERVFAIL":
        return True
    if normalized in DNS_RESPONSE_STATUSES:
        return False
    return None


def _extract_ip(value: object) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.startswith("["):
        closing = text.find("]")
        candidate = text[1:closing] if closing > 1 else text
    else:
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            host, separator, port = text.rpartition(":")
            candidate = host if separator and port.isdigit() else text
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _parse_timestamp(value: object, fallback: dt.datetime) -> dt.datetime:
    text = str(value or "").strip()
    if not text:
        return fallback
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return fallback
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _observation(
    resolver_ip: str,
    *,
    status: str,
    validation: bool | None,
    observed_at: dt.datetime,
    duration_seconds: float | None,
) -> dict[str, object]:
    if validation is True:
        outcome = "validates"
    elif validation is False:
        outcome = "does_not_validate"
    else:
        outcome = "unknown"
    return {
        "resolver_ip": resolver_ip,
        "dnssec_validation": validation,
        "outcome": outcome,
        "zdns_status": status,
        "observed_at": observed_at,
        "duration_seconds": duration_seconds,
    }


def parse_zdns_results(
    raw_output_path: Path,
    resolver_ips: list[str],
    *,
    fallback_timestamp: dt.datetime,
) -> list[dict[str, object]]:
    """Normalize one ZDNS result per requested resolver, retaining unknowns."""

    normalized_ips = [str(ipaddress.ip_address(ip)) for ip in resolver_ips]
    requested = set(normalized_ips)
    observations = {
        ip: _observation(
            ip,
            status="MISSING_OUTPUT",
            validation=None,
            observed_at=fallback_timestamp,
            duration_seconds=None,
        )
        for ip in normalized_ips
    }

    with raw_output_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping invalid ZDNS JSON on line {line_number}", line_number=line_number)
                continue

            if not isinstance(row, dict):
                logger.warning("Skipping non-object ZDNS JSON on line {line_number}", line_number=line_number)
                continue
            results = row.get("results")
            result = results.get("A", {}) if isinstance(results, dict) else {}
            if not isinstance(result, dict):
                result = {}
            data = result.get("data") if isinstance(result.get("data"), dict) else {}
            resolver_ip = _extract_ip(row.get("nameserver")) or _extract_ip(data.get("resolver"))
            if resolver_ip not in requested:
                logger.warning(
                    "Skipping DNSSEC result without a matching target resolver: nameserver={nameserver}",
                    nameserver=row.get("nameserver") or data.get("resolver"),
                )
                continue

            status = str(result.get("status") or "MISSING_STATUS").upper()
            validation = classify_dnssec_validation(status)
            duration_value = result.get("duration")
            try:
                duration_seconds = float(duration_value) if duration_value is not None else None
            except (TypeError, ValueError):
                duration_seconds = None
            observations[resolver_ip] = _observation(
                resolver_ip,
                status=status,
                validation=validation,
                observed_at=_parse_timestamp(result.get("timestamp"), fallback_timestamp),
                duration_seconds=duration_seconds,
            )

    return [observations[ip] for ip in normalized_ips]


def _run_zdns(command: list[str]) -> None:
    logger.info("Running ZDNS command: {command}", command=" ".join(command))
    process = subprocess.Popen(
        command,
        cwd=BASE_DIR,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
    )
    assert process.stdout is not None
    for line in process.stdout:
        line = line.strip()
        if line:
            logger.info("zdns: {line}", line=line)
    return_code = process.wait()
    if return_code != 0:
        raise RuntimeError(f"zdns failed with exit code {return_code}")


def _write_summary_csv(output_path: Path, observations: list[dict[str, object]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            dir=output_path.parent,
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            writer = csv.DictWriter(handle, fieldnames=["resolver_ip", "dnssec-validation"])
            writer.writeheader()
            for observation in observations:
                validation = observation["dnssec_validation"]
                writer.writerow(
                    {
                        "resolver_ip": observation["resolver_ip"],
                        "dnssec-validation": "" if validation is None else str(validation).lower(),
                    }
                )
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def _ensure_source(cursor, source: str) -> None:
    cursor.execute(
        """
        INSERT INTO data_source (source, url, documentation_endpoint, description, apikey_required)
        VALUES (%s, %s, %s, %s, FALSE)
        ON CONFLICT (source) DO NOTHING
        """,
        (
            source,
            "https://github.com/zmap/zdns",
            "https://github.com/zmap/zdns",
            "Active resolver DNSSEC validation measurement using dnssec-failed.org.",
        ),
    )


def _start_run(
    *,
    run_key: str,
    started_at: dt.datetime,
    query_name: str,
    output_file: str,
    source: str,
    target_count: int,
) -> tuple[int, bool, dict[str, object] | None]:
    with connect() as connection:
        with connection.cursor() as cursor:
            _ensure_source(cursor, source)
            cursor.execute(
                """
                INSERT INTO dnssec_measurement_run (
                    run_key, started_at, status, query_name, output_file, source, target_count
                )
                VALUES (%s, %s, 'running', %s, %s, %s, %s)
                ON CONFLICT (run_key) DO NOTHING
                RETURNING id
                """,
                (run_key, started_at, query_name, output_file, source, target_count),
            )
            row = cursor.fetchone()
            if row:
                return int(row[0]), False, None

            cursor.execute(
                """
                SELECT id, status, target_count, validating_count, non_validating_count,
                       unknown_count, output_file, started_at, finished_at
                FROM dnssec_measurement_run
                WHERE run_key = %s
                """,
                (run_key,),
            )
            existing = cursor.fetchone()
            if existing is None:
                raise RuntimeError(f"Unable to create or load DNSSEC measurement run {run_key}")
            if existing[1] == "complete":
                report = {
                    "run_id": int(existing[0]),
                    "resolver_count": int(existing[2]),
                    "validating_count": int(existing[3]),
                    "non_validating_count": int(existing[4]),
                    "unknown_count": int(existing[5]),
                    "output_file": existing[6],
                    "reused_run": True,
                }
                return int(existing[0]), True, report

            cursor.execute(
                """
                UPDATE dnssec_measurement_run
                SET started_at = %s, finished_at = NULL, status = 'running', query_name = %s,
                    output_file = %s, source = %s, target_count = %s,
                    validating_count = 0, non_validating_count = 0, unknown_count = 0, error = NULL
                WHERE id = %s
                """,
                (started_at, query_name, output_file, source, target_count, existing[0]),
            )
            return int(existing[0]), False, None


def _import_observations(
    *,
    run_id: int,
    observations: list[dict[str, object]],
    source: str,
    finished_at: dt.datetime,
) -> int:
    validating_count = sum(item["dnssec_validation"] is True for item in observations)
    non_validating_count = sum(item["dnssec_validation"] is False for item in observations)
    unknown_count = len(observations) - validating_count - non_validating_count

    with connect() as connection:
        with connection.cursor() as cursor:
            _ensure_source(cursor, source)
            cursor.execute(
                """
                CREATE TEMP TABLE dnssec_observation_stage (
                    ip INET NOT NULL,
                    observed_at TIMESTAMPTZ NOT NULL,
                    validates BOOLEAN,
                    outcome TEXT NOT NULL,
                    zdns_status TEXT NOT NULL,
                    duration_seconds DOUBLE PRECISION
                ) ON COMMIT DROP
                """
            )
            with cursor.copy(
                """
                COPY dnssec_observation_stage (
                    ip, observed_at, validates, outcome, zdns_status, duration_seconds
                ) FROM STDIN
                """
            ) as copy:
                for item in observations:
                    copy.write_row(
                        (
                            item["resolver_ip"],
                            item["observed_at"],
                            item["dnssec_validation"],
                            item["outcome"],
                            item["zdns_status"],
                            item["duration_seconds"],
                        )
                    )

            cursor.execute(
                """
                WITH inserted AS (
                    INSERT INTO dnssec_resolver_observation (
                        run_id, ip, observed_at, validates, outcome, zdns_status, duration_seconds
                    )
                    SELECT %s, ip, observed_at, validates, outcome, zdns_status, duration_seconds
                    FROM dnssec_observation_stage
                    ON CONFLICT (run_id, ip) DO NOTHING
                    RETURNING ip, observed_at, validates
                ),
                projected AS (
                    INSERT INTO dnssec_resolver (
                        ip, validates, total_measurements, seen_measurements,
                        validation_count, last_update_ts, source
                    )
                    SELECT
                        ip,
                        validates,
                        1,
                        (validates IS NOT NULL)::INTEGER,
                        (validates IS TRUE)::INTEGER,
                        observed_at,
                        %s
                    FROM inserted
                    ON CONFLICT (ip) DO UPDATE SET
                        validates = CASE
                            WHEN EXCLUDED.last_update_ts >= dnssec_resolver.last_update_ts
                            THEN EXCLUDED.validates
                            ELSE dnssec_resolver.validates
                        END,
                        total_measurements = dnssec_resolver.total_measurements + 1,
                        seen_measurements = dnssec_resolver.seen_measurements + EXCLUDED.seen_measurements,
                        validation_count = dnssec_resolver.validation_count + EXCLUDED.validation_count,
                        last_update_ts = GREATEST(dnssec_resolver.last_update_ts, EXCLUDED.last_update_ts),
                        source = CASE
                            WHEN EXCLUDED.last_update_ts >= dnssec_resolver.last_update_ts
                            THEN EXCLUDED.source
                            ELSE dnssec_resolver.source
                        END
                    RETURNING ip
                )
                SELECT COUNT(*) FROM projected
                """,
                (run_id, source),
            )
            inserted_count = int(cursor.fetchone()[0])
            cursor.execute(
                """
                UPDATE dnssec_measurement_run
                SET finished_at = %s, status = 'complete', validating_count = %s,
                    non_validating_count = %s, unknown_count = %s, error = NULL
                WHERE id = %s
                """,
                (finished_at, validating_count, non_validating_count, unknown_count, run_id),
            )
    return inserted_count


def _mark_run_failed(run_id: int, error: Exception) -> None:
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE dnssec_measurement_run
                    SET finished_at = %s, status = 'failed', error = %s
                    WHERE id = %s
                    """,
                    (dt.datetime.now(dt.timezone.utc), str(error), run_id),
                )
    except Exception:
        logger.exception("Failed to mark DNSSEC measurement run {run_id} as failed", run_id=run_id)


def run_dnssec_validation(
    config_path: Path = CONFIG_FILE,
    *,
    run_key: str | None = None,
) -> dict[str, object]:
    monotonic_start = time.monotonic()
    started_at = dt.datetime.now(dt.timezone.utc)
    config = load_config(config_path)
    domain = config.get("domain", DEFAULT_DOMAIN).strip() or DEFAULT_DOMAIN
    source = config.get("source", DEFAULT_SOURCE).strip() or DEFAULT_SOURCE
    run_key = run_key or str(uuid.uuid4())
    output_dir = _resolve_path(config.get("output_dir", "data/measurements/dnssec_validation"))
    output_dir.mkdir(parents=True, exist_ok=True)
    input_path = output_dir / config.get("input_file", "resolvers.txt")
    output_path = output_dir / config.get("output_file", "dnssec_validation.csv")

    rows = query_resolvers(
        verified=_optional_bool(config.get("verified")),
        is_public=_optional_bool(config.get("is_public")),
        source=config.get("resolver_source") or None,
        country=config.get("country") or None,
        asn=_optional_int(config.get("asn")),
        limit=_optional_int(config.get("limit")),
    )
    resolver_ips, skipped_resolvers = _resolver_ips(rows)
    input_path.write_text("\n".join(resolver_ips) + ("\n" if resolver_ips else ""), encoding="utf-8")

    run_id, reused, reused_report = _start_run(
        run_key=run_key,
        started_at=started_at,
        query_name=domain,
        output_file=str(output_path),
        source=source,
        target_count=len(resolver_ips),
    )
    if reused:
        assert reused_report is not None
        reused_report.update(
            {
                "run_key": run_key,
                "skipped_non_global_resolvers": skipped_resolvers,
                "elapsed_seconds": round(time.monotonic() - monotonic_start, 3),
            }
        )
        return reused_report

    raw_output_path: Path | None = None
    try:
        if resolver_ips:
            with tempfile.NamedTemporaryFile(
                prefix=".dnssec-validation-",
                suffix=".jsonl",
                dir=output_dir,
                delete=False,
            ) as raw_handle:
                raw_output_path = Path(raw_handle.name)
            command = [
                str(_resolve_path(config.get("zdns_path", "measurements/tools/zdns/zdns"))),
                "A",
                "--name-server-mode",
                f"--override-name={domain}",
                f"--input-file={input_path}",
                f"--output-file={raw_output_path}",
                f"--threads={config.get('threads', '100')}",
                f"--network-timeout={config.get('network_timeout', '8')}",
                f"--retries={config.get('retries', '1')}",
            ]
            if _optional_bool(config.get("no_recycle_sockets", "true")):
                command.append("--no-recycle-sockets")
            _run_zdns(command)
            observations = parse_zdns_results(
                raw_output_path,
                resolver_ips,
                fallback_timestamp=started_at,
            )
        else:
            observations = []

        _write_summary_csv(output_path, observations)
        finished_at = dt.datetime.now(dt.timezone.utc)
        inserted_count = _import_observations(
            run_id=run_id,
            observations=observations,
            source=source,
            finished_at=finished_at,
        )
    except Exception as error:
        _mark_run_failed(run_id, error)
        raise
    finally:
        if raw_output_path is not None and raw_output_path.exists():
            raw_output_path.unlink()

    validating_count = sum(item["dnssec_validation"] is True for item in observations)
    non_validating_count = sum(item["dnssec_validation"] is False for item in observations)
    unknown_count = len(observations) - validating_count - non_validating_count
    report = {
        "run_id": run_id,
        "run_key": run_key,
        "resolver_count": len(resolver_ips),
        "skipped_non_global_resolvers": skipped_resolvers,
        "validating_count": validating_count,
        "non_validating_count": non_validating_count,
        "unknown_count": unknown_count,
        "inserted_observation_count": inserted_count,
        "output_file": str(output_path),
        "elapsed_seconds": round(time.monotonic() - monotonic_start, 3),
    }
    logger.info("Finished DNSSEC validation measurement: {report}", report=report)
    return report


@app.task(bind=True, name="measurements.tasks.dnssec_validation.run")
def run(self) -> dict[str, object]:
    return run_dnssec_validation(run_key=str(self.request.id or uuid.uuid4()))
