"""Rate-limited JSON HTTP client shared by public data-source fetchers."""

from __future__ import annotations

import json
import threading
import time
from email.utils import parsedate_to_datetime
from collections.abc import Mapping
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class JsonFetchError(RuntimeError):
    """Raised when an upstream JSON request cannot be completed."""


class _RateLimiter:
    def __init__(self, requests_per_second: float):
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be greater than zero")
        self._interval = 1.0 / requests_per_second
        self._lock = threading.Lock()
        self._next_request = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            delay = max(0.0, self._next_request - now)
            self._next_request = max(now, self._next_request) + self._interval
        if delay:
            time.sleep(delay)


class JsonHttpClient:
    def __init__(
        self,
        *,
        timeout_seconds: float,
        requests_per_second: float,
        retries: int,
        backoff_seconds: float,
        user_agent: str = "dns-resilience-observatory/1.0",
        default_headers: Mapping[str, str] | None = None,
    ):
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        if retries < 0:
            raise ValueError("retries cannot be negative")
        if backoff_seconds < 0:
            raise ValueError("backoff_seconds cannot be negative")
        self.timeout_seconds = timeout_seconds
        self.retries = retries
        self.backoff_seconds = backoff_seconds
        self.user_agent = user_agent
        self.default_headers = dict(default_headers or {})
        self.rate_limiter = _RateLimiter(requests_per_second)

    @staticmethod
    def _retry_after(error: HTTPError) -> float | None:
        value = error.headers.get("Retry-After")
        if not value:
            return None
        try:
            return max(0.0, float(value))
        except ValueError:
            try:
                retry_at = parsedate_to_datetime(value)
                return max(0.0, retry_at.timestamp() - time.time())
            except (TypeError, ValueError, OverflowError):
                return None

    def get(self, url: str, params: dict[str, object]) -> dict[str, Any]:
        request_url = f"{url}?{urlencode(params)}"
        for attempt in range(self.retries + 1):
            self.rate_limiter.wait()
            headers = {
                "Accept": "application/json",
                "User-Agent": self.user_agent,
                **self.default_headers,
            }
            request = Request(
                request_url,
                headers=headers,
            )
            try:
                with urlopen(request, timeout=self.timeout_seconds) as response:
                    payload = json.load(response)
                if not isinstance(payload, dict):
                    raise JsonFetchError(f"Expected a JSON object from {url}")
                return payload
            except HTTPError as error:
                retryable = error.code == 429 or 500 <= error.code < 600
                if not retryable or attempt >= self.retries:
                    raise JsonFetchError(f"HTTP {error.code} from {url}") from error
                delay = self._retry_after(error)
            except (URLError, TimeoutError, json.JSONDecodeError, OSError) as error:
                if attempt >= self.retries:
                    raise JsonFetchError(f"Unable to fetch JSON from {url}: {error}") from error
                delay = None

            if delay is None:
                delay = self.backoff_seconds * (2**attempt)
            if delay:
                time.sleep(delay)

        raise JsonFetchError(f"Unable to fetch JSON from {url}")
