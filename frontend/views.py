from django.conf import settings
from django.core.cache import cache
from django.core.serializers.json import DjangoJSONEncoder
from django.http import HttpResponse
from django.shortcuts import render
from django.template.loader import render_to_string
import json
import threading
import time

from resilience.services import dns_resilience_service


RESOLVER_DASHBOARD_CACHE_KEY = "frontend:resolver-dashboard-html:v1"
RESOLVER_DASHBOARD_CACHE_LOCK_KEY = "frontend:resolver-dashboard-html:v1:refreshing"
RESOLVER_DASHBOARD_CACHE_TTL = 60 * 60


def _render_resolver_dashboard_html() -> str:
    dashboard_summary = dns_resilience_service.get_dashboard_summary()
    return render_to_string(
        "frontend/resolver.html",
        {
            "api_base_url": settings.API_BASE_URL,
            "dashboard_summary_json": json.dumps(dashboard_summary, cls=DjangoJSONEncoder),
        },
    )


def _refresh_resolver_dashboard_cache() -> None:
    try:
        cache.set(
            RESOLVER_DASHBOARD_CACHE_KEY,
            {"html": _render_resolver_dashboard_html(), "created_at": time.time()},
            timeout=None,
        )
    finally:
        cache.delete(RESOLVER_DASHBOARD_CACHE_LOCK_KEY)


def _schedule_resolver_dashboard_refresh() -> None:
    if not cache.add(RESOLVER_DASHBOARD_CACHE_LOCK_KEY, True, timeout=300):
        return
    thread = threading.Thread(target=_refresh_resolver_dashboard_cache, daemon=True)
    thread.start()


def index(request):
    return render(request, "frontend/index.html", {"api_base_url": settings.API_BASE_URL})


def resolver_dashboard(request):
    cached_entry = cache.get(RESOLVER_DASHBOARD_CACHE_KEY)
    if cached_entry is None:
        _refresh_resolver_dashboard_cache()
        cached_entry = cache.get(RESOLVER_DASHBOARD_CACHE_KEY)
    elif time.time() - cached_entry.get("created_at", 0) >= RESOLVER_DASHBOARD_CACHE_TTL:
        _schedule_resolver_dashboard_refresh()

    response = HttpResponse(cached_entry["html"])
    response["Cache-Control"] = "public, max-age=300, stale-while-revalidate=3600"
    return response


def search(request):
    return render(request, "frontend/search.html", {"api_base_url": settings.API_BASE_URL})
