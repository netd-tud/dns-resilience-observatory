from django.conf import settings
from django.shortcuts import render


def index(request):
    return render(request, "frontend/index.html", {"api_base_url": settings.API_BASE_URL})


def resolver_dashboard(request):
    return render(request, "frontend/resolver.html", {"api_base_url": settings.API_BASE_URL})


def search(request):
    return render(request, "frontend/search.html", {"api_base_url": settings.API_BASE_URL})
