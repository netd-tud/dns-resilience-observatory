from django.conf import settings
from django.shortcuts import render


def index(request):
    return render(request, "frontend/index.html", {"api_base_url": settings.API_BASE_URL})
