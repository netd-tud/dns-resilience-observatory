from django.contrib import admin
from django.urls import include, path
from api.api import api
from api.docs_views import openapi_json_view, redoc_docs_view

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("frontend.urls")),
    path("api/", api.urls),
    path("api/docs/", lambda request: redoc_docs_view(request, api), name="redoc-docs"),
    path("api/openapi.json", lambda request: openapi_json_view(request, api), name="openapi-json"),
]
