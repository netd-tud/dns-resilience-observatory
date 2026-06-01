import json
from django.http import JsonResponse
from django.template.response import TemplateResponse


def redoc_docs_view(request, api_instance):
    openapi_schema = api_instance.get_openapi_schema()
    context = {
        "title": openapi_schema.get("info", {}).get("title", "API"),
        "openapi_json": json.dumps(openapi_schema, ensure_ascii=False),
    }
    return TemplateResponse(request, "redoc_docs.html", context)


def openapi_json_view(request, api_instance):
    schema = api_instance.get_openapi_schema()
    return JsonResponse(schema)
