from pathlib import Path
import os
import dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
dotenv.load_dotenv(BASE_DIR / ".env")
ENV = {**dotenv.dotenv_values(BASE_DIR / ".env"), **dict(os.environ)}


def _get_env_list(name: str, default: str = "") -> list[str]:
    value = ENV.get(name, default)
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


SECRET_KEY = ENV.get("DJANGO_SECRET_KEY", "django-insecure-change-me")
DEBUG = ENV.get("DJANGO_DEBUG", "false").lower() == "true"
ALLOWED_HOSTS = _get_env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")
CSRF_TRUSTED_ORIGINS = _get_env_list("DJANGO_CSRF_TRUSTED_ORIGINS")


INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "corsheaders",
    "ninja",
    "api",
    "frontend",
    "resilience",
]

MIDDLEWARE = [
    "django.middleware.cache.UpdateCacheMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.cache.FetchFromCacheMiddleware",
]

ROOT_URLCONF = "dns_resilience_observatory.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    }
]

WSGI_APPLICATION = "dns_resilience_observatory.wsgi.application"
ASGI_APPLICATION = "dns_resilience_observatory.asgi.application"

DATABASE_ENGINE = ENV.get("DATABASE_ENGINE", "postgresql").lower()
if DATABASE_ENGINE == "sqlite":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": ENV.get("DATABASE_NAME", "dns_resilience_observatory"),
            "USER": ENV.get("DATABASE_USER", "postgres"),
            "PASSWORD": ENV.get("DATABASE_PASSWORD", ""),
            "HOST": ENV.get("DATABASE_HOST", "localhost"),
            "PORT": ENV.get("DATABASE_PORT", "5432"),
        }
    }

SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "dns-resilience-observatory-api",
    }
}
CACHE_MIDDLEWARE_SECONDS = 600
CACHE_MIDDLEWARE_KEY_PREFIX = "dns-resilience-observatory"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

CORS_ALLOW_ALL_ORIGINS = ENV.get("CORS_ALLOW_ALL_ORIGINS", "false").lower() == "true"
CORS_ALLOWED_ORIGINS = _get_env_list("CORS_ALLOWED_ORIGINS")

API_BASE_URL = ENV.get("API_BASE_URL", "http://localhost:8000")
