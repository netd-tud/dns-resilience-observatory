#!/bin/sh
set -e

run_startup_tasks="${RUN_STARTUP_TASKS:-true}"
if [ -z "${RUN_STARTUP_TASKS+x}" ] && [ "$1" = "celery" ]; then
    case " $* " in
        *" call "*) run_startup_tasks="false" ;;
    esac
fi

if [ "$run_startup_tasks" = "true" ]; then
    if [ "${RUN_APPLY_SCHEMA:-true}" = "true" ] && [ "${DATABASE_ENGINE:-postgresql}" != "sqlite" ]; then
        echo "Applying observatory database schema"
        python db/apply_schema.py
    fi

    if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
        echo "Applying Django migrations"
        python manage.py migrate --noinput
    fi

    if [ "${RUN_CREATE_SUPERUSER:-true}" = "true" ] && [ -n "${DJANGO_SUPERUSER_USERNAME:-}" ] && [ -n "${DJANGO_SUPERUSER_PASSWORD:-}" ]; then
        if python manage.py shell -c "import os; from django.contrib.auth import get_user_model; User = get_user_model(); username = os.environ.get('DJANGO_SUPERUSER_USERNAME'); raise SystemExit(0 if User._default_manager.filter(**{User.USERNAME_FIELD: username}).exists() else 1)"; then
            echo "Django superuser already exists: ${DJANGO_SUPERUSER_USERNAME}"
        else
            echo "Creating Django superuser: ${DJANGO_SUPERUSER_USERNAME}"
            python manage.py createsuperuser --noinput || python manage.py shell -c "import os; from django.contrib.auth import get_user_model; User = get_user_model(); username = os.environ.get('DJANGO_SUPERUSER_USERNAME'); raise SystemExit(0 if User._default_manager.filter(**{User.USERNAME_FIELD: username}).exists() else 1)"
        fi
    elif [ "${RUN_CREATE_SUPERUSER:-true}" = "true" ]; then
        echo "Skipping Django superuser creation; DJANGO_SUPERUSER_USERNAME or DJANGO_SUPERUSER_PASSWORD is not set"
    fi
fi

exec "$@"
