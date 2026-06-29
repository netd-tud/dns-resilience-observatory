FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    grep -vE '^[[:space:]]*(-e[[:space:]]+\.)[[:space:]]*$|^[[:space:]]*\.[[:space:]]*$' /app/requirements.txt > /tmp/requirements-deps.txt \
    && pip install -r /tmp/requirements-deps.txt

COPY . /app
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-deps -e /app

RUN chmod +x /app/docker-entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
