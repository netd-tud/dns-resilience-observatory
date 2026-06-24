# DNS Resilience Observatory -- Understanding the Ecosystem of Recursive DNS Resolvers
Collaboration between TU Dresden and the Internet Society Pulse.
A project to better understand the DNS resolver ecosystem and assess the resilience of recursive DNS resolvers.

## Setup and Requirements

For pgAdmin, remove `.tmp` suffix from `db/pgadmin/servers.json.tmp` and replace placeholder values.

### Local Python Environment

For local testing, use a project-local virtual environment. This project supports `uv`; install it
from the official Astral documentation: [Installing uv](https://docs.astral.sh/uv/getting-started/installation/).

Quick install on Linux/macOS:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Create and populate the virtual environment:

```bash
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
```

Activate the environment in later shells with:

```bash
source .venv/bin/activate
```

Deactivate it with:

```bash
deactivate
```

## Database

Schema creation and updates are handled by [db/apply_schema.py](db/apply_schema.py). The script is
idempotent and can run against a local or remote PostgreSQL instance.

Connection settings (in order of precedence):

- `DATABASE_URL` (full PostgreSQL URL)
- `DATABASE_HOST`, `DATABASE_PORT`, `DATABASE_USER`, `DATABASE_PASSWORD`, `DATABASE_NAME`
	(defaults to `localhost`, `5432`, `postgres`, empty password, `dns_resilience_observatory`)

Install dependencies:

```bash
python -m pip install "psycopg[binary]" python-dotenv
```

## Docker

Local PostgreSQL via Docker Compose is available in [docker-compose.yml](docker-compose.yml).

1. Copy the env file and edit credentials if needed.

```bash
cp .env.example .env
```

2. Start the database.

```bash
docker compose up -d
```

3. Apply the schema.

```bash
python db/apply_schema.py
```

Run:

```bash
python db/apply_schema.py
```

## Data Gathering (Celery + RabbitMQ)

The data-gathering worker runs scheduled tasks and can be triggered manually. Tasks live under
`data_gathering/tasks/<topic>/` and are auto-discovered.

Scheduling is controlled via environment variables on the data-gathering service:

- `CELERY_SCHEDULED_TASK`: task name to run on a schedule (default: `data_gathering.tasks.dispatch.run_all`).
- `CELERY_SCHEDULE_CRON`: cron expression with 5 fields (default: `0 0 * * *`).
- `DATA_GATHERING_TASKS`: optional comma-separated allowlist of task names.

1. Start the services:

```bash
docker compose up -d rabbitmq data-gathering
```

2. Manual trigger (run all registered tasks):

```bash
docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.dispatch.run_all
```

3. Manual trigger (single task example):

```bash
docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.<topic>.<task_name>
```

## API

Note: both ASGI and WSGI entry points are included; use ASGI for async/WebSockets and WSGI for traditional sync deployments.

### DNS Resilience Endpoints

- `GET /api/dns-resilience/resolver/{resolver-ip}`
- `GET /api/dns-resilience/prefix/{network-prefix}`
- `GET /api/dns-resilience/ASN/{asn}`
- `GET /api/dns-resilience/country/{country}`

### Resolver Anycast Summary

- `GET /api/dns-resilience/resolver/{resolver-ip}/summary`
	- Returns resolver presence in the resolver table, anycast presence, unique anycast site count,
		unique country count, unique ASN count, and per-country anycast site counts with coordinates.

### Current Database Schema

The database is normalized around four currently populated data areas. Schema creation lives in
[db/apply_schema.py](db/apply_schema.py).

| Area | Purpose | Associated tables |
| --- | --- | --- |
| `data_source` | Registry of external data sources. Every imported `source` value must exist here first. | `data_source` |
| `resolver` | Recursive resolver IPs and resolver attributes. The base table maps IPs to stable resolver IDs; attributes are stored in one-purpose tables. | `resolver_id`, `resolver`, `resolver_asn`, `resolver_prefix`, `resolver_org`, `resolver_location`, `resolver_protocol`, `resolver_endpoint`, `resolver_domain`, `resolver_verification` |
| `forwarder` | Forwarder IPs, forwarder attributes, and upstream relationships to resolvers or other forwarders. | `forwarder_id`, `forwarder`, `forwarder_asn`, `forwarder_prefix`, `forwarder_org`, `forwarder_location`, `forwarder_protocol`, `forwarder_endpoint`, `forwarder_domain`, `forwarder_resolver_upstream`, `forwarder_forwarder_upstream` |
| `anycast` | Anycast prefixes, prefix ASNs, and backend evidence by country and ASN. | `anycast`, `anycast_asn`, `anycast_country_backend`, `anycast_asn_backend` |

All source-bearing tables use `source` as a foreign key to `data_source(source)`. Add source
metadata before running imports that reference that source.

Example source registration:

```sql
INSERT INTO data_source (
    source,
    url,
    api_endpoint,
    documentation_endpoint,
    apikey_required
)
VALUES
    (
        'manycast',
        'https://manycast.net/',
        'https://manycast.net/api/v1/export/IPv4-latest.parquet',
        'https://manycast.net/',
        FALSE
    ),
    (
        'odns-api',
        'https://odns-data.netd.cs.tu-dresden.de/',
        'https://odns-data.netd.cs.tu-dresden.de/api/v2/ODNSQuery/GetDnsEntries',
        'https://odns-data.netd.cs.tu-dresden.de/',
        TRUE
    )
ON CONFLICT (source)
DO UPDATE SET
    url = EXCLUDED.url,
    api_endpoint = EXCLUDED.api_endpoint,
    documentation_endpoint = EXCLUDED.documentation_endpoint,
    apikey_required = EXCLUDED.apikey_required;
```

### External Sources

| Source | Used for | API endpoint | API key required |
| --- | --- | --- | --- |
| `odns-api` | Resolver, forwarder, and ODNS-derived anycast backend evidence | `https://odns-data.netd.cs.tu-dresden.de/api/v2/ODNSQuery/GetDnsEntries` | Yes |
| `manycast` | Anycast prefix, ASN, and country-location evidence | `https://manycast.net/api/v1/export/IPv4-latest.parquet` | No |

## Importers

The generic importers accept CSV, Parquet (`.parquet`/`.pq`), JSON, and NDJSON files. Use
`--mapping db_column:file_column` to map file columns to importer fields. Mappings can be repeated
or comma-separated. Imports run as dry-runs by default; pass `--no-dry-run` to commit. Pass
`--force` to overwrite existing rows regardless of timestamp checks.

If no `last_update_ts` column is mapped, resolver and forwarder importers use the current UTC
timestamp for the import run. The anycast importer also fills `last_update_ts` when absent.

#### Resolver Importer

Script: [data_gathering/import/resolver/import_resolvers.py](data_gathering/import/resolver/import_resolvers.py)

Modules and required mapped fields:

| Module | Required mapping | Optional fields used |
| --- | --- | --- |
| `resolver` | `ip` | `is_public`, `source`, `last_update_ts` |
| `asn` | `ip`, `asn` | `source`, `last_update_ts` |
| `prefix` | `ip`, `prefix` | `source`, `last_update_ts` |
| `location` | `ip`, `country` | `city`, `source`, `last_update_ts` |
| `protocol` | `ip`, `protocol` | `source`, `last_update_ts` |
| `endpoint` | `ip`, `endpoint` | `source`, `last_update_ts` |
| `org` | `ip`, `org` | `source`, `last_update_ts` |
| `domain` | `ip`, `domain` | `source`, `last_update_ts` |

Example:

```bash
python data_gathering/import/resolver/import_resolvers.py data/resolvers.pq \
    --mapping "ip:resolver_ip,is_public:is_public,source:source,last_update_ts:observed_at,asn:asn,prefix:bgp_prefix,country:country,protocol:protocol" \
    --modules "resolver,asn,prefix,location,protocol" \
    --no-dry-run
```

#### Forwarder Importer

Script: [data_gathering/import/forwarder/import_forwarders.py](data_gathering/import/forwarder/import_forwarders.py)

Modules and required mapped fields:

| Module | Required mapping | Optional fields used |
| --- | --- | --- |
| `forwarder` | `ip` | `is_public`, `source`, `last_update_ts` |
| `asn` | `ip`, `asn` | `source`, `last_update_ts` |
| `prefix` | `ip`, `prefix` | `source`, `last_update_ts` |
| `location` | `ip`, `country` | `city`, `source`, `last_update_ts` |
| `protocol` | `ip`, `protocol` | `source`, `last_update_ts` |
| `endpoint` | `ip`, `endpoint` | `source`, `last_update_ts` |
| `org` | `ip`, `org` | `source`, `last_update_ts` |
| `domain` | `ip`, `domain` | `source`, `last_update_ts` |
| `upstream` | `ip`, `upstream_ip` | `source`, `last_update_ts` |

Example:

```bash
python data_gathering/import/forwarder/import_forwarders.py data/forwarders.pq \
    --mapping "ip:forwarder_ip,is_public:is_public,source:source,last_update_ts:observed_at,asn:asn,prefix:bgp_prefix,country:country,protocol:protocol,upstream_ip:resolver_ip" \
    --modules "forwarder,asn,prefix,location,protocol,upstream" \
    --no-dry-run
```

#### Anycast Importer

Script: [data_gathering/import/anycast/import_anycast.py](data_gathering/import/anycast/import_anycast.py)

Modules and required mapped fields:

| Module | Required mapping | Optional fields used |
| --- | --- | --- |
| `anycast` | `prefix` | `backing_prefix`, `partial`, `source`, `last_update_ts` |
| `asn` | `prefix`, `asn` | `source`, `last_update_ts` |
| `asn_backend` | `prefix`, `asn` | `asn_count`, `source`, `last_update_ts` |
| `location` | `prefix`, `country` | `country_count`, `source`, `last_update_ts` |

If `source` is not mapped, pass `--source`. The source must already exist in `data_source`.
For backend tables, non-force updates only apply when the incoming timestamp is newer and the
incoming count is higher.

Example:

```bash
python data_gathering/import/anycast/import_anycast.py data/manycast.pq \
    --mapping "prefix:prefix,backing_prefix:backing_prefix,partial:partial,asn:ASN,country:locations" \
    --modules "anycast,asn,location" \
    --source manycast \
    --no-dry-run
```
