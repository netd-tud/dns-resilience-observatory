# DNS Resilience Observatory -- Understanding the Ecosystem of Recursive DNS Resolvers
Collaboration between TU Dresden and the Internet Society Pulse.
A project to better understand the DNS resolver ecosystem and assess the resilience of recursive DNS resolvers.

## Clone the Repository

Clone with submodules so measurement tools such as `measurements/tools/zdns` are available:

```bash
git clone --recurse-submodules <repository-url>
cd dns-resilience-observatory
```

If the repository was already cloned without submodules, initialize them with:

```bash
git submodule update --init --recursive
```

## Configuration Files

Runtime `.env` files can contain credentials and should stay local. Use the matching `.example` files as templates.

| Runtime file | Purpose |
| --- | --- |
| `.env` | Local Docker/Django/PostgreSQL/pgAdmin settings and data-gathering database connection settings. |
| `data_gathering/external_sources/caida/spoofer/spoofer.conf` | CAIDA Spoofer fetcher URL, paging, and data directory. |
| `data_gathering/tasks/apnic_dnssec/apnic_dnssec.conf` | APNIC DNSSEC task URLs, worker counts, batch sizes, and data directory. |
| `data_gathering/tasks/caida_spoofer/caida_spoofer.conf` | CAIDA Spoofer task fetch/import settings. |
| `data_gathering/tasks/manycast/manycast.conf` | Manycast task logging and data directory settings. |
| `data_gathering/tasks/odns_v4/odns_v4.conf` | ODNS API, Manycast fetch, and ODNS import settings. |
| `data_gathering/tasks/webpage_resolver/webpage_resolver.conf` | Web resolver URL import definitions and column mappings. |
| `measurements/tasks/verify_resolvers/verify_resolvers.conf` | Active resolver verification measurement using ZDNS. |
| `measurements/tasks/metainformation_resolvers/metainformation_resolvers.conf` | Resolver metainformation measurement using ZDNS PTR, SVCB, A, AAAA, and HTTPS lookups. |
| `db/data-sources.conf` | Source metadata inserted into the `data_source` table. |

Copy examples before running services:

```bash
cp .env.example .env
cp data_gathering/tasks/odns_v4/odns_v4.conf.example data_gathering/tasks/odns_v4/odns_v4.conf
cp measurements/tasks/verify_resolvers/verify_resolvers.conf.example measurements/tasks/verify_resolvers/verify_resolvers.conf
cp measurements/tasks/metainformation_resolvers/metainformation_resolvers.conf.example measurements/tasks/metainformation_resolvers/metainformation_resolvers.conf
```

Replace these placeholders for setup:

- `.env`: set `POSTGRES_PASSWORD`, `DATABASE_PASSWORD`, `DJANGO_SECRET_KEY`, `DJANGO_SUPERUSER_PASSWORD`, and adjust `DJANGO_ALLOWED_HOSTS` / `API_BASE_URL` for deployment. Docker Compose overrides container-internal values such as frontend `API_BASE_URL=http://api:8000`.
- `data_gathering/tasks/odns_v4/odns_v4.conf`: replace `<ODNS_API_AUTH_TOKEN>` with the ODNS API token.
- `measurements/tasks/verify_resolvers/verify_resolvers.conf`: set `zdns_path` to the built ZDNS binary if it differs from `measurements/tools/zdns/zdns`; adjust `domain` if needed.
- `measurements/tasks/metainformation_resolvers/metainformation_resolvers.conf`: adjust `modules` (`svcb`, `svcb,ptr,a`, or `svcb,ptr,a,aaaa,https`), `threads`, resolver filters, and `recursive_name_servers` if needed.
- Task `.conf` files: adjust `data_dir`, worker counts, fetch windows, URLs, and source mappings only if your deployment differs from the defaults.
- `db/data-sources.conf`: update source metadata only when adding or changing data sources.

If a runtime `.env` or `.conf` file is already tracked, keep the local file but remove it from Git with:

```bash
git rm --cached <path>
```

## Setup and Requirements

For pgAdmin, remove `.tmp` suffix from `db/pgadmin/servers.json.tmp` and replace placeholder values.

### Hardware Requirements

Base system without active measurements: 8 CPU cores and 16 GB RAM.

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

This installs the project-compatible `celery` command. If `celery` is not found, activate the virtual environment or run it through `.venv/bin/celery`; do not install or use the system package with `apt`, because distro Celery packages can pull incompatible dependencies.

`requirements.txt` uses `polars[rtcompat]` instead of plain `polars` so older CPUs/systems can use Polars without failing its runtime CPU feature check. For local runs on such systems, set `POLARS_SKIP_CPU_CHECK=1` before starting Python, Celery, or Django.

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

### Frontend on a Public Server IP

When serving the frontend via a public IP instead of localhost, replace `<SERVER_IP>` with the server address.

In `.env`:

```env
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1,<SERVER_IP>
API_BASE_URL=http://<SERVER_IP>:8000
```

In `docker-compose.yml`, add the same host to the API and frontend `DJANGO_ALLOWED_HOSTS`, and allow the frontend origin in the API CORS setting:

```yaml
api:
  environment:
    DJANGO_ALLOWED_HOSTS: "api,localhost,127.0.0.1,<SERVER_IP>"
    CORS_ALLOWED_ORIGINS: "http://localhost:8001,http://frontend:8000,http://<SERVER_IP>:8001"

frontend:
  environment:
    DJANGO_ALLOWED_HOSTS: "frontend,localhost,127.0.0.1,<SERVER_IP>"
```

The frontend service still uses `API_BASE_URL: "http://api:8000"` inside Docker; this is correct because frontend and API containers communicate over the Docker network.

## Data Gathering (Celery + RabbitMQ)

The data-gathering worker runs scheduled tasks and can be triggered manually. Tasks live under
`data_gathering/tasks/<topic>/` and are auto-discovered.

Scheduling is controlled via environment variables on the data-gathering service:

- `CELERY_SCHEDULED_TASK`: task name to run on a schedule (default: `data_gathering.tasks.dispatch.run_all`).
- `CELERY_SCHEDULE_CRON`: cron expression with 5 fields (default: `0 0 * * *`).
- `DATA_GATHERING_TASKS`: optional comma-separated allowlist of task names.

## Measurements

Resolver lists can be exported from the database:

```bash
python -m measurements.scripts.get_resolvers --verified true --is-public true --country DE --format txt
```

The first measurement task verifies resolvers by running a ZDNS `A` lookup for the configured domain through each resolver:

```bash
docker compose up -d --build measurements
docker compose exec measurements \
	celery -A measurements.celery_app call measurements.tasks.verify_resolvers.run --queue measurements
```

Resolver metainformation measurement:

```bash
docker compose exec measurements \
	celery -A measurements.celery_app call measurements.tasks.metainformation_resolvers.run --queue measurements
```

### Build ZDNS

The resolver verification task expects a ZDNS binary at `measurements/tools/zdns/zdns`.
The `measurements` Docker image builds this binary automatically. For local runs without Docker, install Go first, then compile the submodule:

```bash
git submodule update --init --recursive
cd measurements/tools/zdns
make
cd ../../..
```

Check the binary:

```bash
measurements/tools/zdns/zdns --help
```

## Data Gathering Manual Runs

Run these commands through Docker Compose on deployments. Do not run host `/usr/bin/celery` unless the project virtual environment is active.

1. Start the services:

```bash
docker compose up -d rabbitmq data-gathering
```

2. Manual trigger (run all registered tasks):

```bash
docker compose run --rm data-gathering python3 db/data_source.py
```

Then dispatch all registered tasks:

```bash
docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.dispatch.run_all
```

3. First database bootstrap, only when the database has no imported content:

```bash
docker compose run --rm data-gathering python3 db/data_source.py
```

Then dispatch the first-start bootstrap:

```bash
docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.dispatch.bootstrap_if_empty
```

The one-shot `data-gathering-run-on-start` service inserts data sources first and then uses this bootstrap task automatically. It skips itself once core content tables already contain rows.

4. Manual first-bootstrap task order:

```bash
docker compose run --rm data-gathering python3 db/data_source.py

docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.manycast.refresh

docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.caida_spoofer.refresh

docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.odns.refresh

docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.apnic_dnssec.refresh

docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.webpage_resolver.refresh
```

5. Manual trigger (single task example):

```bash
docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.<topic>.<task_name>
```

### Webpage Resolver URLs

The webpage resolver task imports resolver lists configured in
`data_gathering/tasks/webpage_resolver/webpage_resolver.conf`.

To add a URL, add one entry under `[urls]` and a matching `[url.<name>]` section:

```ini
[urls]
example_resolvers = https://example.org/resolvers.txt

[url.example_resolvers]
headers = resolver_ip
no_header = true
mapping = ip:resolver_ip
modules = resolver
separator = ,
source = webpage-resolver.example
description = Resolver list from example.org.
verified = false
force = false
```

The task name is `data_gathering.tasks.webpage_resolver.refresh`.

## API

Note: both ASGI and WSGI entry points are included; use ASGI for async/WebSockets and WSGI for traditional sync deployments.

### DNS Resilience Endpoints

Interactive API docs are available at `/api/docs/`; the OpenAPI document is available at `/api/openapi.json`.

All list-style endpoints accept `?limit=N` with `1 <= N <= 1000` and return matching resolver rows with metadata such as ASN, prefix, country, domains, and `protocol:port` services.

| Endpoint | Usage |
| --- | --- |
| `GET /api/dns-resilience/resolver/{resolver_ip}` | Resolver lookup by IPv4 or IPv6 address. |
| `GET /api/dns-resilience/prefix/{network_prefix}` | Resolver lookup by CIDR prefix. URL-encode `/`, for example `9.9.9.0%252F24` when called through the frontend-style double encoding. |
| `GET /api/dns-resilience/ASN/{asn}` | Resolver and aggregate lookup by ASN, e.g. `AS3320` or `3320`. |
| `GET /api/dns-resilience/country/{country}` | Resolver and aggregate lookup by ISO country code, alpha-2 or alpha-3. |
| `GET /api/dns-resilience/domain/{domain}` | Resolver lookup by associated resolver domain, e.g. `one.one.one.one`. |
| `GET /api/dns-resilience/protocol/{service}` | Resolver lookup by protocol or `protocol:port`, e.g. `doh`, `doh3:443`, `dot:853`, `doq:853`, `dotcp:53`, or `doudp:53`. |
| `GET /api/dns-resilience/resolver/{resolver_ip}/summary` | Resolver summary for the frontend: metadata, domains, sibling IPs, QMIN, anycast, spoofing, and open-forwarder relay aggregates. |
| `GET /api/dns-resilience/resolver/{resolver_ip}/qmin` | QMIN data for one resolver IP. |
| `GET /api/dns-resilience/resolver/{resolver_ip}/anycast` | Anycast prefix coverage for one resolver IP. |
| `GET /api/dns-resilience/resolver/{resolver_ip}/anycast/sites` | Anycast backend countries and ASNs for one resolver IP. |
| `GET /api/dns-resilience/resolver/{resolver_ip}/spoofing` | Spoofing prefix data containing one resolver IP. |
| `GET /api/dns-resilience/ASN/{asn}/qmin` | QMIN aggregate data for an ASN. |
| `GET /api/dns-resilience/ASN/{asn}/anycast` | Anycast prefix coverage for an ASN. |
| `GET /api/dns-resilience/ASN/{asn}/anycast/sites` | Anycast backend countries and ASNs for an ASN. |
| `GET /api/dns-resilience/ASN/{asn}/spoofing` | Spoofing aggregate data for an ASN. |
| `GET /api/dns-resilience/country/{country}/qmin` | QMIN aggregate data for a country. |
| `GET /api/dns-resilience/country/{country}/anycast` | Anycast prefix coverage for a country. |
| `GET /api/dns-resilience/country/{country}/anycast/sites` | Anycast backend countries and ASNs for a country. |
| `GET /api/dns-resilience/country/{country}/spoofing` | Spoofing aggregate data for a country. |
| `GET /api/dns-resilience/dashboard/summary` | Global dashboard summary used by the frontend start page. |

### Current Database Schema

The database is normalized around the currently populated data areas. Schema creation lives in
[db/apply_schema.py](db/apply_schema.py).

| Area | Purpose | Associated tables |
| --- | --- | --- |
| `data_source` | Registry of external data sources. Every imported `source` value must exist here first. | `data_source` |
| `resolver` | Recursive resolver IPs and resolver attributes. The base table maps IPs to stable resolver IDs; attributes are stored in one-purpose tables. | `resolver_id`, `resolver`, `resolver_asn`, `resolver_prefix`, `resolver_org`, `resolver_location`, `resolver_service`, `resolver_dohpath`, `resolver_domain`, `resolver_verification` |
| `forwarder` | Forwarder IPs, forwarder attributes, and upstream relationships to resolvers or other forwarders. | `forwarder_id`, `forwarder`, `forwarder_asn`, `forwarder_prefix`, `forwarder_org`, `forwarder_location`, `forwarder_protocol`, `forwarder_endpoint`, `forwarder_domain`, `forwarder_resolver_upstream`, `forwarder_forwarder_upstream` |
| `anycast` | Anycast prefixes, prefix ASNs, and backend evidence by country and ASN. | `anycast`, `anycast_asn`, `anycast_country_backend`, `anycast_asn_backend` |
| `spoofing` | CAIDA Spoofer prefix-level spoofing results with ASN and country attributes. | `spoofing`, `spoofing_asn`, `spoofing_country` |

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
    ),
    (
        'caida-spoofer',
        'https://www.caida.org/projects/spoofer/',
        'https://api.spoofer.caida.org/sessions',
        'https://www.caida.org/projects/spoofer/',
        FALSE
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
| `caida-spoofer` | Prefix-level spoofing observations | `https://api.spoofer.caida.org/sessions` | No |

## Importers

The generic importers accept CSV, Parquet (`.parquet`/`.pq`), JSON, and NDJSON files. Use
`--mapping db_column:file_column` to map file columns to importer fields. Mappings can be repeated
or comma-separated. Imports run as dry-runs by default; pass `--no-dry-run` to commit. Pass
`--force` to overwrite existing rows regardless of timestamp checks.

If no `last_update_ts` column is mapped, resolver and forwarder importers use the current UTC
timestamp for the import run. The anycast importer also fills `last_update_ts` when absent.

#### Resolver Importer

Script: [data_gathering/imports/resolver/import_resolvers.py](data_gathering/imports/resolver/import_resolvers.py)

Modules and required mapped fields:

| Module | Required mapping | Optional fields used |
| --- | --- | --- |
| `resolver` | `ip` | `is_public`, `source`, `last_update_ts` |
| `asn` | `ip`, `asn` | `source`, `last_update_ts` |
| `prefix` | `ip`, `prefix` | `source`, `last_update_ts` |
| `location` | `ip`, `country` | `city`, `source`, `last_update_ts` |
| `protocol` | `ip`, `protocol` | `source`, `last_update_ts` |
| `dohpath` | `ip`, `dohpath` | `source`, `last_update_ts` |
| `org` | `ip`, `org` | `source`, `last_update_ts` |
| `domain` | `ip`, `domain` | `source`, `last_update_ts` |

Example:

```bash
python data_gathering/imports/resolver/import_resolvers.py data/resolvers.pq \
    --mapping "ip:resolver_ip,is_public:is_public,source:source,last_update_ts:observed_at,asn:asn,prefix:bgp_prefix,country:country,protocol:protocol" \
    --modules "resolver,asn,prefix,location,protocol" \
    --no-dry-run
```

#### Forwarder Importer

Script: [data_gathering/imports/forwarder/import_forwarders.py](data_gathering/imports/forwarder/import_forwarders.py)

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
python data_gathering/imports/forwarder/import_forwarders.py data/forwarders.pq \
    --mapping "ip:forwarder_ip,is_public:is_public,source:source,last_update_ts:observed_at,asn:asn,prefix:bgp_prefix,country:country,protocol:protocol,upstream_ip:resolver_ip" \
    --modules "forwarder,asn,prefix,location,protocol,upstream" \
    --no-dry-run
```

#### Anycast Importer

Script: [data_gathering/imports/anycast/import_anycast.py](data_gathering/imports/anycast/import_anycast.py)

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
python data_gathering/imports/anycast/import_anycast.py data/manycast.pq \
    --mapping "prefix:prefix,backing_prefix:backing_prefix,partial:partial,asn:ASN,country:locations" \
    --modules "anycast,asn,location" \
    --source manycast \
    --no-dry-run
```
