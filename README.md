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
| `data_gathering/tasks/manycast/manycast.conf` | Manycast IPv4/IPv6 export URLs, task logging, and data directory settings. |
| `data_gathering/tasks/manrs/manrs.conf` | MANRS API key, summary URL, request limits, retries, workers, and upsert batch size. |
| `data_gathering/tasks/ipv6_hitlist/ipv6_hitlist.conf` | IPv6 Hitlist Service username/password, output URL, storage paths, and request timeout. |
| `data_gathering/tasks/odns_v4/odns_v4.conf` | ODNS API and ODNS import settings. |
| `data_gathering/tasks/rpki/rpki.conf` | RIPEstat RPKI URL, request limits, retries, workers, and upsert batch size. |
| `data_gathering/tasks/webpage_resolver/webpage_resolver.conf` | Web resolver URL import definitions and column mappings. |
| `measurements/tasks/verify_resolvers/verify_resolvers.conf` | Active resolver verification measurement using ZDNS. |
| `measurements/tasks/verify_ipv6_resolvers/verify_ipv6_resolvers.conf` | Active IPv6 resolver verification using a ZDNS AAAA query over IPv6. |
| `measurements/tasks/dnssec_validation/dnssec_validation.conf` | Active per-resolver DNSSEC validation measurement using ZDNS. |
| `measurements/tasks/metainformation_resolvers/metainformation_resolvers.conf` | Resolver metainformation measurement using ZDNS PTR, SVCB, A, AAAA, and HTTPS lookups. |
| `db/data-sources.conf` | Source metadata inserted into the `data_source` table. |

Copy examples before running services:

```bash
cp .env.example .env
cp data_gathering/tasks/manrs/manrs.conf.example data_gathering/tasks/manrs/manrs.conf
cp data_gathering/tasks/ipv6_hitlist/ipv6_hitlist.conf.example data_gathering/tasks/ipv6_hitlist/ipv6_hitlist.conf
cp data_gathering/tasks/odns_v4/odns_v4.conf.example data_gathering/tasks/odns_v4/odns_v4.conf
cp data_gathering/tasks/rpki/rpki.conf.example data_gathering/tasks/rpki/rpki.conf
cp measurements/tasks/verify_resolvers/verify_resolvers.conf.example measurements/tasks/verify_resolvers/verify_resolvers.conf
cp measurements/tasks/verify_ipv6_resolvers/verify_ipv6_resolvers.conf.example measurements/tasks/verify_ipv6_resolvers/verify_ipv6_resolvers.conf
cp measurements/tasks/dnssec_validation/dnssec_validation.conf.example measurements/tasks/dnssec_validation/dnssec_validation.conf
cp measurements/tasks/metainformation_resolvers/metainformation_resolvers.conf.example measurements/tasks/metainformation_resolvers/metainformation_resolvers.conf
```

Replace these placeholders for setup:

- `.env`: set `POSTGRES_PASSWORD`, `DATABASE_PASSWORD`, `DJANGO_SECRET_KEY`, and `DJANGO_SUPERUSER_PASSWORD`; adjust `DJANGO_ALLOWED_HOSTS` / `API_BASE_URL` for deployment. Docker Compose configures the frontend to use same-origin `API_BASE_URL=/` in production.
- `data_gathering/tasks/odns_v4/odns_v4.conf`: replace `<ODNS_API_AUTH_TOKEN>` with the ODNS API token.
- `data_gathering/tasks/manrs/manrs.conf`: replace `<MANRS_API_KEY>` with the MANRS Observatory API key, then adjust the API URL, request rate, concurrency, retry, timeout, and batch settings when needed. This runtime file is ignored by Git and mounted read-only into the data-gathering containers.
- `data_gathering/tasks/ipv6_hitlist/ipv6_hitlist.conf`: replace `<IPV6_HITLIST_USERNAME>` and `<IPV6_HITLIST_PASSWORD>` with the registration credentials. The credentials remain in this ignored runtime file and are sent with HTTP Basic authentication.
- `data_gathering/tasks/rpki/rpki.conf`: adjust the public API URL, request rate, concurrency, retry, timeout, and batch settings when needed.
- `measurements/tasks/verify_resolvers/verify_resolvers.conf`: set `zdns_path` to the built ZDNS binary if it differs from `measurements/tools/zdns/zdns`; adjust `domain` if needed.
- `measurements/tasks/verify_ipv6_resolvers/verify_ipv6_resolvers.conf`: selects IPv6 resolver addresses and queries the configured domain's AAAA record using IPv6 transport; the default query name is `rr-mirror.research6.nawrocki.berlin`.
- `measurements/tasks/dnssec_validation/dnssec_validation.conf`: adjust ZDNS execution settings and resolver filters; keep `domain = dnssec-failed.org` for the validation heuristic.
- `measurements/tasks/metainformation_resolvers/metainformation_resolvers.conf`: adjust `modules` (`svcb`, `svcb,ptr,a`, or `svcb,ptr,a,aaaa,https`), `threads`, resolver filters, and `recursive_name_servers` if needed.
- Task `.conf` files: adjust `data_dir`, worker counts, fetch windows, URLs, and source mappings only if your deployment differs from the defaults.
- `db/data-sources.conf`: update source metadata only when adding or changing data sources.

If a runtime `.env` or `.conf` file is already tracked, keep the local file but remove it from Git with:

```bash
git rm --cached <path>
```

## Setup and Requirements

pgAdmin automatically renders `db/pgadmin/servers.json.tmp` from the PostgreSQL environment variables and loads the resulting server definition. No manual file rename or substitution is required.

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

Nginx is the only service with a public host-port mapping: `8000:80`. It accepts both domain-name and IP-address requests and forwards them to the private frontend container. PostgreSQL, RabbitMQ, and the API are available only on Docker networks. pgAdmin is bound to the server loopback interface (`127.0.0.1:5050`) and can be reached remotely using an SSH tunnel:

```bash
ssh -L 5050:127.0.0.1:5050 <USER>@<SERVER_IP>
```

Then open `http://localhost:5050` on your workstation.

Keep only the internal service names and local hosts in `.env`:

```env
DJANGO_ALLOWED_HOSTS=api,frontend,localhost,127.0.0.1
```

Nginx forwards the upstream request with `Host: frontend`, so Django needs only the internal `frontend` hostname in `DJANGO_ALLOWED_HOSTS`; the public domain or IP does not need to be listed. The public frontend uses same-origin `/api/` paths, so browser requests stay on port 8000 while the separate `api` service remains private.

## Common problems

### pgAdmin reports permission denied for `/var/lib/pgadmin/sessions`

The `pgadmin-init` service automatically creates the session directory and assigns the pgAdmin container user (UID `5050`) ownership of the mounted `db/pgadmin_vol` directory before pgAdmin starts. No host-side `chmod` or `chown` is required. After deploying this configuration, recreate pgAdmin and its dependency:

```bash
docker compose up -d --force-recreate pgadmin-init pgadmin
```

If it still fails, inspect the one-shot initializer:

```bash
docker compose logs pgadmin-init
```

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

The IPv6 verification task selects only IPv6 resolver addresses, forces IPv6 query transport, and
runs a ZDNS `AAAA` lookup for `rr-mirror.research6.nawrocki.berlin` by default:

```bash
docker compose exec measurements \
	celery -A measurements.celery_app call measurements.tasks.verify_ipv6_resolvers.run --queue measurements
```

The generated input and raw JSONL result are written below
`data/measurements/verify_ipv6_resolvers/`.

Per-resolver DNSSEC validation queries `dnssec-failed.org`. SERVFAIL is recorded as validating,
another DNS response as non-validating, and missing or invalid responses as unknown. The task writes
`resolver_ip,dnssec-validation` CSV output and imports every outcome into the database:

```bash
docker compose exec api python db/apply_schema.py
docker compose exec api python db/data_source.py
docker compose exec measurements \
	celery -A measurements.celery_app call measurements.tasks.dnssec_validation.run --queue measurements
```

An externally produced raw ZDNS JSONL file can be imported through the same historical measurement
tables. Put both files below `data/` and supply the original resolver input when available so targets
without a JSONL result are retained as unknown:

```bash
docker compose exec measurements \
	python -m measurements.scripts.import_dnssec_validation \
	/app/data/measurements/dnssec_validation/my-results.jsonl \
	--resolver-input /app/data/resolvers.txt
```

The external importer bulk-checks targets against the `resolver` table before inserting DNSSEC
observations. Addresses not present in `resolver` are skipped and reported as
`skipped_missing_resolver_count`; run totals therefore cover only resolvers in the database.

The importer derives an idempotent run key from the input contents, so running the same command again
does not increment the historical counters twice.

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
patch --forward -p1 < ../../patches/zdns-target-nameserver.patch
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

docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.ipv6_hitlist.refresh

docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.manrs.refresh

docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.rpki.refresh
```

5. Manual trigger (single task example):

```bash
docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.<topic>.<task_name>
```

### MANRS Readiness and RPKI

The MANRS task reads `manrs_api_key` from `data_gathering/tasks/manrs/manrs.conf` and authenticates
with the API's Bearer scheme. It queries the current-month `/api/v2/scores/summary` response
separately for every distinct ASN and country represented by recursive DNS resolvers. Resolver
countries are stored as ISO alpha-3 codes; the task converts them to alpha-2 economy codes for the
MANRS request and retains alpha-3 codes in `manrs_country`. It stores the five readiness
scores and trends, plus a readiness label per ASN or ready-ASN share per country. Scores and shares
are normalized to fractions from 0 to 1.

The RIPEstat task queries every distinct resolver BGP prefix/origin-ASN pair and stores its current
`valid`, `unknown`, `invalid_asn`, or `invalid_length` state. Successful API responses are upserted;
failed requests leave the previous row and timestamp unchanged. Both tasks run through the normal
daily data-gathering dispatcher and report target, fetched, upserted, and failed counts.

Run the tasks independently with:

```bash
docker compose run --rm data-gathering python3 db/data_source.py

docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.manrs.refresh

# Countries only
docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.manrs.refresh \
	--kwargs='{"scope":"country"}'

# ASNs only
docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.manrs.refresh \
	--kwargs='{"scope":"asn"}'

# Explicitly request both (also the default used by the scheduler)
docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.manrs.refresh \
	--kwargs='{"scope":"both"}'

docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.rpki.refresh
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

### IPv6 Hitlist Resolver Data

The IPv6 Hitlist refresh reads its registration credentials from
`data_gathering/tasks/ipv6_hitlist/ipv6_hitlist.conf`. It lists the authenticated output index,
selects the newest `YYYY-MM/` directory, and downloads its newest
`YYYY-MM-DD-udp53.csv.xz` file. If the newest directory has no matching file, it checks the
preceding listed month. The parser streams the compressed CSV and retains only rows where
`success == 1` whose hex-encoded `data` field is a structurally valid DNS response with the
complete base/EDNS response code `NOERROR`. It produces the four importer fields `resolver_ip`,
`port`, `protocol`, and `supported`.

The importer upserts these addresses as verified public recursive DNS resolvers and stores each
observed service in `resolver_service`. Its normal protocol normalization records the source
classification `udp` as `doudp`. A successful import also updates the source's
`last_retrieved_ts`.

Run the complete download/parse/import task with:

```bash
docker compose run --rm data-gathering python3 db/data_source.py

docker compose run --rm data-gathering \
	celery -A data_gathering.celery_app call data_gathering.tasks.ipv6_hitlist.refresh
```

The parser and importer can also be invoked separately:

```bash
docker compose run --rm data-gathering \
	python3 data_gathering/tasks/ipv6_hitlist/parse_ipv6_hitlist.py \
	/data/external/ipv6-hitlist/2026-08/2026-08-22-udp53.csv.xz \
	--output /data/interim/ipv6-hitlist/2026-08/2026-08-22-udp53.parsed.csv

docker compose run --rm data-gathering \
	python3 data_gathering/imports/ipv6_hitlist/import_ipv6_hitlist.py \
	/data/interim/ipv6-hitlist/2026-08/2026-08-22-udp53.parsed.csv \
	--no-dry-run
```

To download the latest file and export every deduplicated IPv6 `saddr`—one plain address per line,
without a header or prefix length—run:

```bash
docker compose run --rm data-gathering \
	python3 data_gathering/tasks/ipv6_hitlist/export_ipv6_resolver_ips.py
```

This standalone export does not inspect `success`, DNS RCODE, or the `data` field. Those filters
remain exclusive to database ingestion. The output is written to
`/data/exports/resolver-ipv6-YYYY-MM-DD.txt`, using the measurement date from the selected Hitlist
filename. On the host this is available below `data/exports/`.

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
| `GET /api/dns-resilience/resolver/{resolver_ip}/manrs` | MANRS readiness inherited from the ASN mapped to one resolver IP. |
| `GET /api/dns-resilience/ASN/{asn}/qmin` | QMIN aggregate data for an ASN. |
| `GET /api/dns-resilience/ASN/{asn}/anycast` | Anycast prefix coverage for an ASN. |
| `GET /api/dns-resilience/ASN/{asn}/anycast/sites` | Anycast backend countries and ASNs for an ASN. |
| `GET /api/dns-resilience/ASN/{asn}/spoofing` | Spoofing aggregate data for an ASN. |
| `GET /api/dns-resilience/ASN/{asn}/manrs` | MANRS readiness score for an ASN. |
| `GET /api/dns-resilience/country/{country}/qmin` | QMIN aggregate data for a country. |
| `GET /api/dns-resilience/country/{country}/anycast` | Anycast prefix coverage for a country. |
| `GET /api/dns-resilience/country/{country}/anycast/sites` | Anycast backend countries and ASNs for a country. |
| `GET /api/dns-resilience/country/{country}/spoofing` | Spoofing aggregate data for a country. |
| `GET /api/dns-resilience/country/{country}/dnssec` | DNSSEC validation data for a country. |
| `GET /api/dns-resilience/country/{country}/manrs` | MANRS readiness score for a country. |
| `GET /api/dns-resilience/global/ipv4` | Global IPv4 recursive resolver count and public share. |
| `GET /api/dns-resilience/global/ipv6` | Global IPv6 recursive resolver count and public share. |
| `GET /api/dns-resilience/global/dual-stack` | Number of resolver IDs with both IPv4 and IPv6 addresses. |
| `GET /api/dns-resilience/global/scope` | Global observatory coverage: resolver count, unique ASNs, unique country codes, latest resolver observation. |
| `GET /api/dns-resilience/global/practice-details/manrs/{entity_type}/{scope}` | Distinct ASN/country total, MANRS coverage, and average readiness for `open` or `closed` recursive DNS resolver deployments. |
| `GET /api/dns-resilience/global/anycast` | Global resolver anycast count and top resolver IPs by anycast backend sites. |
| `GET /api/dns-resilience/global/qmin` | Global QMIN measurement summary and parameter distributions. |
| `GET /api/dns-resilience/global/protocols` | Resolver service tests by protocol, port, and protocol-port combination, including tested, supported, and explicitly unsupported counts. |
| `GET /api/dns-resilience/global/spoofing` | Resolver IPs located in networks that allow spoofing. |
| `GET /api/dns-resilience/global/countries` | Resolver deployment by country code, including coordinates for the world map and top 10 countries. |
| `GET /api/dns-resilience/global/asns` | Top 10 ASNs by resolver count. |
| `GET /api/dns-resilience/global/dnssec` | Country-code DNSSEC measurement count and average validation percentage. |

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
        'https://manycast.net/api/v1/export/',
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
| `manycast` | IPv4 and IPv6 anycast prefix, ASN, and country-location evidence | `https://manycast.net/api/v1/export/` | No |
| `caida-spoofer` | IPv4 and IPv6 prefix-level spoofing observations | `https://api.spoofer.caida.org/sessions` | No |

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
| `protocol` | `ip`, `protocol` | `port`, `supported`, `source`, `last_update_ts` |
| `dohpath` | `ip`, `dohpath` | `source`, `last_update_ts` |
| `org` | `ip`, `org` | `source`, `last_update_ts` |
| `domain` | `ip`, `domain` | `source`, `last_update_ts` |

Example:

```bash
python data_gathering/imports/resolver/import_resolvers.py data/resolvers.pq \
    --mapping "ip:resolver_ip,is_public:is_public,source:source,last_update_ts:observed_at,asn:asn,prefix:bgp_prefix,country:country,protocol:protocol,port:port,supported:supported" \
    --modules "resolver,asn,prefix,location,protocol" \
    --no-dry-run
```

Raw ZDNS JSONL can be imported without first converting it to CSV. `--zdns-module` reads the
resolver address from `nameserver` (falling back to `results.<module>.data.resolver`) and keeps
only rows whose selected ZDNS module has status `NOERROR`. For `AAAA`, the queried address must
also occur in the AAAA answer set after excluding the `2001:67c:254::216` mirror control address;
this excludes forwarders whose upstream resolver answered the mirror query. This mode imports
resolver IPs only:

```bash
docker compose run --rm data-gathering \
    python3 data_gathering/imports/resolver/import_resolvers.py \
    /data/ipv6-aaaa.jsonl \
    --zdns-module AAAA \
    --source ipv6-hitlist-service \
    --is-public \
    --verified \
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
| `protocol` | `ip`, `protocol` | `supported`, `source`, `last_update_ts` |
| `endpoint` | `ip`, `endpoint` | `source`, `last_update_ts` |
| `org` | `ip`, `org` | `source`, `last_update_ts` |
| `domain` | `ip`, `domain` | `source`, `last_update_ts` |
| `upstream` | `ip`, `upstream_ip` | `source`, `last_update_ts` |

Example:

```bash
python data_gathering/imports/forwarder/import_forwarders.py data/forwarders.pq \
    --mapping "ip:forwarder_ip,is_public:is_public,source:source,last_update_ts:observed_at,asn:asn,prefix:bgp_prefix,country:country,protocol:protocol,supported:supported,upstream_ip:resolver_ip" \
    --modules "forwarder,asn,prefix,location,protocol,upstream" \
    --no-dry-run
```

For protocol imports, `supported=true` means the test succeeded and `supported=false` means the
protocol was explicitly tested but failed. If `supported` is not mapped, the importer defaults to
`true` for compatibility with discovery-only data sources. No `resolver_service` or
`forwarder_protocol` row means that protocol has not been tested for that resolver or forwarder.

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
