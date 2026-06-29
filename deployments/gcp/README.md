# DeepintShield on GCP

Deploy the open-source DeepintShield AI gateway to **Cloud Run**, backed by
**Memorystore for Redis** (semantic-cache vector store) and **Cloud SQL for
PostgreSQL** (config + logs). A **GKE + Helm** alternative is documented at the
bottom.

## Architecture (at a glance)

```
                      Internet (HTTPS, managed TLS)
                                 |
                          [ Cloud Run ]  deepintshield  (stateless, autoscaled 1..N)
                          image: deepintshield/ai-security
                          listens :8080  /health
                                 |
              Serverless VPC Access connector (private egress)
                                 |
        +------------------------+--------------------------+
        |                                                   |
[ Memorystore for Redis ]                        [ Cloud SQL for PostgreSQL ]
 vector store (RediSearch)                        config_store + logs_store
 DEEPINTSHIELD_REDIS_ADDR                          DEEPINTSHIELD_PG{HOST,PORT,USER,PASSWORD,DATABASE}
```

The gateway holds no durable state. Restarting or scaling Cloud Run instances
loses nothing - all state is in Memorystore + Cloud SQL.

## Prerequisites

- **`gcloud` CLI** installed and authenticated: `gcloud auth login` and
  `gcloud config set project YOUR_PROJECT`.
- A GCP **project with billing enabled**.
- Roles on your principal: roughly `roles/run.admin`, `roles/cloudsql.admin`,
  `roles/redis.admin`, `roles/vpcaccess.admin`, `roles/secretmanager.admin`,
  and `roles/iam.serviceAccountUser`. `roles/owner` covers all of them.
- `openssl` available locally (used to generate the DB password).
- **Quotas / regional availability:** Memorystore and Cloud SQL must be available
  in your `REGION`. The Serverless VPC connector needs a free `/28` range that
  does not overlap existing subnets in the VPC.

The deploy script enables these APIs for you: `run`, `redis`, `sqladmin`,
`vpcaccess`, `servicenetworking`, `secretmanager`.

## Deploy

```bash
cd deployments/gcp

# Minimal: set your project (or have it in `gcloud config`), then run.
export PROJECT_ID=my-project
export REGION=us-central1

./deploy.sh
```

The script is **idempotent** - re-running reconciles rather than recreating. On
success it prints the Cloud Run URL and a health-check command.

### What the script does

1. Enables required APIs.
2. Creates a **Serverless VPC Access connector** so Cloud Run can reach
   Memorystore on its private IP.
3. Creates a **Memorystore for Redis** instance (vector-capable) and reads back
   its `host:port`.
4. Creates a **Cloud SQL for PostgreSQL** instance, database, and user; generates
   a password and stores it in **Secret Manager**.
5. Builds the inline `DEEPINTSHIELD_CONFIG` JSON and deploys the gateway to
   **Cloud Run**, injecting the Redis address and Postgres credentials as env vars.

### Top-of-file variables

Edit the variables block at the top of `deploy.sh` (or override via environment):
`PROJECT_ID`, `REGION`, `IMAGE`, `SERVICE_NAME`, `CPU`, `MEMORY`,
`MIN_INSTANCES`/`MAX_INSTANCES`, `VPC_CONNECTOR`/`VPC_CONNECTOR_RANGE`,
`REDIS_INSTANCE`/`REDIS_SIZE_GB`/`REDIS_VERSION`, `SQL_INSTANCE`/`SQL_TIER`/
`PGDATABASE`/`PGUSER`. To reuse **existing** managed services, set
`REDIS_INSTANCE` / `SQL_INSTANCE` to their names - the existence checks skip
creation and just read their endpoints.

## How config injection works here

The container entrypoint materializes `/app/data/config.json` from
`DEEPINTSHIELD_CONFIG`. The script passes this exact JSON (endpoints/credentials
are `env.X` references resolved at runtime):

```json
{
  "$schema": "https://deepintshield.com/schema",
  "vector_store": {
    "enabled": true,
    "type": "redis",
    "config": { "addr": "env.DEEPINTSHIELD_REDIS_ADDR" }
  },
  "config_store": {
    "enabled": true,
    "type": "postgres",
    "config": {
      "host": "env.DEEPINTSHIELD_PGHOST",
      "port": "env.DEEPINTSHIELD_PGPORT",
      "user": "env.DEEPINTSHIELD_PGUSER",
      "password": "env.DEEPINTSHIELD_PGPASSWORD",
      "db_name": "env.DEEPINTSHIELD_PGDATABASE",
      "ssl_mode": "require"
    }
  },
  "logs_store": {
    "enabled": true,
    "type": "postgres",
    "config": {
      "host": "env.DEEPINTSHIELD_PGHOST",
      "port": "env.DEEPINTSHIELD_PGPORT",
      "user": "env.DEEPINTSHIELD_PGUSER",
      "password": "env.DEEPINTSHIELD_PGPASSWORD",
      "db_name": "env.DEEPINTSHIELD_PGDATABASE",
      "ssl_mode": "require"
    }
  }
}
```

The script sets `DEEPINTSHIELD_REDIS_ADDR`, `DEEPINTSHIELD_PGHOST`,
`DEEPINTSHIELD_PGPORT`, `DEEPINTSHIELD_PGUSER`, `DEEPINTSHIELD_PGPASSWORD`,
`DEEPINTSHIELD_PGDATABASE`, and `APP_PORT=8080` on the Cloud Run service. The
`vector_store` points at Memorystore; `config_store` and `logs_store` point at
Cloud SQL.

## Networking / VPC

- **Cloud Run -> Memorystore** requires a **Serverless VPC Access connector**.
  Memorystore only has a private IP inside the VPC; the connector gives Cloud Run
  a route to it. The script creates it and attaches it with
  `--vpc-egress private-ranges-only`.
- **Cloud Run -> Cloud SQL:** the script uses the instance's IP + `ssl_mode:
  require`. For tighter security, switch Cloud SQL to **Private IP** (in the same
  VPC the connector serves) and set `DEEPINTSHIELD_PGHOST` to the private IP, or
  front the DB with the Cloud SQL Auth Proxy as a sidecar pattern in GKE.

## Scaling

The gateway is stateless, so Cloud Run scales it horizontally (`MIN_INSTANCES`..
`MAX_INSTANCES`). All replicas share the same Memorystore (cache) and Cloud SQL
(config + logs), so they stay consistent. Scale the backing services
independently: bump `REDIS_SIZE_GB` / Redis tier for cache throughput and
`SQL_TIER` for DB load. Keep `MIN_INSTANCES >= 1` to avoid cold starts.

## Persistence

Durable state lives in **Cloud SQL** (config, virtual keys, governance, logs) and
**Memorystore** (semantic-cache vectors). The container's `/app/data` volume is
unused for state in this topology. Enable automated backups / PITR on Cloud SQL.

## TLS / ingress

Cloud Run terminates TLS with a Google-managed certificate on the `*.run.app`
URL automatically. For a custom domain, use **Cloud Run domain mappings** or put
an external HTTPS Load Balancer in front. To require auth at the edge, deploy with
`ALLOW_UNAUTH=false` and gate with IAM / IAP.

## Cost ballpark

Rough monthly estimate at low/steady load (us-central1, list prices change - treat
as order of magnitude):

| Component | Sizing | Approx / mo |
| --- | --- | --- |
| Cloud Run | 2 vCPU / 2 GB, 1 always-on instance | ~$45-90 |
| Memorystore Redis | 1 GB Standard HA | ~$70-100 |
| Cloud SQL Postgres | db-custom-2-7680, HA off | ~$100-140 |
| VPC connector | min instances | ~$10 |
| **Total** | | **~$225-340** |

Drop `MIN_INSTANCES` to `0` and use a smaller Redis/SQL tier for dev to cut this
substantially.

## Teardown

```bash
./teardown.sh
```

Deletes the Cloud Run service, Cloud SQL instance, Memorystore instance, VPC
connector, and the password secret.

## Alternative: GKE via Helm

For teams standardizing on Kubernetes, run the gateway on **GKE** with the
DeepintShield Helm chart instead of Cloud Run. The pattern is identical - point
the chart at **Memorystore** and **Cloud SQL**:

```yaml
# values.gke.yaml (sketch)
image:
  repository: deepintshield/ai-security
  tag: latest

env:
  DEEPINTSHIELD_REDIS_ADDR: "10.0.0.3:6379"      # Memorystore private IP:port
  DEEPINTSHIELD_PGHOST: "10.0.0.5"               # Cloud SQL private IP
  DEEPINTSHIELD_PGPORT: "5432"
  DEEPINTSHIELD_PGUSER: "deepintshield"
  DEEPINTSHIELD_PGDATABASE: "deepintshield"
  APP_PORT: "8080"
# DEEPINTSHIELD_PGPASSWORD via a Kubernetes Secret.
# DEEPINTSHIELD_CONFIG: the same JSON shown above (vector_store->redis, stores->postgres).
```

GKE nodes are in the VPC, so they reach Memorystore and Cloud SQL **private IPs**
directly - no Serverless VPC connector needed. Use a Cloud SQL Auth Proxy sidecar
or Private IP for the DB. Expose the Service via a GKE Ingress / Gateway with a
Google-managed certificate. See the shared config-injection model in the
[deployments overview](../README.md#the-shared-config-injection-model).
