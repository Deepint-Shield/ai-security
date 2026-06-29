# DeepintShield - Cloud Deployments

Production-ready, cloud-optimal deployment recipes for the open-source
**DeepintShield AI gateway**. Each cloud folder ships a single idempotent deploy
script and a detailed README that provisions managed Redis + managed PostgreSQL
and runs the gateway container wired to them.

The gateway is **stateless**. All durable state lives in the managed backing
services, not in the container - so you can scale the gateway horizontally and
treat individual instances as disposable.

## At a glance

| Cloud | Primary (serverless/container) | Managed Redis (vector) | Managed PostgreSQL | Kubernetes alternative | Folder |
| --- | --- | --- | --- | --- | --- |
| **GCP** | Cloud Run | Memorystore for Redis (search/vector tier) | Cloud SQL for PostgreSQL | GKE (Helm) | [`gcp/`](./gcp) |
| **AWS** | ECS Fargate | ElastiCache for Redis (vector-capable) | RDS for PostgreSQL | EKS (Helm) | [`aws/`](./aws) |
| **Azure** | Azure Container Apps | Azure Cache for Redis | Azure Database for PostgreSQL Flexible Server | AKS (Helm) | [`azure/`](./azure) |

Every primary path is a managed serverless/container runtime so you do not run a
control plane. Every folder also documents a Kubernetes alternative driven by the
DeepintShield Helm chart for teams that already standardize on K8s.

## The shared config-injection model

The gateway reads **one** JSON config at startup. The container entrypoint
materializes it from either of two environment variables (see
[`deepintshield_server/transports/docker-entrypoint.sh`](../deepintshield_server/transports/docker-entrypoint.sh)):

| Variable | Meaning |
| --- | --- |
| `DEEPINTSHIELD_CONFIG` | The config **JSON inline** (a string). Written to `/app/data/config.json`. |
| `DEEPINTSHIELD_CONFIG_FILE` | A **path** to a mounted config file. Copied to `/app/data/config.json`. |

Inside that JSON, any string value of the form `env.SOME_VAR` is resolved from the
process environment **at runtime**. That is the seam the deploy scripts use: the
config selects managed Redis + Postgres by referencing env vars, and the scripts
inject the actual endpoints/credentials as those env vars. You never bake a
hostname or password into the JSON.

The three backing stores the config wires up for production:

```jsonc
{
  "$schema": "https://deepintshield.com/schema",

  // Semantic-cache vector store -> managed, vector-capable Redis (RediSearch).
  "vector_store": {
    "enabled": true,
    "type": "redis",
    "config": { "addr": "env.DEEPINTSHIELD_REDIS_ADDR" }
  },

  // Control-plane config (providers, virtual keys, governance) -> managed Postgres.
  "config_store": {
    "enabled": true,
    "type": "postgres",
    "config": {
      "host":     "env.DEEPINTSHIELD_PGHOST",
      "port":     "env.DEEPINTSHIELD_PGPORT",
      "user":     "env.DEEPINTSHIELD_PGUSER",
      "password": "env.DEEPINTSHIELD_PGPASSWORD",
      "db_name":  "env.DEEPINTSHIELD_PGDATABASE",
      "ssl_mode": "require"
    }
  },

  // Request/response logs -> managed Postgres (same instance, same DB is fine).
  "logs_store": {
    "enabled": true,
    "type": "postgres",
    "config": {
      "host":     "env.DEEPINTSHIELD_PGHOST",
      "port":     "env.DEEPINTSHIELD_PGPORT",
      "user":     "env.DEEPINTSHIELD_PGUSER",
      "password": "env.DEEPINTSHIELD_PGPASSWORD",
      "db_name":  "env.DEEPINTSHIELD_PGDATABASE",
      "ssl_mode": "require"
    }
  }
}
```

The matching env vars the scripts set are:

| Env var | Used by |
| --- | --- |
| `DEEPINTSHIELD_REDIS_ADDR` | `vector_store.config.addr` (`host:port`) |
| `DEEPINTSHIELD_PGHOST` | Postgres host |
| `DEEPINTSHIELD_PGPORT` | Postgres port (usually `5432`) |
| `DEEPINTSHIELD_PGUSER` | Postgres user |
| `DEEPINTSHIELD_PGPASSWORD` | Postgres password |
| `DEEPINTSHIELD_PGDATABASE` | Postgres database name |
| `APP_PORT` | Listen port (defaults to `8080`) |

> **Why managed services, not the bundled ones?** The published image bundles a
> SQLite store and a single-node redis-stack so `docker run` works with zero
> setup. That is great for local/dev, but it is **not** for production scale:
> SQLite does not share across replicas and the bundled Redis is in-container
> (it dies with the container). For production, every recipe here points the
> gateway at managed Redis + managed Postgres so state is shared, durable, and
> backed up. When `DEEPINTSHIELD_REDIS_ADDR` is set, the bundled Redis stays idle.

## The image

All recipes run the same OSS image built from
[`deepintshield_server/transports/Dockerfile`](../deepintshield_server/transports/Dockerfile):

- Listens on **8080**, health endpoint **`/health`**, embeds the UI.
- Declares a `VOLUME` at **`/app/data`** (used only by the bundled stores; with
  managed Redis + Postgres the container holds no durable state).

Pull the published image or build/push your own:

```bash
# Build from the repo root (BuildKit required for the cache mounts).
DOCKER_BUILDKIT=1 docker build \
  -f deepintshield_server/transports/Dockerfile \
  -t deepintshield/ai-security:local .
```

Each deploy script has an `IMAGE` variable at the top - point it at whatever
registry tag you push to that cloud (Artifact Registry / ECR / ACR).

## Local / Docker

For local development and the all-in-one single-container experience (bundled
Redis + SQLite, zero managed services), use the **Run with Docker** section of the
[top-level README](../README.md#run-with-docker). These cloud recipes are the
production counterpart to that.

## OSS scope

These recipes use **only** the open-source image and **managed open services**
(Redis/Valkey-compatible cache, PostgreSQL). No enterprise-only services, vendors,
or hosted control planes are required.
