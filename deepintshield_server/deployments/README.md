# Deployment Guide

This guide covers local self-hosted deployment with Docker Compose, PostgreSQL 18.3, and Redis 8.6.1.

Reference files used by this guide:

- Local compose stack: [`examples/dockers/postgres-redis/docker-compose.yml`](../examples/dockers/postgres-redis/docker-compose.yml)
- Local runtime config: [`examples/dockers/postgres-redis/config.json`](../examples/dockers/postgres-redis/config.json)

The container entrypoint also supports `DEEPINTSHIELD_CONFIG` and `DEEPINTSHIELD_CONFIG_FILE`, so you can inject `config.json` without rebuilding the image.

## Local Deployment

This path is the fastest way to run the full stack on your machine with persistent config and logs in PostgreSQL plus semantic-cache vectors in Redis 8.

### Prerequisites

- A provider API key for the example config in `.env`

### Step 1: Move into the local preset

```bash
cd deepintshield_server/examples/dockers/postgres-redis
```

### Step 2: Create your environment file

```bash
cp .env.example .env
```

Edit `.env` and set at least:

```bash
OPENAI_API_KEY=sk-your-real-key
```

### Step 3: Review the config that will be loaded

The application loads [`config.json`](../examples/dockers/postgres-redis/config.json) through `DEEPINTSHIELD_CONFIG_FILE`.

Key defaults in this preset:

- `config_store` -> PostgreSQL at `postgres:5432`
- `logs_store` -> PostgreSQL at `postgres:5432`
- `vector_store` -> Redis 8 at `redis:6379`
- `semantic_cache` -> enabled with `text-embedding-3-small`

If you want a different provider or embedding model, edit `config.json` before starting the stack.

### Step 4: Start the stack

```bash
docker compose up --build
# or, on systems with standalone Compose:
docker-compose up --build
```

This starts:

- `deepintshield` on `http://localhost:8080`
- `postgres` on `localhost:5432`
- `redis` on `localhost:6379`

### Step 5: Open the UI

Open:

```text
http://localhost:8080
```

From there you can verify provider settings, semantic cache, virtual keys, and logs.

### Step 6: Verify the backing services

Check running containers:

```bash
docker compose ps
```

Tail application logs:

```bash
docker compose logs -f deepintshield
```

If you want to inspect PostgreSQL directly:

```bash
docker compose exec postgres psql -U deepintshield -d deepintshield
```

### Step 7: Stop or reset the local stack

Stop containers:

```bash
docker compose down
```

Remove containers and volumes for a clean reset:

```bash
docker compose down -v
```

### Local Troubleshooting

- If `localhost:8080`, `5432`, or `6379` are already in use, free the port or edit `docker-compose.yml`.
- If `docker compose` says the command is unknown, use `docker-compose` instead.
- If you are upgrading from an older version of this preset, run `docker compose down -v` or `docker-compose down -v` once so PostgreSQL 18.3 can initialize a fresh volume layout.
- If PostgreSQL says `role "deepintshield" does not exist`, you are usually hitting a stale Postgres data volume or a different Postgres server already bound to `localhost:5432`.
- To reset the compose-managed database completely, run `docker compose down -v` or `docker-compose down -v`, then start the stack again so Postgres re-initializes with `POSTGRES_USER=deepintshield` and `POSTGRES_DB=deepintshield`.
- If you need to keep the existing Postgres volume, connect as the current admin user and create the missing role/database manually instead of deleting the volume.
- If DeepIntShield fails at startup, check whether `.env` contains a real provider key.
- If semantic cache fails, make sure Redis 8 is healthy and exposing `FT.*` search commands.
