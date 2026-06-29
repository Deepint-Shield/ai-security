# Local PostgreSQL + Redis

For the full local deployment guide, see [`../../../deployments/README.md`](../../../deployments/README.md).

This preset runs DeepIntShield Server with:

- PostgreSQL 18.3 for `config_store` and `logs_store`
- Redis 8.6.1 for semantic-cache vector storage
- The deterministic guardrails runtime (`deepintshield-guard`)
- The local source tree via `transports/Dockerfile.local`

## Usage

```bash
cd deepintshield_server/examples/dockers/postgres-redis
cp .env.example .env
docker compose up --build
# or, on systems with standalone Compose:
docker-compose up --build
```

## Endpoints

- DeepIntShield Server UI/API: `http://localhost:8080`
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`

The container loads [`config.json`](./config.json) through `DEEPINTSHIELD_CONFIG_FILE`, so the app data volume can stay dedicated to runtime state.

## Troubleshooting

- If you are upgrading from an older local preset, run `docker compose down -v` or `docker-compose down -v` once so PostgreSQL 18.3 can initialize a fresh volume layout.
- If PostgreSQL says `role "deepintshield" does not exist`, the usual cause is a previously initialized Postgres volume.
- Reset the local database with `docker compose down -v` or `docker-compose down -v`, then start again with `docker compose up --build` or `docker-compose up --build`.
- If `localhost:5432` is already used by another Postgres instance on your machine, stop that server or change the host port mapping in [`docker-compose.yml`](./docker-compose.yml).
