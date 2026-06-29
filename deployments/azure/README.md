# DeepintShield on Azure

Deploy the open-source DeepintShield AI gateway to **Azure Container Apps**,
backed by **Azure Cache for Redis** (semantic-cache vector store) and **Azure
Database for PostgreSQL Flexible Server** (config + logs). An **AKS + Helm**
alternative is documented at the bottom.

## Architecture (at a glance)

```
                      Internet (HTTPS, managed cert on *.azurecontainerapps.io)
                                 |
                    [ Azure Container Apps ]  deepintshield  (1..N replicas)
                     image: deepintshield/ai-security  :8080  /health
                                 |
        +------------------------+--------------------------+
        |                                                   |
[ Azure Cache for Redis ]                    [ PostgreSQL Flexible Server ]
 vector store (RediSearch), TLS :6380         config_store + logs_store
 DEEPINTSHIELD_REDIS_ADDR + _PASSWORD          DEEPINTSHIELD_PG{HOST,PORT,USER,PASSWORD,DATABASE}
```

The gateway is stateless; replicas are disposable. All state is in Azure Cache +
PostgreSQL Flexible Server.

## Prerequisites

- **Azure CLI (`az`)** installed and authenticated: `az login` (and `az account
  set --subscription ...` if you have several).
- **`openssl`** available locally (generates the DB password).
- An Azure **subscription** with permission to create Container Apps, Cache for
  Redis, and PostgreSQL Flexible Server.
- The script installs/upgrades the **`containerapp`** CLI extension and registers
  the `Microsoft.App`, `Microsoft.OperationalInsights`, `Microsoft.Cache`, and
  `Microsoft.DBforPostgreSQL` resource providers.
- **Quotas / regions:** ensure the chosen `LOCATION` offers Container Apps, your
  Redis SKU, and the PostgreSQL tier/SKU.

> **Note:** Azure Cache for Redis provisioning typically takes ~15-20 minutes -
> the longest single step in the deploy.

## Deploy

```bash
cd deployments/azure

export LOCATION=eastus
export RESOURCE_GROUP=deepintshield-rg
# Optional: export SUBSCRIPTION=<sub-id>

./deploy.sh
```

The script is **idempotent** - re-running reconciles. On success it prints the
Container App HTTPS URL and a health-check command.

### What the script does

1. Registers providers + the `containerapp` extension; creates the resource group.
2. Creates an **Azure Cache for Redis** and reads its host + primary key.
3. Creates a **PostgreSQL Flexible Server** + the application database; generates
   the admin password.
4. Creates a **Container Apps environment**.
5. Stores the Redis key, DB password, and the `DEEPINTSHIELD_CONFIG` JSON as
   **Container App secrets**, then creates/updates the **Container App** with
   external ingress, referencing those secrets from env vars.

### Top-of-file variables

Edit the variables block in `deploy.sh` (or override via environment):
`SUBSCRIPTION`, `LOCATION`, `RESOURCE_GROUP`, `NAME_PREFIX`, `IMAGE`,
`APP_CPU`/`APP_MEMORY`/`MIN_REPLICAS`/`MAX_REPLICAS`,
`REDIS_NAME`/`REDIS_SKU`/`REDIS_VM_SIZE`,
`PG_SERVER`/`PG_SKU`/`PG_TIER`/`PG_VERSION`/`PG_STORAGE_GB`/`PGDATABASE`/`PGUSER`.
To reuse **existing** services, set `REDIS_NAME` / `PG_SERVER` to their names -
the existence checks skip creation and read their endpoints. (Supply `PGPASSWORD`
for an existing server.)

## How config injection works here

`DEEPINTSHIELD_CONFIG` is stored as a Container App **secret** (`dis-config`) and
referenced by the env var. Its JSON selects the managed services; every
endpoint/credential is an `env.X` reference resolved at runtime:

```json
{
  "$schema": "https://deepintshield.com/schema",
  "vector_store": {
    "enabled": true,
    "type": "redis",
    "config": {
      "addr": "env.DEEPINTSHIELD_REDIS_ADDR",
      "password": "env.DEEPINTSHIELD_REDIS_PASSWORD"
    }
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

The Container App sets `DEEPINTSHIELD_REDIS_ADDR` (`host:6380`),
`DEEPINTSHIELD_REDIS_PASSWORD` (from a secret), the five `DEEPINTSHIELD_PG*` vars
(Postgres; password from a secret), and `APP_PORT=8080`.

> **Azure Cache for Redis specifics:** it requires **AUTH** (the access key) and
> serves TLS on **port 6380** - hence the extra `DEEPINTSHIELD_REDIS_PASSWORD`
> and the `:6380` address. The key and DB password are kept in Container App
> secrets, never inline in the config JSON.

## Networking / VPC

This recipe uses the platform's **public managed endpoints** for the data stores,
secured by credentials and TLS:

- **PostgreSQL Flexible Server** is created with `--public-access 0.0.0.0`, which
  adds the "Allow Azure services" firewall rule so the Container App can reach it;
  `ssl_mode: require` enforces TLS.
- **Azure Cache for Redis** is reached on its TLS port `6380` with the access key.

For stricter isolation, deploy the Container Apps environment **into your VNet**
(`az containerapp env create --infrastructure-subnet-resource-id ...`), use
**VNet-integrated** PostgreSQL Flexible Server (`--vnet`/`--subnet`) and a Redis
**Private Endpoint**, and drop the public firewall rule. Then the data tier has no
public surface.

## Scaling

The gateway is stateless, so Container Apps scales replicas between
`MIN_REPLICAS` and `MAX_REPLICAS` (add HTTP/KEDA scale rules as needed) - all
replicas share the same Redis + PostgreSQL. Scale the data tier independently with
a larger Redis SKU/size and a larger PostgreSQL tier/SKU or read replicas.

## Persistence

Durable state lives in **PostgreSQL Flexible Server** (config, virtual keys,
governance, logs) and **Azure Cache for Redis** (semantic-cache vectors). The
container has no durable volume in this topology. Flexible Server has automated
backups by default; tune retention as needed.

## TLS / ingress

Container Apps provides **HTTPS automatically** with a managed certificate on the
`*.azurecontainerapps.io` FQDN (external ingress). For a custom domain, add a
custom domain + managed certificate to the Container App.

## Cost ballpark

Rough monthly estimate at low/steady load (eastus, prices change - order of
magnitude only):

| Component | Sizing | Approx / mo |
| --- | --- | --- |
| Container Apps | 1 vCPU / 2 GB, ~1 always-on replica | ~$40-80 |
| Azure Cache for Redis | Standard C1 (1 GB) | ~$75-100 |
| PostgreSQL Flexible Server | Burstable B2s, 32 GB | ~$60-90 |
| **Total** | | **~$175-270** |

Use Basic Redis, a smaller B-series PostgreSQL, and `MIN_REPLICAS=0` for dev to
cut this.

## Teardown

```bash
./teardown.sh
```

By default this deletes the **entire resource group** (everything the deploy
created lives inside it) asynchronously. Set `DELETE_RESOURCE_GROUP=false` to
delete the Container App, environment, PostgreSQL server, and Redis individually
and keep the group.

## Alternative: AKS via Helm

For teams on Kubernetes, run the gateway on **AKS** with the DeepintShield Helm
chart instead of Container Apps. Point the chart at **Azure Cache for Redis** and
**PostgreSQL Flexible Server**:

```yaml
# values.aks.yaml (sketch)
image:
  repository: deepintshield/ai-security
  tag: latest

env:
  DEEPINTSHIELD_REDIS_ADDR: "myredis.redis.cache.windows.net:6380"
  DEEPINTSHIELD_PGHOST: "mypg.postgres.database.azure.com"
  DEEPINTSHIELD_PGPORT: "5432"
  DEEPINTSHIELD_PGUSER: "dishadmin"
  DEEPINTSHIELD_PGDATABASE: "deepintshield"
  APP_PORT: "8080"
# DEEPINTSHIELD_REDIS_PASSWORD + DEEPINTSHIELD_PGPASSWORD via Kubernetes Secrets
# (or the Azure Key Vault Provider for Secrets Store CSI Driver).
# DEEPINTSHIELD_CONFIG: the same JSON shown above (note the Redis password field).
```

Use a **VNet-integrated** AKS cluster with Private Endpoints to Redis and
PostgreSQL so the data tier stays private. Expose the Service via an Ingress
(AGIC / NGINX) with a managed certificate for TLS. See the shared
config-injection model in the [deployments overview](../README.md#the-shared-config-injection-model).
