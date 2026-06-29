#!/usr/bin/env bash
#
# DeepintShield on Azure - Container Apps + Azure Cache for Redis +
#                          Azure Database for PostgreSQL Flexible Server
#
# Primary container path. Provisions (idempotently) an Azure Cache for Redis,
# a PostgreSQL Flexible Server, a Container Apps environment, then deploys the
# gateway as a Container App wired to Redis + Postgres via the DEEPINTSHIELD_*
# env contract.
#
# Re-running is safe: each "create" is guarded by a show/exists check.
#
# Usage:
#   ./deploy.sh                 # provision everything + deploy
#   ./teardown.sh               # remove everything (deletes the resource group)
#
# Requires: az CLI (authenticated), the containerapp + rdbms-connect extensions
#           (the script installs/registers what it needs).

set -euo pipefail

# =============================================================================
# Variables - edit these (or override via environment before running).
# =============================================================================
SUBSCRIPTION="${SUBSCRIPTION:-}"           # empty = current `az account` default
LOCATION="${LOCATION:-eastus}"
RESOURCE_GROUP="${RESOURCE_GROUP:-deepintshield-rg}"
NAME_PREFIX="${NAME_PREFIX:-deepintshield}"

# Container image. Push your build to ACR, or use a public tag.
IMAGE="${IMAGE:-deepintshield/ai-security:latest}"
APP_PORT="${APP_PORT:-8080}"

# Container App sizing / scale.
APP_CPU="${APP_CPU:-1.0}"          # cores
APP_MEMORY="${APP_MEMORY:-2.0Gi}"
MIN_REPLICAS="${MIN_REPLICAS:-1}"
MAX_REPLICAS="${MAX_REPLICAS:-10}"

# Azure Cache for Redis (Basic/Standard support RediSearch via the search module
# on the appropriate SKU; use Standard+ for production HA).
REDIS_NAME="${REDIS_NAME:-${NAME_PREFIX}-redis}"
REDIS_SKU="${REDIS_SKU:-Standard}"
REDIS_VM_SIZE="${REDIS_VM_SIZE:-c1}"   # Standard C1 = 1 GB

# Azure Database for PostgreSQL Flexible Server.
PG_SERVER="${PG_SERVER:-${NAME_PREFIX}-pg}"
PG_SKU="${PG_SKU:-Standard_B2s}"
PG_TIER="${PG_TIER:-Burstable}"
PG_VERSION="${PG_VERSION:-16}"
PG_STORAGE_GB="${PG_STORAGE_GB:-32}"
PGDATABASE="${PGDATABASE:-deepintshield}"
PGUSER="${PGUSER:-dishadmin}"
PGPASSWORD="${PGPASSWORD:-}"   # generated on first run if empty

# Container Apps environment.
CAE_NAME="${CAE_NAME:-${NAME_PREFIX}-env}"
APP_NAME="${APP_NAME:-${NAME_PREFIX}}"

# =============================================================================
# Derived / constants.
# =============================================================================
PGPORT="5432"
REDIS_PORT="6380"   # Azure Cache for Redis uses TLS port 6380

require() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' not found on PATH" >&2; exit 1; }; }
log() { echo ">> $*"; }

require az
[ -n "$SUBSCRIPTION" ] && az account set --subscription "$SUBSCRIPTION"
log "Location=$LOCATION RG=$RESOURCE_GROUP App=$APP_NAME"

# -----------------------------------------------------------------------------
# 0. Provider registration + CLI extension.
# -----------------------------------------------------------------------------
log "Ensuring providers + containerapp extension..."
az extension add --name containerapp --upgrade --only-show-errors >/dev/null 2>&1 || true
az provider register --namespace Microsoft.App --wait >/dev/null 2>&1 || true
az provider register --namespace Microsoft.OperationalInsights --wait >/dev/null 2>&1 || true
az provider register --namespace Microsoft.Cache --wait >/dev/null 2>&1 || true
az provider register --namespace Microsoft.DBforPostgreSQL --wait >/dev/null 2>&1 || true

# -----------------------------------------------------------------------------
# 1. Resource group.
# -----------------------------------------------------------------------------
if az group show --name "$RESOURCE_GROUP" >/dev/null 2>&1; then
  log "Resource group '$RESOURCE_GROUP' already exists."
else
  log "Creating resource group..."
  az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --only-show-errors >/dev/null
fi

# -----------------------------------------------------------------------------
# 2. Azure Cache for Redis (vector store).
# -----------------------------------------------------------------------------
if az redis show --name "$REDIS_NAME" --resource-group "$RESOURCE_GROUP" >/dev/null 2>&1; then
  log "Azure Cache for Redis '$REDIS_NAME' already exists."
else
  log "Creating Azure Cache for Redis '$REDIS_NAME' (this can take ~15-20 min)..."
  az redis create \
    --name "$REDIS_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --sku "$REDIS_SKU" \
    --vm-size "$REDIS_VM_SIZE" \
    --redis-configuration '{"aof-backup-enabled":"false"}' \
    --only-show-errors >/dev/null
fi

REDIS_HOST="$(az redis show --name "$REDIS_NAME" --resource-group "$RESOURCE_GROUP" \
  --query hostName --output tsv)"
REDIS_KEY="$(az redis list-keys --name "$REDIS_NAME" --resource-group "$RESOURCE_GROUP" \
  --query primaryKey --output tsv)"
REDIS_ADDR="${REDIS_HOST}:${REDIS_PORT}"
log "Redis address: $REDIS_ADDR"

# -----------------------------------------------------------------------------
# 3. PostgreSQL Flexible Server.
# -----------------------------------------------------------------------------
if [ -z "$PGPASSWORD" ]; then
  PGPASSWORD="$(openssl rand -base64 24 | tr -d '/+=@' | cut -c1-24)"
  log "Generated DB password (store it securely): $PGPASSWORD"
fi

if az postgres flexible-server show --name "$PG_SERVER" \
     --resource-group "$RESOURCE_GROUP" >/dev/null 2>&1; then
  log "PostgreSQL server '$PG_SERVER' already exists."
else
  log "Creating PostgreSQL Flexible Server '$PG_SERVER' (this can take several minutes)..."
  # Public access with firewall rule for Azure services; switch to --vnet for
  # private networking in production (see README).
  az postgres flexible-server create \
    --name "$PG_SERVER" \
    --resource-group "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --tier "$PG_TIER" \
    --sku-name "$PG_SKU" \
    --version "$PG_VERSION" \
    --storage-size "$PG_STORAGE_GB" \
    --admin-user "$PGUSER" \
    --admin-password "$PGPASSWORD" \
    --public-access 0.0.0.0 \
    --yes \
    --only-show-errors >/dev/null
fi

# Ensure the application database exists.
if ! az postgres flexible-server db show --database-name "$PGDATABASE" \
      --server-name "$PG_SERVER" --resource-group "$RESOURCE_GROUP" >/dev/null 2>&1; then
  log "Creating database '$PGDATABASE'..."
  az postgres flexible-server db create \
    --database-name "$PGDATABASE" \
    --server-name "$PG_SERVER" \
    --resource-group "$RESOURCE_GROUP" \
    --only-show-errors >/dev/null
fi

PGHOST="$(az postgres flexible-server show --name "$PG_SERVER" \
  --resource-group "$RESOURCE_GROUP" --query fullyQualifiedDomainName --output tsv)"
log "Postgres host: $PGHOST"

# -----------------------------------------------------------------------------
# 4. Container Apps environment.
# -----------------------------------------------------------------------------
if az containerapp env show --name "$CAE_NAME" \
     --resource-group "$RESOURCE_GROUP" >/dev/null 2>&1; then
  log "Container Apps environment '$CAE_NAME' already exists."
else
  log "Creating Container Apps environment..."
  az containerapp env create \
    --name "$CAE_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --only-show-errors >/dev/null
fi

# -----------------------------------------------------------------------------
# 5. Build inline DEEPINTSHIELD_CONFIG (vector_store->Redis, stores->Postgres).
# -----------------------------------------------------------------------------
read -r -d '' DEEPINTSHIELD_CONFIG <<'JSON' || true
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
JSON

# -----------------------------------------------------------------------------
# 6. Deploy / update the Container App.
#    Sensitive values go through Container App secrets; env vars reference them.
# -----------------------------------------------------------------------------
log "Deploying Container App '$APP_NAME'..."

# Secrets (idempotent: set-secret-on-create or update afterwards).
SECRETS=(
  "redis-password=${REDIS_KEY}"
  "pg-password=${PGPASSWORD}"
  "dis-config=${DEEPINTSHIELD_CONFIG}"
)

ENV_VARS=(
  "DEEPINTSHIELD_CONFIG=secretref:dis-config"
  "DEEPINTSHIELD_REDIS_ADDR=${REDIS_ADDR}"
  "DEEPINTSHIELD_REDIS_PASSWORD=secretref:redis-password"
  "DEEPINTSHIELD_PGHOST=${PGHOST}"
  "DEEPINTSHIELD_PGPORT=${PGPORT}"
  "DEEPINTSHIELD_PGUSER=${PGUSER}"
  "DEEPINTSHIELD_PGPASSWORD=secretref:pg-password"
  "DEEPINTSHIELD_PGDATABASE=${PGDATABASE}"
  "APP_PORT=${APP_PORT}"
)

if az containerapp show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" >/dev/null 2>&1; then
  log "Updating existing Container App..."
  az containerapp secret set --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" \
    --secrets "${SECRETS[@]}" --only-show-errors >/dev/null
  az containerapp update --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" \
    --image "$IMAGE" \
    --cpu "$APP_CPU" --memory "$APP_MEMORY" \
    --min-replicas "$MIN_REPLICAS" --max-replicas "$MAX_REPLICAS" \
    --set-env-vars "${ENV_VARS[@]}" \
    --only-show-errors >/dev/null
else
  log "Creating Container App..."
  az containerapp create \
    --name "$APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --environment "$CAE_NAME" \
    --image "$IMAGE" \
    --target-port "$APP_PORT" \
    --ingress external \
    --cpu "$APP_CPU" --memory "$APP_MEMORY" \
    --min-replicas "$MIN_REPLICAS" --max-replicas "$MAX_REPLICAS" \
    --secrets "${SECRETS[@]}" \
    --env-vars "${ENV_VARS[@]}" \
    --only-show-errors >/dev/null
fi

FQDN="$(az containerapp show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" \
  --query properties.configuration.ingress.fqdn --output tsv)"
log "Done. Gateway URL: https://${FQDN}"
log "Health check: curl -fsS https://${FQDN}/health"
