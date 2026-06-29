#!/usr/bin/env bash
#
# Teardown for the Azure Container Apps deployment.
# Simplest path: delete the whole resource group (everything created by deploy.sh
# lives inside it). Set DELETE_RESOURCE_GROUP=false to delete resources
# individually instead and keep the group.
#
# Variables must match deploy.sh (override via environment if you customized them).

set -euo pipefail

SUBSCRIPTION="${SUBSCRIPTION:-}"
RESOURCE_GROUP="${RESOURCE_GROUP:-deepintshield-rg}"
NAME_PREFIX="${NAME_PREFIX:-deepintshield}"
APP_NAME="${APP_NAME:-${NAME_PREFIX}}"
CAE_NAME="${CAE_NAME:-${NAME_PREFIX}-env}"
REDIS_NAME="${REDIS_NAME:-${NAME_PREFIX}-redis}"
PG_SERVER="${PG_SERVER:-${NAME_PREFIX}-pg}"
DELETE_RESOURCE_GROUP="${DELETE_RESOURCE_GROUP:-true}"

log() { echo ">> $*"; }
[ -n "$SUBSCRIPTION" ] && az account set --subscription "$SUBSCRIPTION"

if [ "$DELETE_RESOURCE_GROUP" = "true" ]; then
  log "Deleting resource group '$RESOURCE_GROUP' (all resources within it)..."
  az group delete --name "$RESOURCE_GROUP" --yes --no-wait
  log "Deletion started (running asynchronously)."
  exit 0
fi

log "Deleting Container App '$APP_NAME'..."
az containerapp delete --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" \
  --yes --only-show-errors >/dev/null 2>&1 || true

log "Deleting Container Apps environment '$CAE_NAME'..."
az containerapp env delete --name "$CAE_NAME" --resource-group "$RESOURCE_GROUP" \
  --yes --only-show-errors >/dev/null 2>&1 || true

log "Deleting PostgreSQL server '$PG_SERVER'..."
az postgres flexible-server delete --name "$PG_SERVER" \
  --resource-group "$RESOURCE_GROUP" --yes --only-show-errors >/dev/null 2>&1 || true

log "Deleting Azure Cache for Redis '$REDIS_NAME'..."
az redis delete --name "$REDIS_NAME" --resource-group "$RESOURCE_GROUP" \
  --yes --only-show-errors >/dev/null 2>&1 || true

log "Teardown complete."
