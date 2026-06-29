#!/usr/bin/env bash
#
# DeepintShield on GCP - Cloud Run + Memorystore for Redis + Cloud SQL (Postgres)
#
# Primary serverless path. Provisions (idempotently) a vector-capable Memorystore
# Redis instance, a Cloud SQL for PostgreSQL instance, a Serverless VPC Access
# connector (so Cloud Run can reach Memorystore on its private IP), then deploys
# the gateway to Cloud Run wired to both via the DEEPINTSHIELD_* env contract.
#
# Re-running is safe: every "create" is guarded by an existence check.
#
# Usage:
#   ./deploy.sh                 # provision everything + deploy
#   ./teardown.sh               # remove everything created here
#
# Requires: gcloud (authenticated), an active project with billing enabled.

set -euo pipefail

# =============================================================================
# Variables - edit these (or override via environment before running).
# =============================================================================
PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${REGION:-us-central1}"

# Container image. Push your build to Artifact Registry, or use a public tag.
IMAGE="${IMAGE:-deepintshield/ai-security:latest}"

# Cloud Run service.
SERVICE_NAME="${SERVICE_NAME:-deepintshield}"
APP_PORT="${APP_PORT:-8080}"
CPU="${CPU:-2}"
MEMORY="${MEMORY:-2Gi}"
MIN_INSTANCES="${MIN_INSTANCES:-1}"   # >=1 keeps a warm instance (faster, costs more)
MAX_INSTANCES="${MAX_INSTANCES:-10}"
ALLOW_UNAUTH="${ALLOW_UNAUTH:-true}"  # public ingress; set false to require IAM/IAP

# Networking. Cloud Run reaches Memorystore over a Serverless VPC connector.
NETWORK="${NETWORK:-default}"
VPC_CONNECTOR="${VPC_CONNECTOR:-deepintshield-conn}"
# /28 range that does NOT overlap existing subnets in the VPC.
VPC_CONNECTOR_RANGE="${VPC_CONNECTOR_RANGE:-10.8.0.0/28}"

# Memorystore for Redis (vector / search requires the standard search feature
# tier; Redis 7.2+ exposes RediSearch via the search feature).
REDIS_INSTANCE="${REDIS_INSTANCE:-deepintshield-redis}"
REDIS_TIER="${REDIS_TIER:-STANDARD_HA}"
REDIS_SIZE_GB="${REDIS_SIZE_GB:-1}"
REDIS_VERSION="${REDIS_VERSION:-REDIS_7_2}"

# Cloud SQL for PostgreSQL.
SQL_INSTANCE="${SQL_INSTANCE:-deepintshield-pg}"
SQL_TIER="${SQL_TIER:-db-custom-2-7680}"   # 2 vCPU / 7.5 GB
SQL_PG_VERSION="${SQL_PG_VERSION:-POSTGRES_16}"
PGDATABASE="${PGDATABASE:-deepintshield}"
PGUSER="${PGUSER:-deepintshield}"
# A password is generated on first run if not supplied.
PGPASSWORD="${PGPASSWORD:-}"

# Secret Manager secret that stores the generated DB password.
PG_SECRET_NAME="${PG_SECRET_NAME:-deepintshield-pg-password}"

# =============================================================================
# Derived / constants - usually no need to edit.
# =============================================================================
PGPORT="5432"

require() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' not found on PATH" >&2; exit 1; }; }
log() { echo ">> $*"; }

require gcloud
[ -n "$PROJECT_ID" ] || { echo "ERROR: PROJECT_ID is empty. Set it or run 'gcloud config set project ...'." >&2; exit 1; }

log "Project=$PROJECT_ID Region=$REGION Service=$SERVICE_NAME"
gcloud config set project "$PROJECT_ID" >/dev/null

# -----------------------------------------------------------------------------
# 1. Enable required APIs (idempotent).
# -----------------------------------------------------------------------------
log "Enabling APIs..."
gcloud services enable \
  run.googleapis.com \
  redis.googleapis.com \
  sqladmin.googleapis.com \
  vpcaccess.googleapis.com \
  servicenetworking.googleapis.com \
  secretmanager.googleapis.com \
  --quiet

# -----------------------------------------------------------------------------
# 2. Serverless VPC Access connector (lets Cloud Run reach Memorystore privately).
# -----------------------------------------------------------------------------
if gcloud compute networks vpc-access connectors describe "$VPC_CONNECTOR" \
      --region "$REGION" >/dev/null 2>&1; then
  log "VPC connector '$VPC_CONNECTOR' already exists."
else
  log "Creating VPC connector '$VPC_CONNECTOR' ($VPC_CONNECTOR_RANGE)..."
  gcloud compute networks vpc-access connectors create "$VPC_CONNECTOR" \
    --region "$REGION" \
    --network "$NETWORK" \
    --range "$VPC_CONNECTOR_RANGE"
fi

# -----------------------------------------------------------------------------
# 3. Memorystore for Redis (vector store for the semantic cache).
# -----------------------------------------------------------------------------
if gcloud redis instances describe "$REDIS_INSTANCE" --region "$REGION" >/dev/null 2>&1; then
  log "Memorystore instance '$REDIS_INSTANCE' already exists."
else
  log "Creating Memorystore Redis '$REDIS_INSTANCE' (this can take several minutes)..."
  gcloud redis instances create "$REDIS_INSTANCE" \
    --region "$REGION" \
    --tier "$REDIS_TIER" \
    --size "$REDIS_SIZE_GB" \
    --redis-version "$REDIS_VERSION" \
    --network "projects/${PROJECT_ID}/global/networks/${NETWORK}" \
    --connect-mode DIRECT_PEERING
fi

REDIS_HOST="$(gcloud redis instances describe "$REDIS_INSTANCE" --region "$REGION" \
  --format='value(host)')"
REDIS_PORT="$(gcloud redis instances describe "$REDIS_INSTANCE" --region "$REGION" \
  --format='value(port)')"
REDIS_ADDR="${REDIS_HOST}:${REDIS_PORT}"
log "Redis address: $REDIS_ADDR"

# -----------------------------------------------------------------------------
# 4. Cloud SQL for PostgreSQL.
# -----------------------------------------------------------------------------
if gcloud sql instances describe "$SQL_INSTANCE" >/dev/null 2>&1; then
  log "Cloud SQL instance '$SQL_INSTANCE' already exists."
else
  log "Creating Cloud SQL Postgres '$SQL_INSTANCE' (this can take several minutes)..."
  gcloud sql instances create "$SQL_INSTANCE" \
    --region "$REGION" \
    --database-version "$SQL_PG_VERSION" \
    --tier "$SQL_TIER" \
    --storage-auto-increase
fi

# Resolve / create the DB password and store it in Secret Manager.
if [ -z "$PGPASSWORD" ]; then
  if gcloud secrets describe "$PG_SECRET_NAME" >/dev/null 2>&1; then
    log "Reusing DB password from Secret Manager secret '$PG_SECRET_NAME'."
    PGPASSWORD="$(gcloud secrets versions access latest --secret "$PG_SECRET_NAME")"
  else
    log "Generating DB password and storing it in Secret Manager..."
    PGPASSWORD="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)"
    printf '%s' "$PGPASSWORD" | gcloud secrets create "$PG_SECRET_NAME" --data-file=-
  fi
fi

# Database (idempotent).
if gcloud sql databases describe "$PGDATABASE" --instance "$SQL_INSTANCE" >/dev/null 2>&1; then
  log "Database '$PGDATABASE' already exists."
else
  log "Creating database '$PGDATABASE'..."
  gcloud sql databases create "$PGDATABASE" --instance "$SQL_INSTANCE"
fi

# User (create or reset password so it matches our secret).
if gcloud sql users list --instance "$SQL_INSTANCE" --format='value(name)' | grep -qx "$PGUSER"; then
  log "User '$PGUSER' exists - syncing password."
  gcloud sql users set-password "$PGUSER" --instance "$SQL_INSTANCE" --password "$PGPASSWORD"
else
  log "Creating user '$PGUSER'..."
  gcloud sql users create "$PGUSER" --instance "$SQL_INSTANCE" --password "$PGPASSWORD"
fi

# Cloud Run connects to Cloud SQL via the built-in connector socket; the gateway
# speaks TCP, so we also expose the instance privately. The simplest portable
# wiring is Cloud SQL's public IP + SSL; for production prefer Private IP.
SQL_PUBLIC_IP="$(gcloud sql instances describe "$SQL_INSTANCE" \
  --format='value(ipAddresses[0].ipAddress)')"
log "Cloud SQL IP: $SQL_PUBLIC_IP"

# -----------------------------------------------------------------------------
# 5. Build the inline DEEPINTSHIELD_CONFIG (selects managed Redis + Postgres).
#    Every endpoint/credential is referenced as env.X and injected below.
# -----------------------------------------------------------------------------
read -r -d '' DEEPINTSHIELD_CONFIG <<'JSON' || true
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
JSON

# -----------------------------------------------------------------------------
# 6. Deploy / update the Cloud Run service.
# -----------------------------------------------------------------------------
log "Deploying Cloud Run service '$SERVICE_NAME'..."

AUTH_FLAG="--no-allow-unauthenticated"
[ "$ALLOW_UNAUTH" = "true" ] && AUTH_FLAG="--allow-unauthenticated"

# Env vars are passed via a temp file to avoid quoting issues with the JSON blob.
ENV_FILE="$(mktemp)"
trap 'rm -f "$ENV_FILE"' EXIT
{
  printf 'DEEPINTSHIELD_REDIS_ADDR: "%s"\n' "$REDIS_ADDR"
  printf 'DEEPINTSHIELD_PGHOST: "%s"\n' "$SQL_PUBLIC_IP"
  printf 'DEEPINTSHIELD_PGPORT: "%s"\n' "$PGPORT"
  printf 'DEEPINTSHIELD_PGUSER: "%s"\n' "$PGUSER"
  printf 'DEEPINTSHIELD_PGPASSWORD: "%s"\n' "$PGPASSWORD"
  printf 'DEEPINTSHIELD_PGDATABASE: "%s"\n' "$PGDATABASE"
  printf 'APP_PORT: "%s"\n' "$APP_PORT"
} > "$ENV_FILE"

gcloud run deploy "$SERVICE_NAME" \
  --image "$IMAGE" \
  --region "$REGION" \
  --platform managed \
  --port "$APP_PORT" \
  --cpu "$CPU" \
  --memory "$MEMORY" \
  --min-instances "$MIN_INSTANCES" \
  --max-instances "$MAX_INSTANCES" \
  --vpc-connector "$VPC_CONNECTOR" \
  --vpc-egress private-ranges-only \
  --set-env-vars "DEEPINTSHIELD_CONFIG=${DEEPINTSHIELD_CONFIG}" \
  --env-vars-file "$ENV_FILE" \
  $AUTH_FLAG

URL="$(gcloud run services describe "$SERVICE_NAME" --region "$REGION" \
  --format='value(status.url)')"
log "Done. Gateway URL: $URL"
log "Health check: curl -fsS ${URL}/health"
