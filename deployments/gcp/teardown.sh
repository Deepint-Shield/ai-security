#!/usr/bin/env bash
#
# Teardown for the GCP Cloud Run deployment.
# Deletes the Cloud Run service, Cloud SQL instance, Memorystore instance,
# the VPC connector, and the password secret. Safe to re-run.
#
# Variables must match deploy.sh (override via environment if you customized them).

set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-deepintshield}"
VPC_CONNECTOR="${VPC_CONNECTOR:-deepintshield-conn}"
REDIS_INSTANCE="${REDIS_INSTANCE:-deepintshield-redis}"
SQL_INSTANCE="${SQL_INSTANCE:-deepintshield-pg}"
PG_SECRET_NAME="${PG_SECRET_NAME:-deepintshield-pg-password}"

log() { echo ">> $*"; }
[ -n "$PROJECT_ID" ] || { echo "ERROR: PROJECT_ID is empty." >&2; exit 1; }
gcloud config set project "$PROJECT_ID" >/dev/null

log "Deleting Cloud Run service '$SERVICE_NAME'..."
gcloud run services delete "$SERVICE_NAME" --region "$REGION" --quiet || true

log "Deleting Cloud SQL instance '$SQL_INSTANCE'..."
gcloud sql instances delete "$SQL_INSTANCE" --quiet || true

log "Deleting Memorystore instance '$REDIS_INSTANCE'..."
gcloud redis instances delete "$REDIS_INSTANCE" --region "$REGION" --quiet || true

log "Deleting VPC connector '$VPC_CONNECTOR'..."
gcloud compute networks vpc-access connectors delete "$VPC_CONNECTOR" \
  --region "$REGION" --quiet || true

log "Deleting Secret Manager secret '$PG_SECRET_NAME'..."
gcloud secrets delete "$PG_SECRET_NAME" --quiet || true

log "Teardown complete."
