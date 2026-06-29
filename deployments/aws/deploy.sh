#!/usr/bin/env bash
#
# DeepintShield on AWS - ECS Fargate + ElastiCache (Redis) + RDS (PostgreSQL)
#
# Primary container path. Provisions (idempotently) a vector-capable ElastiCache
# Redis (Valkey) cluster, an RDS for PostgreSQL instance, security groups, an ECS
# cluster + Fargate service behind an Application Load Balancer, then runs the
# gateway wired to Redis + Postgres via the DEEPINTSHIELD_* env contract.
#
# Re-running is safe: each "create" is guarded by a describe/exists check.
#
# Usage:
#   ./deploy.sh                 # provision everything + deploy
#   ./teardown.sh               # remove everything created here
#
# Requires: aws CLI v2 (authenticated), a default VPC (or set VPC_ID/SUBNET_IDS).

set -euo pipefail

# =============================================================================
# Variables - edit these (or override via environment before running).
# =============================================================================
AWS_REGION="${AWS_REGION:-us-east-1}"
NAME_PREFIX="${NAME_PREFIX:-deepintshield}"

# Container image. Push your build to ECR, or use a public tag.
IMAGE="${IMAGE:-deepintshield/ai-security:latest}"
APP_PORT="${APP_PORT:-8080}"

# Fargate task sizing (CPU units / MiB).
TASK_CPU="${TASK_CPU:-1024}"        # 1 vCPU
TASK_MEMORY="${TASK_MEMORY:-2048}"  # 2 GB
DESIRED_COUNT="${DESIRED_COUNT:-2}" # number of gateway tasks

# Networking. Leave VPC_ID empty to use the account's default VPC.
VPC_ID="${VPC_ID:-}"
# Space-separated subnet IDs. Leave empty to auto-discover the VPC's subnets.
SUBNET_IDS="${SUBNET_IDS:-}"

# ElastiCache for Redis (Valkey/Redis is RediSearch/vector-capable on supported
# engine versions). Single primary by default; raise replicas for HA.
REDIS_NODE_TYPE="${REDIS_NODE_TYPE:-cache.t4g.small}"
REDIS_ENGINE_VERSION="${REDIS_ENGINE_VERSION:-7.1}"

# RDS for PostgreSQL.
RDS_INSTANCE_CLASS="${RDS_INSTANCE_CLASS:-db.t4g.medium}"
RDS_ENGINE_VERSION="${RDS_ENGINE_VERSION:-16}"
RDS_ALLOCATED_STORAGE="${RDS_ALLOCATED_STORAGE:-20}"
PGDATABASE="${PGDATABASE:-deepintshield}"
PGUSER="${PGUSER:-deepintshield}"
PGPASSWORD="${PGPASSWORD:-}"   # generated on first run if empty

# =============================================================================
# Derived / constants.
# =============================================================================
PGPORT="5432"
REDIS_PORT="6379"
CLUSTER_NAME="${NAME_PREFIX}-cluster"
SERVICE_NAME="${NAME_PREFIX}-svc"
TASK_FAMILY="${NAME_PREFIX}-task"
LOG_GROUP="/ecs/${NAME_PREFIX}"
REDIS_ID="${NAME_PREFIX}-redis"
REDIS_SUBNET_GROUP="${NAME_PREFIX}-redis-subnets"
RDS_ID="${NAME_PREFIX}-pg"
RDS_SUBNET_GROUP="${NAME_PREFIX}-rds-subnets"
ALB_NAME="${NAME_PREFIX}-alb"
TG_NAME="${NAME_PREFIX}-tg"
SG_LB="${NAME_PREFIX}-lb-sg"
SG_APP="${NAME_PREFIX}-app-sg"
SG_DATA="${NAME_PREFIX}-data-sg"

require() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' not found on PATH" >&2; exit 1; }; }
log() { echo ">> $*"; }
aws_() { aws --region "$AWS_REGION" "$@"; }

require aws
ACCOUNT_ID="$(aws_ sts get-caller-identity --query Account --output text)"
log "Account=$ACCOUNT_ID Region=$AWS_REGION Prefix=$NAME_PREFIX"

# -----------------------------------------------------------------------------
# 1. Resolve VPC + subnets.
# -----------------------------------------------------------------------------
if [ -z "$VPC_ID" ]; then
  VPC_ID="$(aws_ ec2 describe-vpcs --filters Name=isDefault,Values=true \
    --query 'Vpcs[0].VpcId' --output text)"
fi
[ "$VPC_ID" != "None" ] && [ -n "$VPC_ID" ] || { echo "ERROR: no VPC found; set VPC_ID." >&2; exit 1; }

if [ -z "$SUBNET_IDS" ]; then
  SUBNET_IDS="$(aws_ ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" \
    --query 'Subnets[].SubnetId' --output text)"
fi
log "VPC=$VPC_ID Subnets=$SUBNET_IDS"
# Comma-separated form for APIs that want it.
SUBNETS_CSV="$(echo "$SUBNET_IDS" | tr ' ' ',')"

# -----------------------------------------------------------------------------
# 2. Security groups: LB (public 80), app (from LB on APP_PORT), data (from app).
# -----------------------------------------------------------------------------
sg_id() { aws_ ec2 describe-security-groups \
  --filters "Name=group-name,Values=$1" "Name=vpc-id,Values=$VPC_ID" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null; }

ensure_sg() {
  local name="$1" desc="$2" id
  id="$(sg_id "$name")"
  if [ "$id" = "None" ] || [ -z "$id" ]; then
    id="$(aws_ ec2 create-security-group --group-name "$name" \
      --description "$desc" --vpc-id "$VPC_ID" --query GroupId --output text)"
    log "Created SG $name=$id"
  fi
  echo "$id"
}

LB_SG="$(ensure_sg "$SG_LB" "deepintshield ALB")"
APP_SG="$(ensure_sg "$SG_APP" "deepintshield app tasks")"
DATA_SG="$(ensure_sg "$SG_DATA" "deepintshield data stores")"

# Idempotent rule helper (ignore "already exists").
allow() { aws_ ec2 authorize-security-group-ingress "$@" 2>/dev/null || true; }

allow --group-id "$LB_SG"  --protocol tcp --port 80 --cidr 0.0.0.0/0
allow --group-id "$APP_SG" --protocol tcp --port "$APP_PORT" --source-group "$LB_SG"
allow --group-id "$DATA_SG" --protocol tcp --port "$REDIS_PORT" --source-group "$APP_SG"
allow --group-id "$DATA_SG" --protocol tcp --port "$PGPORT" --source-group "$APP_SG"

# -----------------------------------------------------------------------------
# 3. ElastiCache for Redis (vector store).
# -----------------------------------------------------------------------------
if ! aws_ elasticache describe-cache-subnet-groups \
      --cache-subnet-group-name "$REDIS_SUBNET_GROUP" >/dev/null 2>&1; then
  log "Creating ElastiCache subnet group..."
  aws_ elasticache create-cache-subnet-group \
    --cache-subnet-group-name "$REDIS_SUBNET_GROUP" \
    --cache-subnet-group-description "deepintshield redis" \
    --subnet-ids $SUBNET_IDS >/dev/null
fi

if aws_ elasticache describe-cache-clusters --cache-cluster-id "$REDIS_ID" >/dev/null 2>&1; then
  log "ElastiCache cluster '$REDIS_ID' already exists."
else
  log "Creating ElastiCache Redis '$REDIS_ID'..."
  aws_ elasticache create-cache-cluster \
    --cache-cluster-id "$REDIS_ID" \
    --engine redis \
    --engine-version "$REDIS_ENGINE_VERSION" \
    --cache-node-type "$REDIS_NODE_TYPE" \
    --num-cache-nodes 1 \
    --cache-subnet-group-name "$REDIS_SUBNET_GROUP" \
    --security-group-ids "$DATA_SG" >/dev/null
  log "Waiting for ElastiCache to become available..."
  aws_ elasticache wait cache-cluster-available --cache-cluster-id "$REDIS_ID"
fi

REDIS_HOST="$(aws_ elasticache describe-cache-clusters --cache-cluster-id "$REDIS_ID" \
  --show-cache-node-info \
  --query 'CacheClusters[0].CacheNodes[0].Endpoint.Address' --output text)"
REDIS_ADDR="${REDIS_HOST}:${REDIS_PORT}"
log "Redis address: $REDIS_ADDR"

# -----------------------------------------------------------------------------
# 4. RDS for PostgreSQL.
# -----------------------------------------------------------------------------
if [ -z "$PGPASSWORD" ]; then
  PGPASSWORD="$(openssl rand -base64 24 | tr -d '/+=@' | cut -c1-24)"
  log "Generated DB password (store it securely): $PGPASSWORD"
fi

if ! aws_ rds describe-db-subnet-groups \
      --db-subnet-group-name "$RDS_SUBNET_GROUP" >/dev/null 2>&1; then
  log "Creating RDS subnet group..."
  aws_ rds create-db-subnet-group \
    --db-subnet-group-name "$RDS_SUBNET_GROUP" \
    --db-subnet-group-description "deepintshield postgres" \
    --subnet-ids $SUBNET_IDS >/dev/null
fi

if aws_ rds describe-db-instances --db-instance-identifier "$RDS_ID" >/dev/null 2>&1; then
  log "RDS instance '$RDS_ID' already exists."
else
  log "Creating RDS Postgres '$RDS_ID' (this can take several minutes)..."
  aws_ rds create-db-instance \
    --db-instance-identifier "$RDS_ID" \
    --engine postgres \
    --engine-version "$RDS_ENGINE_VERSION" \
    --db-instance-class "$RDS_INSTANCE_CLASS" \
    --allocated-storage "$RDS_ALLOCATED_STORAGE" \
    --master-username "$PGUSER" \
    --master-user-password "$PGPASSWORD" \
    --db-name "$PGDATABASE" \
    --db-subnet-group-name "$RDS_SUBNET_GROUP" \
    --vpc-security-group-ids "$DATA_SG" \
    --no-publicly-accessible \
    --backup-retention-period 7 \
    --storage-encrypted >/dev/null
  log "Waiting for RDS to become available..."
  aws_ rds wait db-instance-available --db-instance-identifier "$RDS_ID"
fi

PGHOST="$(aws_ rds describe-db-instances --db-instance-identifier "$RDS_ID" \
  --query 'DBInstances[0].Endpoint.Address' --output text)"
log "Postgres host: $PGHOST"

# -----------------------------------------------------------------------------
# 5. Application Load Balancer + target group + listener.
# -----------------------------------------------------------------------------
ALB_ARN="$(aws_ elbv2 describe-load-balancers --names "$ALB_NAME" \
  --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || echo "None")"
if [ "$ALB_ARN" = "None" ]; then
  log "Creating ALB..."
  ALB_ARN="$(aws_ elbv2 create-load-balancer --name "$ALB_NAME" \
    --type application --scheme internet-facing \
    --subnets $SUBNET_IDS --security-groups "$LB_SG" \
    --query 'LoadBalancers[0].LoadBalancerArn' --output text)"
fi
ALB_DNS="$(aws_ elbv2 describe-load-balancers --load-balancer-arns "$ALB_ARN" \
  --query 'LoadBalancers[0].DNSName' --output text)"

TG_ARN="$(aws_ elbv2 describe-target-groups --names "$TG_NAME" \
  --query 'TargetGroups[0].TargetGroupArn' --output text 2>/dev/null || echo "None")"
if [ "$TG_ARN" = "None" ]; then
  log "Creating target group (health check /health)..."
  TG_ARN="$(aws_ elbv2 create-target-group --name "$TG_NAME" \
    --protocol HTTP --port "$APP_PORT" --vpc-id "$VPC_ID" \
    --target-type ip --health-check-path /health \
    --query 'TargetGroups[0].TargetGroupArn' --output text)"
fi

if ! aws_ elbv2 describe-listeners --load-balancer-arn "$ALB_ARN" \
      --query 'Listeners[?Port==`80`]' --output text | grep -q .; then
  log "Creating HTTP:80 listener..."
  aws_ elbv2 create-listener --load-balancer-arn "$ALB_ARN" \
    --protocol HTTP --port 80 \
    --default-actions Type=forward,TargetGroupArn="$TG_ARN" >/dev/null
fi

# -----------------------------------------------------------------------------
# 6. IAM execution role for ECS tasks + CloudWatch log group.
# -----------------------------------------------------------------------------
EXEC_ROLE_NAME="${NAME_PREFIX}-ecs-exec-role"
EXEC_ROLE_ARN="$(aws iam get-role --role-name "$EXEC_ROLE_NAME" \
  --query 'Role.Arn' --output text 2>/dev/null || echo "None")"
if [ "$EXEC_ROLE_ARN" = "None" ]; then
  log "Creating ECS task execution role..."
  TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
  EXEC_ROLE_ARN="$(aws iam create-role --role-name "$EXEC_ROLE_NAME" \
    --assume-role-policy-document "$TRUST" --query 'Role.Arn' --output text)"
  aws iam attach-role-policy --role-name "$EXEC_ROLE_NAME" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
fi

aws_ logs create-log-group --log-group-name "$LOG_GROUP" 2>/dev/null || true

# -----------------------------------------------------------------------------
# 7. ECS cluster, task definition, service.
# -----------------------------------------------------------------------------
aws_ ecs create-cluster --cluster-name "$CLUSTER_NAME" \
  --capacity-providers FARGATE >/dev/null 2>&1 || true

# Inline gateway config: vector_store->Redis, config/logs->Postgres.
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

log "Registering task definition..."
TASKDEF_FILE="$(mktemp)"
trap 'rm -f "$TASKDEF_FILE"' EXIT

# Build the container env array with jq so the JSON blob is escaped correctly.
require jq
ENV_JSON="$(jq -n \
  --arg cfg "$DEEPINTSHIELD_CONFIG" \
  --arg redis "$REDIS_ADDR" \
  --arg pghost "$PGHOST" --arg pgport "$PGPORT" \
  --arg pguser "$PGUSER" --arg pgpass "$PGPASSWORD" \
  --arg pgdb "$PGDATABASE" --arg port "$APP_PORT" \
  '[
    {name:"DEEPINTSHIELD_CONFIG",      value:$cfg},
    {name:"DEEPINTSHIELD_REDIS_ADDR",  value:$redis},
    {name:"DEEPINTSHIELD_PGHOST",      value:$pghost},
    {name:"DEEPINTSHIELD_PGPORT",      value:$pgport},
    {name:"DEEPINTSHIELD_PGUSER",      value:$pguser},
    {name:"DEEPINTSHIELD_PGPASSWORD",  value:$pgpass},
    {name:"DEEPINTSHIELD_PGDATABASE",  value:$pgdb},
    {name:"APP_PORT",                  value:$port}
  ]')"

jq -n \
  --arg family "$TASK_FAMILY" --arg cpu "$TASK_CPU" --arg mem "$TASK_MEMORY" \
  --arg exec "$EXEC_ROLE_ARN" --arg image "$IMAGE" --arg port "$APP_PORT" \
  --arg lg "$LOG_GROUP" --arg region "$AWS_REGION" --arg prefix "$NAME_PREFIX" \
  --argjson env "$ENV_JSON" \
  '{
    family: $family,
    requiresCompatibilities: ["FARGATE"],
    networkMode: "awsvpc",
    cpu: $cpu,
    memory: $mem,
    executionRoleArn: $exec,
    containerDefinitions: [{
      name: $prefix,
      image: $image,
      essential: true,
      portMappings: [{containerPort: ($port|tonumber), protocol: "tcp"}],
      environment: $env,
      logConfiguration: {
        logDriver: "awslogs",
        options: {
          "awslogs-group": $lg,
          "awslogs-region": $region,
          "awslogs-stream-prefix": "gateway"
        }
      }
    }]
  }' > "$TASKDEF_FILE"

aws_ ecs register-task-definition --cli-input-json "file://$TASKDEF_FILE" >/dev/null

NETCFG="awsvpcConfiguration={subnets=[${SUBNETS_CSV}],securityGroups=[${APP_SG}],assignPublicIp=ENABLED}"

if aws_ ecs describe-services --cluster "$CLUSTER_NAME" --services "$SERVICE_NAME" \
     --query 'services[0].status' --output text 2>/dev/null | grep -q ACTIVE; then
  log "Updating ECS service..."
  aws_ ecs update-service --cluster "$CLUSTER_NAME" --service "$SERVICE_NAME" \
    --task-definition "$TASK_FAMILY" --desired-count "$DESIRED_COUNT" \
    --force-new-deployment >/dev/null
else
  log "Creating ECS service..."
  aws_ ecs create-service \
    --cluster "$CLUSTER_NAME" --service-name "$SERVICE_NAME" \
    --task-definition "$TASK_FAMILY" --desired-count "$DESIRED_COUNT" \
    --launch-type FARGATE \
    --network-configuration "$NETCFG" \
    --load-balancers "targetGroupArn=${TG_ARN},containerName=${NAME_PREFIX},containerPort=${APP_PORT}" \
    --health-check-grace-period-seconds 60 >/dev/null
fi

log "Done. Gateway URL: http://${ALB_DNS}"
log "Health check: curl -fsS http://${ALB_DNS}/health"
