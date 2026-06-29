#!/usr/bin/env bash
#
# Teardown for the AWS ECS Fargate deployment.
# Deletes the ECS service/cluster, ALB + target group, RDS, ElastiCache, subnet
# groups, security groups, IAM role, and log group. Safe to re-run.
#
# Variables must match deploy.sh (override via environment if you customized them).

set -euo pipefail

AWS_REGION="${AWS_REGION:-us-east-1}"
NAME_PREFIX="${NAME_PREFIX:-deepintshield}"

CLUSTER_NAME="${NAME_PREFIX}-cluster"
SERVICE_NAME="${NAME_PREFIX}-svc"
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
EXEC_ROLE_NAME="${NAME_PREFIX}-ecs-exec-role"

log() { echo ">> $*"; }
aws_() { aws --region "$AWS_REGION" "$@"; }

# 1. ECS service + cluster.
log "Deleting ECS service..."
aws_ ecs update-service --cluster "$CLUSTER_NAME" --service "$SERVICE_NAME" \
  --desired-count 0 >/dev/null 2>&1 || true
aws_ ecs delete-service --cluster "$CLUSTER_NAME" --service "$SERVICE_NAME" \
  --force >/dev/null 2>&1 || true
aws_ ecs delete-cluster --cluster "$CLUSTER_NAME" >/dev/null 2>&1 || true

# 2. ALB listener + target group + load balancer.
log "Deleting ALB + target group..."
ALB_ARN="$(aws_ elbv2 describe-load-balancers --names "$ALB_NAME" \
  --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || echo "None")"
if [ "$ALB_ARN" != "None" ] && [ -n "$ALB_ARN" ]; then
  for L in $(aws_ elbv2 describe-listeners --load-balancer-arn "$ALB_ARN" \
      --query 'Listeners[].ListenerArn' --output text 2>/dev/null); do
    aws_ elbv2 delete-listener --listener-arn "$L" >/dev/null 2>&1 || true
  done
  aws_ elbv2 delete-load-balancer --load-balancer-arn "$ALB_ARN" >/dev/null 2>&1 || true
fi
TG_ARN="$(aws_ elbv2 describe-target-groups --names "$TG_NAME" \
  --query 'TargetGroups[0].TargetGroupArn' --output text 2>/dev/null || echo "None")"
if [ "$TG_ARN" != "None" ] && [ -n "$TG_ARN" ]; then
  aws_ elbv2 delete-target-group --target-group-arn "$TG_ARN" >/dev/null 2>&1 || true
fi

# 3. RDS.
log "Deleting RDS instance..."
aws_ rds delete-db-instance --db-instance-identifier "$RDS_ID" \
  --skip-final-snapshot --delete-automated-backups >/dev/null 2>&1 || true
aws_ rds wait db-instance-deleted --db-instance-identifier "$RDS_ID" 2>/dev/null || true
aws_ rds delete-db-subnet-group --db-subnet-group-name "$RDS_SUBNET_GROUP" >/dev/null 2>&1 || true

# 4. ElastiCache.
log "Deleting ElastiCache cluster..."
aws_ elasticache delete-cache-cluster --cache-cluster-id "$REDIS_ID" >/dev/null 2>&1 || true
aws_ elasticache wait cache-cluster-deleted --cache-cluster-id "$REDIS_ID" 2>/dev/null || true
aws_ elasticache delete-cache-subnet-group \
  --cache-subnet-group-name "$REDIS_SUBNET_GROUP" >/dev/null 2>&1 || true

# 5. Security groups (delete data/app/lb after dependents are gone).
log "Deleting security groups..."
for SG in "$SG_DATA" "$SG_APP" "$SG_LB"; do
  ID="$(aws_ ec2 describe-security-groups --filters "Name=group-name,Values=$SG" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "None")"
  [ "$ID" != "None" ] && [ -n "$ID" ] && \
    aws_ ec2 delete-security-group --group-id "$ID" >/dev/null 2>&1 || true
done

# 6. IAM role + log group.
log "Deleting IAM role + log group..."
aws iam detach-role-policy --role-name "$EXEC_ROLE_NAME" \
  --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy 2>/dev/null || true
aws iam delete-role --role-name "$EXEC_ROLE_NAME" 2>/dev/null || true
aws_ logs delete-log-group --log-group-name "$LOG_GROUP" >/dev/null 2>&1 || true

log "Teardown complete."
