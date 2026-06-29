# DeepintShield on AWS

Deploy the open-source DeepintShield AI gateway to **ECS Fargate**, backed by
**ElastiCache for Redis** (semantic-cache vector store) and **RDS for PostgreSQL**
(config + logs), behind an **Application Load Balancer**. An **EKS + Helm**
alternative is documented at the bottom.

## Architecture (at a glance)

```
                      Internet (HTTP :80 -> add HTTPS, see TLS below)
                                 |
                    [ Application Load Balancer ]  health: /health
                                 |
                    [ ECS Fargate service ]  deepintshield  (N tasks, awsvpc)
                     image: deepintshield/ai-security  :8080
                                 |
        +------------------------+--------------------------+
        |                                                   |
[ ElastiCache for Redis ]                          [ RDS for PostgreSQL ]
 vector store (RediSearch)                          config_store + logs_store
 DEEPINTSHIELD_REDIS_ADDR                            DEEPINTSHIELD_PG{HOST,PORT,USER,PASSWORD,DATABASE}
```

Everything runs **inside one VPC**. The ALB is internet-facing; the gateway tasks
and the data stores are reachable only through tiered security groups (LB -> app
-> data). The gateway is stateless - tasks are disposable.

## Prerequisites

- **AWS CLI v2** installed and authenticated (`aws configure` or SSO). The deploy
  script uses `sts get-caller-identity` to confirm.
- **`jq`** and **`openssl`** available locally (the script builds the ECS task
  JSON with `jq` and generates the DB password with `openssl`).
- A **VPC with subnets** (the default VPC works out of the box; otherwise set
  `VPC_ID` and `SUBNET_IDS`). For Fargate tasks to pull the image and reach the
  internet, the subnets need a route to an Internet/NAT gateway (the script sets
  `assignPublicIp=ENABLED` so default-VPC public subnets work).
- IAM permissions for ECS, ELBv2, ElastiCache, RDS, EC2 (security groups), IAM
  (create role), and CloudWatch Logs.
- **Quotas:** ensure your account can create the chosen RDS / ElastiCache instance
  classes in `AWS_REGION`.

## Deploy

```bash
cd deployments/aws

export AWS_REGION=us-east-1
# Optional: export VPC_ID=vpc-... SUBNET_IDS="subnet-a subnet-b"

./deploy.sh
```

The script is **idempotent** - re-running reconciles. On success it prints the
ALB DNS name and a health-check command. RDS + ElastiCache creation each take a
few minutes; the script waits for them.

### What the script does

1. Resolves the VPC + subnets (default VPC if unset).
2. Creates three **security groups** (LB / app / data) and wires LB->app->data.
3. Creates an **ElastiCache Redis** cluster (vector-capable) + subnet group.
4. Creates an **RDS PostgreSQL** instance (encrypted, private) + subnet group;
   generates the DB password.
5. Creates an **ALB**, target group (health check `/health`), and HTTP listener.
6. Creates an **ECS task execution role** + CloudWatch log group.
7. Registers the **task definition** (with the inline `DEEPINTSHIELD_CONFIG`) and
   creates/updates the **Fargate service** behind the ALB.

### Top-of-file variables

Edit the variables block in `deploy.sh` (or override via environment): `AWS_REGION`,
`NAME_PREFIX`, `IMAGE`, `TASK_CPU`/`TASK_MEMORY`/`DESIRED_COUNT`, `VPC_ID`/
`SUBNET_IDS`, `REDIS_NODE_TYPE`/`REDIS_ENGINE_VERSION`, `RDS_INSTANCE_CLASS`/
`RDS_ENGINE_VERSION`/`RDS_ALLOCATED_STORAGE`, `PGDATABASE`/`PGUSER`. To reuse an
**existing** Redis or RDS, set `REDIS_ID` / `RDS_ID` to their identifiers - the
existence checks skip creation and read their endpoints. (Supply `PGPASSWORD` for
an existing RDS so the config matches.)

## How config injection works here

The ECS task definition sets `DEEPINTSHIELD_CONFIG` to this JSON (endpoints and
credentials are `env.X` references resolved at runtime by the entrypoint):

```json
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
```

Alongside it, the task sets `DEEPINTSHIELD_REDIS_ADDR` (ElastiCache endpoint),
`DEEPINTSHIELD_PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE` (RDS), and `APP_PORT=8080`.
`vector_store` -> ElastiCache; `config_store`/`logs_store` -> RDS.

> **Secrets hardening:** the script passes `DEEPINTSHIELD_PGPASSWORD` as a plain
> task env var for simplicity. For production, store it in **AWS Secrets Manager**
> (or SSM Parameter Store) and reference it via the task definition's `secrets`
> block instead of `environment`.

## Networking / VPC

ElastiCache and RDS have **no public endpoint** - they live in the VPC and only
accept traffic from the app security group (`DATA_SG` allows `6379` and `5432`
from `APP_SG`). The Fargate tasks (`APP_SG`) accept `8080` only from the ALB
(`LB_SG`). This keeps the data tier private while the gateway scales out. The ALB
is the only internet-facing component.

## Scaling

The gateway is stateless, so raise `DESIRED_COUNT` (or attach ECS Service
Auto Scaling on CPU/ALB request count) to add tasks - all tasks share the same
ElastiCache + RDS. Scale the data tier independently: a larger `REDIS_NODE_TYPE`
(or a replication group with replicas) for cache throughput, and a larger
`RDS_INSTANCE_CLASS` / read replicas for DB load.

## Persistence

Durable state lives in **RDS** (config, virtual keys, governance, logs) and
**ElastiCache** (semantic-cache vectors). The Fargate task's `/app/data` is
ephemeral and unused for state. RDS is created with 7-day automated backups and
storage encryption; tune `--backup-retention-period` as needed.

## TLS / ingress

The script provisions an **HTTP:80** listener for simplicity. For production,
request an **ACM certificate**, add an **HTTPS:443** listener forwarding to the
same target group, and (optionally) redirect 80->443. Point your DNS (Route 53)
at the ALB.

## Cost ballpark

Rough monthly estimate at low/steady load (us-east-1, prices change - order of
magnitude only):

| Component | Sizing | Approx / mo |
| --- | --- | --- |
| ECS Fargate | 2 tasks x 1 vCPU / 2 GB | ~$70-90 |
| ElastiCache Redis | cache.t4g.small, 1 node | ~$25-35 |
| RDS Postgres | db.t4g.medium, single-AZ | ~$70-100 |
| ALB | 1 ALB + LCUs | ~$20-30 |
| **Total** | | **~$185-255** |

Use a single Fargate task and smaller instance classes for dev to cut this.

## Teardown

```bash
./teardown.sh
```

Deletes the ECS service/cluster, ALB + listeners + target group, RDS (no final
snapshot), ElastiCache, subnet groups, security groups, the IAM role, and the log
group. RDS/ElastiCache deletion waits are included.

## Alternative: EKS via Helm

For teams on Kubernetes, run the gateway on **EKS** with the DeepintShield Helm
chart instead of ECS. Point the chart at **ElastiCache** and **RDS**:

```yaml
# values.eks.yaml (sketch)
image:
  repository: deepintshield/ai-security
  tag: latest

env:
  DEEPINTSHIELD_REDIS_ADDR: "my-redis.xxxx.use1.cache.amazonaws.com:6379"
  DEEPINTSHIELD_PGHOST: "my-pg.xxxx.us-east-1.rds.amazonaws.com"
  DEEPINTSHIELD_PGPORT: "5432"
  DEEPINTSHIELD_PGUSER: "deepintshield"
  DEEPINTSHIELD_PGDATABASE: "deepintshield"
  APP_PORT: "8080"
# DEEPINTSHIELD_PGPASSWORD via a Kubernetes Secret (or Secrets Manager + CSI).
# DEEPINTSHIELD_CONFIG: the same JSON shown above.
```

Put the EKS nodes in the **same VPC** as ElastiCache + RDS (and open their
security groups to the node/pod security group). Expose the Service with an AWS
Load Balancer Controller `Ingress` (ALB) and an ACM cert for TLS. See the shared
config-injection model in the [deployments overview](../README.md#the-shared-config-injection-model).
