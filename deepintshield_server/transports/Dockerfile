# syntax=docker/dockerfile:1.7
#
# REQUIRES BUILDKIT for the --mount=type=cache directives below.
# Run with `docker buildx build ...`, or with classic docker-compose set
# DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1.
#
# --- UI Build Stage: Build the Next.js frontend ---
FROM node:25-alpine3.23 AS ui-builder
WORKDIR /app
ENV DEEPINTSHIELD_UI_SKIP_TYPECHECK=1

# Copy UI package files and install dependencies. Cache /root/.npm so warm
# CI builds skip the network fetch - typically a 30-60 s saving.
COPY deepintshield_server/ui/package*.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm install

# Copy UI source code
COPY deepintshield_server/ui/ ./

# Build UI (skip the copy-build step). Cache the next.js webpack cache so
# unchanged routes don't need re-bundling on every CI run.
RUN --mount=type=cache,target=/app/.next/cache \
    npx next build
RUN node scripts/fix-paths.js
# Skip the copy-build step since we'll copy the files in the Go build stage

# --- Go Build Stage: Compile the Go binary ---
FROM golang:1.26.1-alpine3.23 AS builder
WORKDIR /build

# Install dependencies including gcc for CGO and sqlite
RUN apk add --no-cache gcc musl-dev sqlite-dev binutils binutils-gold git ca-certificates

# Set environment for CGO-enabled build (required for go-sqlite3)
ENV CGO_ENABLED=1 GOOS=linux

COPY deepintshield_server/core/go.mod deepintshield_server/core/go.sum ./deepintshield_server/core/
COPY deepintshield_server/framework/go.mod deepintshield_server/framework/go.sum ./deepintshield_server/framework/
COPY deepintshield_server/plugins/governance/go.mod deepintshield_server/plugins/governance/go.sum ./deepintshield_server/plugins/governance/
COPY deepintshield_server/plugins/guardrails/go.mod deepintshield_server/plugins/guardrails/go.sum ./deepintshield_server/plugins/guardrails/
COPY deepintshield_server/plugins/jsonparser/go.mod deepintshield_server/plugins/jsonparser/go.sum ./deepintshield_server/plugins/jsonparser/
COPY deepintshield_server/plugins/litellmcompat/go.mod deepintshield_server/plugins/litellmcompat/go.sum ./deepintshield_server/plugins/litellmcompat/
COPY deepintshield_server/plugins/logging/go.mod deepintshield_server/plugins/logging/go.sum ./deepintshield_server/plugins/logging/
COPY deepintshield_server/plugins/otel/go.mod deepintshield_server/plugins/otel/go.sum ./deepintshield_server/plugins/otel/
COPY deepintshield_server/plugins/semanticcache/go.mod deepintshield_server/plugins/semanticcache/go.sum ./deepintshield_server/plugins/semanticcache/
COPY deepintshield_server/plugins/telemetry/go.mod deepintshield_server/plugins/telemetry/go.sum ./deepintshield_server/plugins/telemetry/
COPY deepintshield_server/transports/go.mod deepintshield_server/transports/go.sum ./deepintshield_server/transports/
COPY deepintshield_guard/go.mod deepintshield_guard/go.sum ./deepintshield_guard/

RUN go work init && \
  go work use ./deepintshield_server/core && \
  go work use ./deepintshield_server/framework && \
  go work use ./deepintshield_server/plugins/governance && \
  go work use ./deepintshield_server/plugins/guardrails && \
  go work use ./deepintshield_server/plugins/jsonparser && \
  go work use ./deepintshield_server/plugins/litellmcompat && \
  go work use ./deepintshield_server/plugins/logging && \
  go work use ./deepintshield_server/plugins/otel && \
  go work use ./deepintshield_server/plugins/semanticcache && \
  go work use ./deepintshield_server/plugins/telemetry && \
  go work use ./deepintshield_server/transports && \
  go work use ./deepintshield_guard

# BuildKit cache mounts: persist the module cache and build cache across CI
# runs. With cold caches the build is unchanged (~5 min); with a warm cache
# this drops to ~45 s. Requires DOCKER_BUILDKIT=1 (default on docker buildx
# and Cloud Build).
RUN --mount=type=cache,target=/go/pkg/mod \
    cd /build/deepintshield_server/transports && go mod download

# Copy source code and dependencies
COPY deepintshield_server/core/ ./deepintshield_server/core/
COPY deepintshield_server/framework/ ./deepintshield_server/framework/
COPY deepintshield_server/plugins/ ./deepintshield_server/plugins/
COPY deepintshield_server/transports/ ./deepintshield_server/transports/
COPY deepintshield_guard/ ./deepintshield_guard/

RUN rm -rf ./deepintshield_server/transports/deepintshield-http/ui && mkdir -p ./deepintshield_server/transports/deepintshield-http/ui
COPY --from=ui-builder /app/out ./deepintshield_server/transports/deepintshield-http/ui

# Build the binary with CGO enabled and static SQLite linking. Cache mounts
# on the build cache are the single biggest CI speedup - incremental rebuilds
# only recompile the touched packages.
ARG VERSION=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    cd /build/deepintshield_server/transports && go build \
      -ldflags="-w -s -X main.Version=v${VERSION} -extldflags '-static'" \
      -a -trimpath \
      -tags "sqlite_static" \
      -o /app/main \
      ./deepintshield-http

# Verify build succeeded
RUN test -f /app/main || (echo "Build failed" && exit 1)

# --- Runtime Stage: gateway + bundled vector store ---
# Built on redis-stack-server so the semantic cache has a vector store
# (RediSearch / FT.* / HNSW) out of the box - `docker run` brings up both Redis
# and the gateway in one container. The gateway binary is statically linked, so
# it runs on this glibc base just as it would on alpine. Operators who want an
# external Redis just set DEEPINTSHIELD_REDIS_ADDR and the bundled one stays idle.
FROM redis/redis-stack-server:latest
WORKDIR /app
USER root

# curl for the healthcheck, ca-certificates for outbound HTTPS to providers.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*

# Create data directory and set up user
COPY --from=builder /app/main .
COPY --from=builder /build/deepintshield_server/transports/config.schema.json /app/config.schema.json
COPY --from=builder /build/deepintshield_server/transports/docker-entrypoint.sh .

# Getting arguments
ARG ARG_APP_PORT=8080
ARG ARG_APP_HOST=0.0.0.0
ARG ARG_LOG_LEVEL=info
ARG ARG_LOG_STYLE=json
ARG ARG_APP_DIR=/app/data

# Environment variables with defaults (can be overridden at runtime)
ENV APP_PORT=$ARG_APP_PORT \
  APP_HOST=$ARG_APP_HOST \
  LOG_LEVEL=$ARG_LOG_LEVEL \
  LOG_STYLE=$ARG_LOG_STYLE \
  APP_DIR=$ARG_APP_DIR

# Go runtime performance tuning (override at runtime for your workload)
# GOGC: GC target percentage. Higher = less frequent GC, more memory usage.
#       Default: 100. For high-throughput with available memory, try 200-400.
# GOMEMLIMIT: Soft memory limit for Go runtime. Set to ~90% of container memory limit.
#             Example: "1800MiB" for a 2GB container, "3600MiB" for 4GB.
#             When set, Go will be more aggressive about GC as it approaches this limit.
# Note: GOMAXPROCS is automatically detected from cgroup CPU limits via automaxprocs.
ENV GOGC="" \
  GOMEMLIMIT=""


# Runs as root so the entrypoint can launch redis-stack-server alongside the
# gateway and fix permissions on a mounted data volume.
RUN mkdir -p $APP_DIR/logs && chmod +x /app/docker-entrypoint.sh

# Declare volume for data persistence
VOLUME ["/app/data"]
EXPOSE $APP_PORT

# Health check for container status monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:${APP_PORT}/health >/dev/null || exit 1

# Use entrypoint script that handles volume permissions and argument processing
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["/app/main"]
