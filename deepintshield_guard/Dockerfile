# syntax=docker/dockerfile:1.7
#
# REQUIRES BUILDKIT. Run with `docker buildx build ...`, or with classic
# docker-compose set DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1. Without
# BuildKit the --mount=type=cache directives below are unrecognised and the
# build fails with "the --mount option requires BuildKit".
#
# Guard image: Go binary on the inference hot path.
#
# Two optimisations for cold-start + image size:
#   1) BuildKit cache mounts on /go/pkg/mod and /root/.cache/go-build cut
#      CI build time from ~3 min to ~30 s on warm caches. Requires
#      DOCKER_BUILDKIT=1 (the default on modern docker / Cloud Build).
#   2) Static binary + distroless static base. Final image is ~15 MB instead
#      of ~30 MB on alpine - pulls faster on autoscaler-spawned nodes, which
#      is the dominant cold-start contributor.
#
# We keep wget out of the runtime stage by using gRPC's built-in health
# probe through the kubelet (httpGet probe is plain HTTP, doesn't need a
# binary inside the container).

FROM golang:1.26.1-alpine3.23 AS builder
WORKDIR /build

RUN apk add --no-cache git ca-certificates

COPY deepintshield_guard/go.mod deepintshield_guard/go.sum ./deepintshield_guard/
RUN --mount=type=cache,target=/go/pkg/mod \
    cd /build/deepintshield_guard && go mod download

COPY deepintshield_guard/ ./deepintshield_guard/

# CGO_ENABLED=0 + -tags=netgo so the binary is statically linked and runs on
# distroless static (no libc). -trimpath strips local paths from stack
# traces; -ldflags "-w -s" drops DWARF + symbol tables for smaller size.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    cd /build/deepintshield_guard && \
    CGO_ENABLED=0 GOOS=linux \
      go build -trimpath -ldflags="-w -s" -tags="netgo" \
        -o /app/deepintshield_guard ./cmd/runtime

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app

COPY --from=builder /app/deepintshield_guard /app/deepintshield_guard

EXPOSE 8091 8092

# No HEALTHCHECK directive - distroless has no shell. Kubelet probes via
# httpGet (deepintshield-guard-deployment.yaml) are the source of truth.

USER nonroot:nonroot
ENTRYPOINT ["/app/deepintshield_guard"]
