#!/usr/bin/env bash
# Codespaces post-create bootstrap for the DeepintShield gateway.
#
# Mirrors the `build-ui` then `build` targets in deepintshield_server/Makefile:
#   - build-ui:  cd ui && npm install && npm run build   (static export copied
#                into transports/deepintshield-http/ui)
#   - build:     cd transports/deepintshield-http &&
#                CGO_ENABLED=1 go build -tags sqlite_static -o ../../tmp/deepintshield-http .
#
# CGO is mandatory: gorm's sqlite driver (mattn/go-sqlite3) compiles C, so the
# binary cannot be built with CGO_ENABLED=0.
#
# Resilient by design: every step logs and continues, so a transient npm/go
# hiccup never blocks the codespace from opening. Re-run `make build` by hand
# if a step fails.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_DIR="${REPO_ROOT}/deepintshield_server"
export CGO_ENABLED=1

echo "==> DeepintShield codespace bootstrap"
echo "    repo:   ${REPO_ROOT}"
echo "    go:     $(go version 2>/dev/null || echo 'not found')"
echo "    node:   $(node --version 2>/dev/null || echo 'not found')"
echo "    gcc:    $(gcc --version 2>/dev/null | head -1 || echo 'not found')"

# 1. Build the Next.js dashboard. `npm run build` runs
#    `next build && fix-paths && copy-build`, exporting the static UI into
#    transports/deepintshield-http/ui where the Go binary embeds it.
echo "==> Building dashboard UI (npm install && npm run build)"
if [ -d "${SERVER_DIR}/ui" ]; then
  (
    cd "${SERVER_DIR}/ui" || exit 1
    npm install && npm run build
  ) || echo "!! UI build failed - run 'cd deepintshield_server && make build-ui' manually"
else
  echo "!! ${SERVER_DIR}/ui not found - skipping UI build"
fi

# 2. Build the CGO gateway binary into tmp/deepintshield-http.
#    Matches the Makefile native build path (CGO_ENABLED=1, sqlite_static tag).
echo "==> Building gateway binary (CGO_ENABLED=1, sqlite_static)"
if [ -d "${SERVER_DIR}/transports/deepintshield-http" ]; then
  mkdir -p "${SERVER_DIR}/tmp"
  (
    cd "${SERVER_DIR}/transports/deepintshield-http" || exit 1
    CGO_ENABLED=1 go build \
      -ldflags="-X main.Version=vdev-codespace" \
      -trimpath \
      -tags "sqlite_static" \
      -o "${SERVER_DIR}/tmp/deepintshield-http" \
      .
  ) && echo "==> Built ${SERVER_DIR}/tmp/deepintshield-http" \
    || echo "!! Gateway build failed - run 'cd deepintshield_server && make build' manually"
else
  echo "!! transports/deepintshield-http not found - skipping gateway build"
fi

echo "==> Bootstrap complete. Start the gateway with:"
echo "      cd deepintshield_server && make run"
echo "    (or run the prebuilt binary: ./deepintshield_server/tmp/deepintshield-http -host 0.0.0.0 -port 8080)"
