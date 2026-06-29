# Contributing to DeepintShield

Thanks for your interest in contributing! This document covers how to build,
test, and submit changes to the open-source AI gateway.

## Ways to contribute

- Report bugs and request features via [GitHub Issues](https://github.com/deepint-shield/ai-security/issues).
- Improve documentation.
- Submit pull requests for fixes and features.

For security issues, **do not open a public issue** - follow [SECURITY.md](SECURITY.md).

## Project layout

This is a multi-module Go repository:

```
deepintshield_server/
  core/         # provider routing, schemas, the gateway engine
  framework/    # config store, log store, plugins runtime
  transports/   # deepintshield-http (the gateway binary) + UI embed
  plugins/      # guardrails, governance, semantic cache, otel, ...
  cli/          # interactive CLI
  ui/           # Next.js dashboard (embedded into the gateway binary)
deepintshield_guard/   # guardrails runtime (separate module)
npx/ai-security/       # npx wrapper published as @deepintshield/ai-security
```

## Prerequisites

- Go 1.26.1+
- Node.js 20+ (only needed to build the embedded UI)

## Building

```bash
# Build the gateway binary (UI embed required by //go:embed)
cd deepintshield_server/ui && npm ci && npm run build   # writes ../transports/deepintshield-http/ui
cd ../transports/deepintshield-http && go build .
```

Release binaries are cross-compiled and published by [`.github/workflows/release.yml`](.github/workflows/release.yml) when a maintainer pushes a version tag.

## Running tests

Tests run per module, e.g.:

```bash
cd deepintshield_server/core      && go test $(go list ./... | grep -v '/internal/mcptests')
cd deepintshield_server/framework && go test ./...
cd deepintshield_server/transports && go test ./deepintshield-http/...
cd deepintshield_guard            && go test ./...
```

The same set runs in [CI](.github/workflows/ci.yml); please make sure it passes
before opening a PR.

## Pull request guidelines

1. Fork and create a topic branch off `main`.
2. Keep changes focused; one logical change per PR.
3. Add or update tests for behavior changes.
4. Run `gofmt`/`go vet` and ensure the CI test set passes.
5. Write a clear description of what and why (see the PR template).
6. By submitting a PR you agree your contribution is licensed under Apache-2.0.

## Code of conduct

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
