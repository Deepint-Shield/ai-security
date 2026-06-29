# Profile-Guided Optimization (PGO)

Go 1.21+ supports PGO: the compiler uses a CPU profile from a representative
workload to make better inlining + devirtualization decisions. Measured wins
across the Go team's benchmarks are **2-14%** with no source changes -
biggest on regex-heavy and JSON-heavy workloads, which describes the
DeepintShield gateway exactly.

## How the build picks up a profile

`go build` automatically uses a file named **`default.pgo`** in the same
directory as the package's `main.go`, *if it exists*. No build flag needed.

When the file is absent, the compiler falls back to standard (non-PGO)
codegen - i.e. the dev experience is unaffected for contributors who
haven't collected a profile.

```
transports/deepintshield-http/
├── main.go
├── default.pgo            ← drop this file in to enable PGO
└── PGO.md                 (this file)
```

## Collecting a fresh profile

The gateway exposes pprof on `/debug/pprof/profile` (via the [pprof
package](./pprof)) when `DEEPINTSHIELD_HTTP_ENABLE_PPROF=true`. Collect a
30-second CPU profile from a node running representative traffic:

```bash
# 1. Make sure pprof is enabled on the target node (staging or prod-mirror).
export DEEPINTSHIELD_HTTP_ENABLE_PPROF=true

# 2. Capture a 30-second sample during steady-state traffic.
curl -o cpu.pprof "http://<gateway-host>:8080/debug/pprof/profile?seconds=30"

# 3. Move it into the source tree and commit.
mv cpu.pprof deepintshield_server/transports/deepintshield-http/default.pgo
git add deepintshield_server/transports/deepintshield-http/default.pgo
git commit -m "perf(gateway): refresh PGO profile (YYYY-MM-DD)"
```

## Verifying PGO is active

Add `-pgo=auto` explicitly so the build log is unambiguous:

```bash
cd deepintshield_server/transports/deepintshield-http
go build -pgo=auto -o /tmp/deepintshield-http .
go version -m /tmp/deepintshield-http | grep -i pgo
# Expected:
#   build   -pgo=auto
#   build   GOEXPERIMENT=pgo
```

## How often to refresh

The Go team recommends regenerating the profile **whenever the workload
mix shifts noticeably** - typically:

- After landing a new plugin or guard category that runs on every request
- When the policy mix changes substantially (e.g. enabling streaming
  output guards on most VKs)
- Quarterly as a default cadence

Stale profiles still help - they just leave some win on the table. They
never hurt.

## CI integration

Production builds in [.github/workflows/cd-production.yml](../../../.github/workflows/cd-production.yml)
should pick up `default.pgo` automatically. Verify by checking the build
log for `-pgo=` lines.

If you want a CI step that fails the build when the profile is older than
N days (to force periodic refresh):

```yaml
- name: Check PGO profile freshness
  run: |
    if [ -f deepintshield_server/transports/deepintshield-http/default.pgo ]; then
      age_days=$(( ($(date +%s) - $(stat -c %Y deepintshield_server/transports/deepintshield-http/default.pgo)) / 86400 ))
      if [ "$age_days" -gt 90 ]; then
        echo "::warning::PGO profile is $age_days days old - consider refreshing."
      fi
    fi
```

## Why not check in `default.pgo` until we have one

PGO files contain stack samples from a real production process. They can be
megabytes in size and they bloat git history if rotated frequently. We
treat the profile as an artifact: collect it out-of-band, drop it in, build,
ship. The first profile is the highest leverage; subsequent refreshes give
diminishing returns.
