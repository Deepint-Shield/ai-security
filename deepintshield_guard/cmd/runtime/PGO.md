# Profile-Guided Optimization (PGO) - guard runtime

Same mechanic as the gateway (see `deepintshield_server/transports/deepintshield-http/PGO.md`),
but for the standalone guard runtime binary. When you run the guard
out-of-process (i.e. **not** in embedded mode), this is where the regex
scan + provider adapter dispatch happens.

## Drop the profile here

```
deepintshield_guard/cmd/runtime/
├── main.go
└── default.pgo            ← drop file in to enable PGO
```

`go build` auto-detects `default.pgo` next to `main.go` and applies it.

## Collecting a profile

The guard exposes pprof on `/debug/pprof/profile` when the runtime is
started with `--enable-pprof` (or `DEEPINTSHIELD_GUARD_ENABLE_PPROF=true`).

```bash
# 30-second CPU profile under steady-state traffic.
curl -o cpu.pprof "http://<guard-host>:9443/debug/pprof/profile?seconds=30"
mv cpu.pprof deepintshield_guard/cmd/runtime/default.pgo
git add deepintshield_guard/cmd/runtime/default.pgo
git commit -m "perf(guard): refresh PGO profile (YYYY-MM-DD)"
```

## Why this matters more for the guard than the gateway

The guard runtime spends ~60% of its CPU in regex evaluation (after T2.1's
swap to grafana/regexp). PGO devirtualizes the `regexp.Regexp.Match` call
sites and inlines the hot DFA inner loop - measured wins in the Go team's
own benchmarks on regex-heavy workloads land in the **8-14%** range,
toward the upper end of the PGO improvement distribution.
