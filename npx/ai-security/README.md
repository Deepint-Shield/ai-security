# @deepintshield/ai-security

The zero-install launcher for [DeepintShield](https://github.com/deepint-shield/ai-security) -
the open-source, OpenAI-compatible AI gateway.

```bash
npx -y @deepintshield/ai-security        # gateway live on http://localhost:8080
```

This package contains no native code. On first run it downloads the prebuilt
`deepintshield-http` binary for your platform from the project's
[GitHub Releases](https://github.com/deepint-shield/ai-security/releases), caches it,
verifies its SHA-256 checksum, and executes it. Every command-line argument and
the process exit code are forwarded to the gateway.

## Usage

```bash
# Start on the default host:port (localhost:8080)
npx -y @deepintshield/ai-security

# Pass gateway flags straight through
npx -y @deepintshield/ai-security -port 9000 -host 0.0.0.0 -log-style pretty
```

Then point any OpenAI-compatible client at it:

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer <virtual-key>" -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello!"}]}'
```

## Supported platforms

| OS      | Architectures   |
| ------- | --------------- |
| macOS   | arm64, x64      |
| Linux   | arm64, x64      |
| Windows | x64             |

For any other platform, [build from source](https://github.com/deepint-shield/ai-security).

## Environment variables

| Variable                | Purpose                                                              |
| ----------------------- | ------------------------------------------------------------------- |
| `DEEPINTSHIELD_VERSION` | Override the release to download (e.g. `v0.10.2` or `latest`). Defaults to this package's version. |
| `DEEPINTSHIELD_HOST`    | Default bind host for the gateway (e.g. `0.0.0.0`).                  |
| `XDG_CACHE_HOME`        | Cache location on Linux (the binary is cached per version).          |

## License

Apache-2.0
