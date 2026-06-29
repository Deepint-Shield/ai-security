# DeepIntShield AI Gateway

[![Go Report Card](https://goreportcard.com/badge/github.com/deepint-shield/ai-security/core)](https://goreportcard.com/report/github.com/deepint-shield/ai-security/core)
[![Discord badge](https://dcbadge.limes.pink/api/server/https://discord.gg/43tHeQPyV?style=flat)](https://discord.gg/43tHeQPyV)
[![Known Vulnerabilities](https://snyk.io/test/github/deepint-shield/ai-security/badge.svg)](https://snyk.io/test/github/deepint-shield/ai-security)
[![codecov](https://codecov.io/gh/deepint-shield/ai-security/branch/main/graph/badge.svg)](https://codecov.io/gh/deepint-shield/ai-security)
![Docker Pulls](https://img.shields.io/docker/pulls/deepintshield/ai-security)
[<img src="https://run.pstmn.io/button.svg" alt="Run In Postman" style="width: 95px; height: 21px;">](https://app.getpostman.com/run-collection/31642484-2ba0e658-4dcd-49f4-845a-0c7ed745b916?action=collection%2Ffork&source=rip_markdown&collection-url=entityId%3D31642484-2ba0e658-4dcd-49f4-845a-0c7ed745b916%26entityType%3Dcollection%26workspaceId%3D63e853c8-9aec-477f-909c-7f02f543150e)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/deepintshield)](https://artifacthub.io/packages/search?repo=deepintshield)
[![License](https://img.shields.io/github/license/deepint-shield/ai-security)](LICENSE)

## The fastest way to build AI applications that never go down

DeepIntShield is a high-performance AI gateway that unifies access to 15+ providers (OpenAI, Anthropic, AWS Bedrock, Google Vertex, and more) through a single OpenAI-compatible API. Deploy in seconds with zero configuration and get automatic failover, load balancing, semantic caching, and enterprise-grade features.

## Quick Start

**Go from zero to production-ready AI gateway in under a minute.**

**Step 1:** Start DeepIntShield Gateway

```bash
make build-ui && make run
cd transports
go run ./deepintshield-http -app-dir /tmp/deepintshield-data -port 8080 -host 0.0.0.0
```

```bash
# Install and run locally
npx -y @deepintshield/ai-security

# Or use Docker
docker run -p 8080:8080 deepintshield/ai-security
```

**Step 2:** Configure via Web UI

```bash
# Open the built-in web interface
open http://localhost:8080
```

**Step 3:** Make your first API call

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "openai/gpt-4o-mini",
    "messages": [{"role": "user", "content": "Hello, DeepIntShield!"}]
  }'
```

**That's it!** Your AI gateway is running with a web interface for visual configuration, real-time monitoring, and analytics.

**Complete Setup Guides:**

- [Gateway Setup](https://deepintshield.com/quickstart/gateway/setting-up) - HTTP API deployment
- [Go SDK Setup](https://deepintshield.com/quickstart/go-sdk/setting-up) - Direct integration

## Deployment Presets

This repo now includes separate storage-backed deployment presets for local and GCP use cases:

- Step-by-step local + GCP guide: [`deployments/README.md`](./deployments/README.md)
- Local Docker Compose with PostgreSQL 18.3 + Redis 8.6.1: [`examples/dockers/postgres-redis/README.md`](./examples/dockers/postgres-redis/README.md)
- GKE with external Cloud SQL PostgreSQL + Memorystore Redis: [`helm-charts/deepintshield/values-examples/gcp-cloudsql-memorystore.yaml`](./helm-charts/deepintshield/values-examples/gcp-cloudsql-memorystore.yaml)

The container entrypoint also supports `DEEPINTSHIELD_CONFIG` and `DEEPINTSHIELD_CONFIG_FILE`, so you can inject `config.json` from a secret or a mounted file without rebuilding the image.

---

## Key Features

### Core Infrastructure

- **[Unified Interface](https://deepintshield.com/features/unified-interface)** - Single OpenAI-compatible API for all providers
- **[Multi-Provider Support](https://deepintshield.com/quickstart/gateway/provider-configuration)** - OpenAI, Anthropic, AWS Bedrock, Google Vertex, Azure, Cerebras, Cohere, Mistral, Ollama, Groq, and more
- **[Automatic Fallbacks](https://deepintshield.com/features/fallbacks)** - Seamless failover between providers and models with zero downtime
- **[Load Balancing](https://deepintshield.com/features/fallbacks)** - Intelligent request distribution across multiple API keys and providers

### Advanced Features

- **[Model Context Protocol (MCP)](https://deepintshield.com/features/mcp)** - Enable AI models to use external tools (filesystem, web search, databases)
- **[Semantic Caching](https://deepintshield.com/features/semantic-caching)** - Intelligent response caching based on semantic similarity to reduce costs and latency
- **[Multimodal Support](https://deepintshield.com/quickstart/gateway/streaming)** - Support for text,images, audio, and streaming, all behind a common interface.
- **[Custom Plugins](https://deepintshield.com/enterprise/custom-plugins)** - Extensible middleware architecture for analytics, monitoring, and custom logic
- **[Governance](https://deepintshield.com/features/governance)** - Usage tracking, rate limiting, and fine-grained access control

### Enterprise & Security

- **Multimodal Guardrails** - Extend content-safety policies to image, audio, video, embedding & rerank requests using the same engine, decision path, and `x-deepintshield-guardrail-*` headers as text - off by default with zero added latency
- **ReBAC Studio (agentic-security)** - Interactive UI for relationship-based access control (OpenFGA / ReBAC): drag-and-drop Builder (drag a subject onto a tool to grant a tuple), Tuple Workbench, Check / Access-Path Inspector, read-only Model viewer, and least-privilege analytics - grants flow through the mediated relationships endpoint and invalidate the L1 decision cache so the next `/decide` reflects them at zero added latency (Business+; activates when `OPENFGA_API_URL` is set)
- **[Budget Management](https://deepintshield.com/features/governance)** - Hierarchical cost control with virtual keys, teams, and customer budgets
- **[SSO Integration](https://deepintshield.com/features/sso-with-google-github)** - Google and GitHub authentication support
- **[Observability](https://deepintshield.com/features/observability)** - Native Prometheus metrics, distributed tracing, and comprehensive logging
- **[Vault Support](https://deepintshield.com/enterprise/vault-support)** - Secure API key management with HashiCorp Vault integration

### Developer Experience

- **[Zero-Config Startup](https://deepintshield.com/quickstart/gateway/setting-up)** - Start immediately with dynamic provider configuration
- **[Drop-in Replacement](https://deepintshield.com/features/drop-in-replacement)** - Replace OpenAI/Anthropic/GenAI APIs with one line of code
- **[SDK Integrations](https://deepintshield.com/integrations/what-is-an-integration)** - Native support for popular AI SDKs with zero code changes
- **[Configuration Flexibility](https://deepintshield.com/quickstart/gateway/provider-configuration)** - Web UI, API-driven, or file-based configuration options

---

## Repository Structure

DeepIntShield uses a modular architecture for maximum flexibility:

```text
deepintshield/
├── npx/                 # NPX script for easy installation
├── core/                # Core functionality and shared components
│   ├── providers/       # Provider-specific implementations (OpenAI, Anthropic, etc.)
│   ├── schemas/         # Interfaces and structs used throughout DeepIntShield
│   └── deepintshield.go       # Main DeepIntShield implementation
├── framework/           # Framework components for data persistence
│   ├── configstore/     # Configuration storages
│   ├── logstore/        # Request logging storages
│   └── vectorstore/     # Vector storages
├── transports/          # HTTP gateway and other interface layers
│   └── deepintshield-http/    # HTTP transport implementation
├── ui/                  # Web interface for HTTP gateway
├── plugins/             # Extensible plugin system
│   ├── governance/      # Budget management and access control
│   ├── guardrails/      # Deterministic guardrail enforcement
│   ├── jsonparser/      # JSON parsing and manipulation utilities
│   ├── litellmcompat/   # LiteLLM compatibility layer
│   ├── logging/         # Request logging and analytics
│   ├── otel/            # OpenTelemetry traces and metrics
│   ├── semanticcache/   # Intelligent response caching
│   └── telemetry/       # Monitoring and observability
└── tests/               # Comprehensive test suites
```

---

## Getting Started Options

Choose the deployment method that fits your needs:

### 1. Gateway (HTTP API)

**Best for:** Language-agnostic integration, microservices, and production deployments

```bash
# NPX - Get started in 30 seconds
npx -y @deepintshield/ai-security

# Docker - Production ready
docker run -p 8080:8080 -v $(pwd)/data:/app/data deepintshield/ai-security
```

**Features:** Web UI, real-time monitoring, multi-provider management, zero-config startup

**Learn More:** [Gateway Setup Guide](https://deepintshield.com/quickstart/gateway/setting-up)

### 2. Go SDK

**Best for:** Direct Go integration with maximum performance and control

```bash
go get github.com/deepint-shield/ai-security/core
```

**Features:** Native Go APIs, embedded deployment, custom middleware integration

**Learn More:** [Go SDK Guide](https://deepintshield.com/quickstart/go-sdk/setting-up)

### 3. Drop-in Replacement

**Best for:** Migrating existing applications with zero code changes

```diff
# OpenAI SDK
- base_url = "https://api.openai.com"
+ base_url = "http://localhost:8080/openai"

# Anthropic SDK  
- base_url = "https://api.anthropic.com"
+ base_url = "http://localhost:8080/anthropic"

# Google GenAI SDK
- api_endpoint = "https://generativelanguage.googleapis.com"
+ api_endpoint = "http://localhost:8080/genai"
```

**Learn More:** [Integration Guides](https://deepintshield.com/integrations/what-is-an-integration)

---

## Performance

DeepIntShield adds virtually zero overhead to your AI requests. In sustained 5,000 RPS benchmarks, the gateway added only **11 µs** of overhead per request.

| Metric | t3.medium | t3.xlarge | Improvement |
|--------|-----------|-----------|-------------|
| Added latency (DeepIntShield overhead) | 59 µs | **11 µs** | **-81%** |
| Success rate @ 5k RPS | 100% | 100% | No failed requests |
| Avg. queue wait time | 47 µs | **1.67 µs** | **-96%** |
| Avg. request latency (incl. provider) | 2.12 s | **1.61 s** | **-24%** |

**Key Performance Highlights:**

- **Perfect Success Rate** - 100% request success rate even at 5k RPS
- **Minimal Overhead** - Less than 15 µs additional latency per request
- **Efficient Queuing** - Sub-microsecond average wait times
- **Fast Key Selection** - ~10 ns to pick weighted API keys

**Complete Benchmarks:** [Performance Analysis](https://deepintshield.com/benchmarking/getting-started)

---

## Documentation

**Complete Documentation:** [https://deepintshield.com](https://deepintshield.com)

### Quick Start

- [Gateway Setup](https://deepintshield.com/quickstart/gateway/setting-up) - HTTP API deployment in 30 seconds
- [Go SDK Setup](https://deepintshield.com/quickstart/go-sdk/setting-up) - Direct Go integration
- [Provider Configuration](https://deepintshield.com/quickstart/gateway/provider-configuration) - Multi-provider setup

### Features

- [Multi-Provider Support](https://deepintshield.com/features/unified-interface) - Single API for all providers
- [MCP Integration](https://deepintshield.com/features/mcp) - External tool calling
- [Semantic Caching](https://deepintshield.com/features/semantic-caching) - Intelligent response caching
- [Fallbacks & Load Balancing](https://deepintshield.com/features/fallbacks) - Reliability features
- [Budget Management](https://deepintshield.com/features/governance) - Cost control and governance

### Integrations

- [OpenAI SDK](https://deepintshield.com/integrations/openai-sdk) - Drop-in OpenAI replacement
- [Anthropic SDK](https://deepintshield.com/integrations/anthropic-sdk) - Drop-in Anthropic replacement
- [AWS Bedrock SDK](https://deepintshield.com/integrations/bedrock-sdk) - AWS Bedrock integration
- [Google GenAI SDK](https://deepintshield.com/integrations/genai-sdk) - Drop-in GenAI replacement
- [LiteLLM SDK](https://deepintshield.com/integrations/litellm-sdk) - LiteLLM integration
- [Langchain SDK](https://deepintshield.com/integrations/langchain-sdk) - Langchain integration

### Enterprise

- [Custom Plugins](https://deepintshield.com/enterprise/custom-plugins) - Extend functionality
- [Clustering](https://deepintshield.com/enterprise/clustering) - Multi-node deployment
- [Vault Support](https://deepintshield.com/enterprise/vault-support) - Secure key management
- [Production Deployment](https://deepintshield.com/deployment/docker-setup) - Scaling and monitoring

---

## Need Help?

**[Join our Discord](https://discord.gg/43tHeQPyV)** for community support and discussions.

Get help with:

- Quick setup assistance and troubleshooting
- Best practices and configuration tips  
- Community discussions and support
- Real-time help with integrations

---

## Contributing

We welcome contributions of all kinds! See our [Contributing Guide](https://deepintshield.com/contributing/setting-up-repo) for:

- Setting up the development environment
- Code conventions and best practices
- How to submit pull requests
- Building and testing locally

For development requirements and build instructions, see our [Development Setup Guide](https://deepintshield.com/contributing/setting-up-repo#development-environment-setup).

---

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

Built with ❤️ by [DeepintShield](https://github.com/deepint-shield/ai-security)
