# DeepIntShield Gateway

DeepIntShield Gateway is a blazing-fast HTTP API that unifies access to 15+ AI providers (OpenAI, Anthropic, AWS Bedrock, Google Vertex, and more) through a single OpenAI-compatible interface. Deploy in seconds with zero configuration and get automatic fallbacks, semantic caching, tool calling, and enterprise-grade features.

**Complete Documentation**: [https://deepintshield.com](https://deepintshield.com)

---

## Quick Start

### Installation

Choose your preferred method:

#### NPX (Recommended)

```bash
# Install and run locally
npx -y @deepintshield/ai-security

# Open web interface at http://localhost:8080
```

#### Docker

```bash
# Pull and run DeepIntShield Gateway
docker pull deepintshield/ai-security
docker run -p 8080:8080 deepintshield/ai-security

# For persistent configuration
docker run -p 8080:8080 -v $(pwd)/data:/app/data deepintshield/ai-security
```

### Configuration

DeepIntShield starts with zero configuration needed. Configure providers through the **built-in web UI** at `http://localhost:8080` or via API:

```bash
# Add OpenAI provider via API
curl -X POST http://localhost:8080/api/providers \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "openai",
    "keys": [{"value": "sk-your-openai-key", "models": ["gpt-4o-mini"], "weight": 1.0}]
  }'
```

For file-based configuration, create `config.json` in your app directory:

```json
{
  "providers": {
    "openai": {
      "keys": [{"value": "env.OPENAI_API_KEY", "models": ["gpt-4o-mini"], "weight": 1.0}]
    }
  }
}
```

### Your First API Call

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "openai/gpt-4o-mini",
    "messages": [{"role": "user", "content": "Hello, DeepIntShield!"}]
  }'
```

**That's it!** You now have a unified AI gateway running locally.

---

## Key Features

DeepIntShield Gateway provides enterprise-grade AI infrastructure with these core capabilities:

### Core Features

- **[Unified Interface](https://deepintshield.com/features/unified-interface)** - Single OpenAI-compatible API for all providers
- **[Multi-Provider Support](https://deepintshield.com/quickstart/gateway/provider-configuration)** - OpenAI, Anthropic, AWS Bedrock, Google Vertex, Cerebras, Azure, Cohere, Mistral, Ollama, Groq, and more
- **[Drop-in Replacement](https://deepintshield.com/features/drop-in-replacement)** - Replace OpenAI/Anthropic/GenAI SDKs with zero code changes
- **[Automatic Fallbacks](https://deepintshield.com/features/fallbacks)** - Seamless failover between providers and models
- **[Streaming Support](https://deepintshield.com/quickstart/gateway/streaming)** - Real-time response streaming for all providers

### Advanced Features

- **[Model Context Protocol (MCP)](https://deepintshield.com/features/mcp)** - Enable AI models to use external tools (filesystem, web search, databases)
- **[Semantic Caching](https://deepintshield.com/features/semantic-caching)** - Intelligent response caching based on semantic similarity
- **[Load Balancing](https://deepintshield.com/features/fallbacks)** - Distribute requests across multiple API keys and providers
- **[Governance & Budget Management](https://deepintshield.com/features/governance)** - Usage tracking, rate limiting, and cost control
- **[Custom Plugins](https://deepintshield.com/enterprise/custom-plugins)** - Extensible middleware for analytics, monitoring, and custom logic

### Enterprise Features

- **[Clustering](https://deepintshield.com/enterprise/clustering)** - Multi-node deployment with shared state
- **[SSO Integration](https://deepintshield.com/features/sso-with-google-github)** - Google, GitHub authentication
- **[Vault Support](https://deepintshield.com/enterprise/vault-support)** - Secure API key management
- **[Custom Analytics](https://deepintshield.com/features/observability)** - Detailed usage insights and monitoring
- **[In-VPC Deployments](https://deepintshield.com/enterprise/invpc-deployments)** - Private cloud deployment options

**Learn More**: [Complete Feature Documentation](https://deepintshield.com/features/unified-interface)

---

## SDK Integrations

Replace your existing SDK base URLs to unlock DeepIntShield's features instantly:

### OpenAI SDK

```python
import openai
client = openai.OpenAI(
    base_url="http://localhost:8080/openai",
    api_key="dummy"  # Handled by DeepIntShield
)
```

### Anthropic SDK

```python
import anthropic
client = anthropic.Anthropic(
    base_url="http://localhost:8080/anthropic",
    api_key="dummy"  # Handled by DeepIntShield
)
```

### Google GenAI SDK

```python
import google.generativeai as genai
genai.configure(
    transport="rest",
    api_endpoint="http://localhost:8080/genai",
    api_key="dummy"  # Handled by DeepIntShield
)
```

**Complete Integration Guides**: [SDK Integrations](https://deepintshield.com/integrations/what-is-an-integration)

---

## Documentation

### Getting Started

- [Quick Setup Guide](https://deepintshield.com/quickstart/gateway/setting-up) - Detailed installation and configuration
- [Provider Configuration](https://deepintshield.com/quickstart/gateway/provider-configuration) - Connect multiple AI providers
- [Integration Guide](https://deepintshield.com/quickstart/gateway/integrations) - SDK replacements

### Advanced Topics

- [MCP Tool Calling](https://deepintshield.com/features/mcp) - External tool integration
- [Semantic Caching](https://deepintshield.com/features/semantic-caching) - Intelligent response caching
- [Fallbacks & Load Balancing](https://deepintshield.com/features/fallbacks) - Reliability and scaling
- [Budget Management](https://deepintshield.com/features/governance) - Cost control and governance

**Browse All Documentation**: [https://deepintshield.com](https://deepintshield.com)

---

*Built with ❤️ by [DeepintShield](https://github.com/deepint-shield/ai-security)*
