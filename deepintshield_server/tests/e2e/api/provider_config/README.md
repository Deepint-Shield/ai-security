# Provider config (Postman env files)

Per-provider Postman environment `.json` files for running the DeepIntShield V1 API Newman e2e tests. Each file defines `base_url`, `provider`, `model`, and other model-type variables for that provider.

## Variables

Each `deepintshield-v1-<provider>.postman_environment.json` typically includes:

| Key | Description |
|-----|-------------|
| `base_url` | Gateway base URL (default `http://localhost:8080`) |
| `provider` | Provider name (e.g. `openai`, `anthropic`, `gemini`) |
| `model` | Chat/completions model |
| `embedding_model` | Embeddings model |
| `speech_model` | TTS model |
| `transcription_model` | Transcription model |
| `image_model` | Image generation model |
| `batch_id`, `file_id`, `container_id` | Placeholders; overwritten at runtime when tests create resources |

## Usage

From `tests/e2e/api`:

```bash
# Run for all providers (each deepintshield-v1-*.postman_environment.json in this folder, except sgl and ollama)
./run-newman-tests.sh

# Run for a single provider
./run-newman-tests.sh --env openai
./run-newman-tests.sh --env provider_config/deepintshield-v1-openai.postman_environment.json
```

Ensure the DeepIntShield server is running and the chosen provider(s) are configured (API keys, etc.). Depending on provider capabilities, tests may either succeed (2xx) or return expected unsupported-operation responses.

## Provider-specific notes

- **Cohere** – Requires a valid Cohere API key in DeepIntShield provider config. Key format and auth may differ from other providers; 401 is expected if the key is missing or invalid.
- **Vertex** – Requires `region` in the key config for embeddings and other operations. Set this in DeepIntShield provider config (project, region, credentials). Embeddings typically require a supported region such as `us-central1`.
- **Replicate** – Set `replicate_owner` (e.g. via environment or Postman env) when running Replicate tests; otherwise API calls may fail.

## Files

All DeepIntShield providers are included except **sgl** and **ollama** (excluded in `run-newman-tests.sh` when running “all providers”).

- `deepintshield-v1-openai.postman_environment.json`
- `deepintshield-v1-anthropic.postman_environment.json`
- `deepintshield-v1-azure.postman_environment.json`
- `deepintshield-v1-bedrock.postman_environment.json`
- `deepintshield-v1-cerebras.postman_environment.json`
- `deepintshield-v1-cohere.postman_environment.json`
- `deepintshield-v1-elevenlabs.postman_environment.json`
- `deepintshield-v1-gemini.postman_environment.json`
- `deepintshield-v1-groq.postman_environment.json`
- `deepintshield-v1-huggingface.postman_environment.json`
- `deepintshield-v1-mistral.postman_environment.json`
- `deepintshield-v1-nebius.postman_environment.json`
- `deepintshield-v1-openrouter.postman_environment.json`
- `deepintshield-v1-parasail.postman_environment.json`
- `deepintshield-v1-perplexity.postman_environment.json`
- `deepintshield-v1-replicate.postman_environment.json`
- `deepintshield-v1-vertex.postman_environment.json`
- `deepintshield-v1-xai.postman_environment.json`

To add a provider, copy an existing env file, rename it to `deepintshield-v1-<provider>.postman_environment.json`, and set the `provider` and model values for that provider.
