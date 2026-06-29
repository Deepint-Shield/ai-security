# DeepintShield examples

Minimal, runnable examples for the [`deepintshield`](https://pypi.org/project/deepintshield/)
Python SDK against a DeepintShield gateway. Every script is standalone, uses
`DeepintShield.from_env()`, and shows one concept — copy/paste friendly.

## Setup

1. **Run a gateway** (pointed at a real provider, e.g. `OPENAI_API_KEY` set):

   ```bash
   npx -y @deepintshield/ai-security        # gateway on :8080
   ```

2. **Set the two env vars** every example reads via `from_env()`:

   ```bash
   export DEEPINTSHIELD_BASE_URL=http://localhost:8080   # default is the hosted cloud
   export DEEPINTSHIELD_VIRTUAL_KEY=sk-...               # create one in the UI (Virtual Keys)
   ```

3. **Install the SDK** with the extra(s) for the example you want to run. Only the
   `deepintshield` SDK is installed — the extras are its own optional provider/framework clients:

   | Folder | Install |
   | --- | --- |
   | `sdk/` (core: OpenAI/Anthropic) | `pip install 'deepintshield[openai,anthropic]'` |
   | `openai/` (stock OpenAI SDK, drop-in) | `pip install openai httpx` |
   | `langchain/` | `pip install 'deepintshield[langchain]'` |
   | `langgraph/` | `pip install 'deepintshield[langgraph]'` |
   | `crewai/` | `pip install 'deepintshield[crewai]'` |
   | `pydanticai/` | `pip install 'deepintshield[pydanticai]'` |
   | `openai-agents/` | `pip install 'deepintshield[openai-agents]'` |
   | `llamaindex/` | `pip install 'deepintshield[llamaindex]'` |
   | `autogen/` | `pip install 'deepintshield[autogen]'` |
   | `litellm/` | `pip install 'deepintshield[litellm]'` |

   ```bash
   python sdk/01_chat_completions.py     # run any single example
   python sdk/run_all.py                 # run the whole core suite
   ```

## Core SDK (`sdk/`)

Provider-native usage through the gateway (`pip install 'deepintshield[openai,anthropic]'`):

| Script | Shows |
| --- | --- |
| `01_chat_completions.py` | `.openai()` chat completions |
| `02_streaming.py` | streaming / SSE chat |
| `03_embeddings.py` | `.openai()` embeddings |
| `04_native_chat_helper.py` | `.chat()` helper |
| `05_multi_provider.py` | `.openai()` / `.anthropic()` surfaces |
| `06_guardrails.py` | `.evaluate_guardrail()` (deterministic regex + PII) |
| `07_agentic_decide.py` | `.agentic.decide()` policy decision point |
| `08_shield_tool.py` | `@shield.agentic.tool` tool-call authorization |
| `09_mcp_tools.py` | `shield.mcp` list / call tools |
| `10_rag_grounding.py` | `build_chunk` + `shield.rag.filter` |
| `11_virtual_keys.py` | virtual-key governance headers |
| `12_error_handling.py` | typed exceptions (`GuardrailDenied`, `DeepintShieldError`) |

## Frameworks

Keep your framework code; just get the model/tooling from the SDK binder so traffic
flows through the gateway (guardrails, RAG filtering, agentic tool-gating, identity).

| Folder | Examples |
| --- | --- |
| `openai/` (stock OpenAI SDK - no DeepintShield SDK, just `base_url` + a virtual key) | `chat.py`, `rag.py`, `mcp.py`, `agentic.py` |
| `langchain/` | `chat.py`, `rag.py`, `mcp.py`, `agentic.py` |
| `langgraph/` | `chat.py`, `agentic.py` (auto-governed graph), `mcp.py` |
| `crewai/` | `chat.py`, `agentic.py` (tool gating), `mcp.py` |
| `pydanticai/` | `chat.py`, `agentic.py`, `mcp.py` |
| `openai-agents/` | `chat.py`, `agentic.py`, `mcp.py` |
| `llamaindex/` | `chat.py`, `rag.py`, `mcp.py` |
| `autogen/` | `chat.py`, `mcp.py` |
| `litellm/` | `chat.py`, `mcp.py` |

## Scope

The deterministic/free tier runs against the open-source gateway. Advanced ML/LLM
tiers (ML guardrail suite, agentic supply-chain, governed/OAuth MCP, RAG-security
re-ranking) use the **same SDK** but require DeepintShield Cloud / Enterprise.
