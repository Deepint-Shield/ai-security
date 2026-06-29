"""LlamaIndex chat: a guarded LLM via the deepintshield SDK."""
from deepintshield import DeepintShield

shield = DeepintShield.from_env()

llm = shield.llamaindex().llm("gpt-4o-mini")
resp = llm.complete("hello")

print(resp)
