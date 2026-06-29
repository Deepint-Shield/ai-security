"""04 - Native chat helper + raw requests."""
from deepintshield import DeepintShield

shield = DeepintShield.from_env()

# One-shot chat that returns a plain dict (no OpenAI client needed).
data = shield.chat(
    model="openai/gpt-4o-mini",
    messages=[{"role": "user", "content": "Reply with the single word: pong"}],
)
print(data["choices"][0]["message"]["content"])

# Raw call to any gateway endpoint.
models = shield.request("GET", "/v1/models")
print([m["id"] for m in models["data"][:5]])
