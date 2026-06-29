"""02 - Streaming chat completions (SSE)."""
from deepintshield import DeepintShield

shield = DeepintShield.from_env()

stream = shield.openai().chat.completions.create(
    model="openai/gpt-4o-mini",
    messages=[{"role": "user", "content": "Count from 1 to 5, one number per line."}],
    stream=True,
)
for event in stream:
    print(event.choices[0].delta.content or "", end="", flush=True)
print()
