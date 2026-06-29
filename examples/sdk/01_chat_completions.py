"""01 - Chat completions (OpenAI-compatible)."""
from deepintshield import DeepintShield

shield = DeepintShield.from_env()

resp = shield.openai().chat.completions.create(
    model="openai/gpt-4o-mini",
    messages=[{"role": "user", "content": "Name three primary colors."}],
)
print(resp.choices[0].message.content)
