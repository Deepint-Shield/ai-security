"""LiteLLM chat completion through DeepintShield."""
from deepintshield import DeepintShield

shield = DeepintShield.from_env()

resp = shield.litellm().completion(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "hello"}],
)
print(resp.choices[0].message.content)
