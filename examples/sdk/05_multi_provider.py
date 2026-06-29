"""05 - Multiple providers behind one gateway."""
from deepintshield import DeepintShield

shield = DeepintShield.from_env()

# OpenAI Chat Completions surface
openai_resp = shield.openai().chat.completions.create(
    model="openai/gpt-4o-mini",
    messages=[{"role": "user", "content": "Say hi in 3 words."}],
)
print("openai   :", openai_resp.choices[0].message.content)

# Anthropic Messages surface
anthropic_resp = shield.anthropic().messages.create(
    model="anthropic/claude-3-5-haiku-latest",
    max_tokens=64,
    messages=[{"role": "user", "content": "Say hi in 3 words."}],
)
print("anthropic:", anthropic_resp.content[0].text)
