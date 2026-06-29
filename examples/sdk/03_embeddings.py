"""03 - Embeddings (OpenAI-compatible)."""
from deepintshield import DeepintShield

shield = DeepintShield.from_env()

resp = shield.openai().embeddings.create(
    model="openai/text-embedding-3-small",
    input=["the quick brown fox", "lazy dogs sleep"],
)
for i, item in enumerate(resp.data):
    print(f"vector[{i}]: dim={len(item.embedding)} first3={item.embedding[:3]}")
