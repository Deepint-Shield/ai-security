"""OpenAI SDK drop-in: a minimal RAG flow through DeepintShield.

Both the embedding lookup and the grounded answer go through the gateway, so
guardrails, caching, and logging apply to the whole RAG pipeline - no gateway
specific code, just the stock OpenAI client.
"""
import math
import os

from openai import OpenAI

client = OpenAI(
    base_url=os.environ["DEEPINTSHIELD_BASE_URL"].rstrip("/") + "/v1",
    api_key=os.environ["DEEPINTSHIELD_VIRTUAL_KEY"],
)

DOCS = [
    "DeepintShield is a self-hosted AI security gateway.",
    "Virtual keys scope credentials with per-key budgets and rate limits.",
    "The guardrail runtime screens prompts and responses for PII and policy violations.",
]
QUESTION = "What does the guardrail runtime screen for?"


def embed(texts):
    out = client.embeddings.create(model="openai/text-embedding-3-small", input=texts)
    return [d.embedding for d in out.data]


def cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    return dot / (math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b)))


doc_vectors = embed(DOCS)
query_vector = embed([QUESTION])[0]
context = max(DOCS, key=lambda d: cosine(query_vector, doc_vectors[DOCS.index(d)]))

answer = client.chat.completions.create(
    model="openai/gpt-4o-mini",
    messages=[
        {"role": "system", "content": f"Answer using only this context:\n{context}"},
        {"role": "user", "content": QUESTION},
    ],
)
print("retrieved:", context)
print("answer:   ", answer.choices[0].message.content)
