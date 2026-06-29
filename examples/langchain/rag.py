"""shield.rag.guard_embedder(...) screens text through the guardrail before embedding."""
from langchain_openai import OpenAIEmbeddings

from deepintshield import DeepintShield

shield = DeepintShield.from_env()

my_embedder = OpenAIEmbeddings(model="text-embedding-3-small")
embedder = shield.rag.guard_embedder(my_embedder)

# embed_query / embed_documents now screen each string first; a blocking verdict raises.
vector = embedder.embed_query("text")

# Filter retrieved chunks on the way out (one line) before they reach the LLM:
#   retriever = shield.rag.guard_retriever(retriever)

print(len(vector))
