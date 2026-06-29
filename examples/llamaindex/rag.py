"""LlamaIndex RAG: guard a retriever so unauthorised chunks are dropped post-retrieval."""
from llama_index.core import VectorStoreIndex, Document

from deepintshield import DeepintShield

shield = DeepintShield.from_env()

# Guarded embed model from the gateway.
embed_model = shield.llamaindex().embedder("text-embedding-3-small")

# Minimal LlamaIndex retriever over a couple of documents.
index = VectorStoreIndex.from_documents(
    [
        Document(text="Paris is the capital of France."),
        Document(text="The launch codes are stored in vault 7."),
    ],
    embed_model=embed_model,
)
retriever = index.as_retriever(similarity_top_k=2)

# Wrap the retriever; guarded retriever drops unauthorised chunks post-retrieval.
retriever = shield.rag.guard_retriever(retriever)

nodes = retriever.retrieve("What is the capital of France?")
for n in nodes:
    print(n.get_content())

print("kept:", len(nodes))
