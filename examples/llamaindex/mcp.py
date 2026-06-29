"""LlamaIndex: let the model call a governed MCP tool through DeepintShield.

The FunctionTool body calls shield.mcp.call(...) - the gateway resolves the MCP
server, runs the tool, and applies tool governance. Needs an MCP server (e.g.
DeepWiki) registered on the gateway.
"""
from llama_index.core.tools import FunctionTool

from deepintshield import DeepintShield

shield = DeepintShield.from_env()


def ask_repo(repo_name: str, question: str) -> str:
    """Ask a free-form question about a public GitHub repository via MCP."""
    result = shield.mcp.call(
        server="DeepWiki",
        tool="ask_question",
        arguments={"repoName": repo_name, "question": question},
    )
    return str(result)


tool = FunctionTool.from_defaults(fn=ask_repo)
llm = shield.llamaindex().llm("gpt-4o-mini")  # guarded LLM via the gateway

# The model decides whether to call the MCP-backed tool, then answers from it.
print(llm.predict_and_call([tool], "What is the reconciler in facebook/react?"))
