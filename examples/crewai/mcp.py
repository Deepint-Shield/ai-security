"""CrewAI: call a governed MCP tool through DeepintShield.

Wrap shield.mcp.call(...) in a CrewAI @tool - the gateway resolves the MCP server,
runs the tool, and applies tool governance. Needs an MCP server (e.g. DeepWiki)
registered on the gateway.
"""
from crewai.tools import tool

from deepintshield import DeepintShield

shield = DeepintShield.from_env()


@tool("ask_repo")
def ask_repo(repo_name: str, question: str) -> str:
    """Ask a free-form question about a public GitHub repository via MCP."""
    result = shield.mcp.call(
        server="DeepWiki",
        tool="ask_question",
        arguments={"repoName": repo_name, "question": question},
    )
    return str(result)


print(ask_repo.run(repo_name="facebook/react", question="What is the reconciler?"))
