"""PydanticAI: gate a governed MCP tool through DeepintShield.

The tool body calls shield.mcp.call(...) - the gateway resolves the MCP server,
runs the tool, and applies tool governance. Needs an MCP server (e.g. DeepWiki)
registered on the gateway.
"""
from pydantic_ai import Agent

from deepintshield import DeepintShield

shield = DeepintShield.from_env()
agent = Agent(shield.pydanticai().model("gpt-4o-mini"))


@agent.tool_plain
def ask_repo(repo_name: str, question: str) -> str:
    """Ask a free-form question about a public GitHub repository via MCP."""
    result = shield.mcp.call(
        server="DeepWiki",
        tool="ask_question",
        arguments={"repoName": repo_name, "question": question},
    )
    return str(result)


print(agent.run_sync("Use ask_repo to summarise facebook/react's reconciler.").output)
