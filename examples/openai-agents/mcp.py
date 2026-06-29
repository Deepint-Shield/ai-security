"""OpenAI Agents SDK: gate a governed MCP tool through DeepintShield.

The function tool calls shield.mcp.call(...) - the gateway resolves the MCP
server, runs the tool, and applies tool governance. Needs an MCP server (e.g.
DeepWiki) registered on the gateway.
"""
from agents import Agent, Runner, function_tool

from deepintshield import DeepintShield

shield = DeepintShield.from_env()
shield.openai_agents().apply()  # route the Agents SDK through the gateway


@function_tool
def ask_repo(repo_name: str, question: str) -> str:
    """Ask a free-form question about a public GitHub repository via MCP."""
    result = shield.mcp.call(
        server="DeepWiki",
        tool="ask_question",
        arguments={"repoName": repo_name, "question": question},
    )
    return str(result)


agent = Agent(name="Researcher", instructions="Use ask_repo to answer questions about GitHub repos.", tools=[ask_repo])
result = Runner.run_sync(agent, "Summarise facebook/react's reconciler.")
print(result.final_output)
