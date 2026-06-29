"""AutoGen: wrap a governed MCP tool as an autogen_core FunctionTool.

The tool body calls shield.mcp.call(...) - the gateway resolves the MCP server,
runs the tool, and applies tool governance. Needs an MCP server (e.g. DeepWiki)
registered on the gateway.
"""
import asyncio

from autogen_core import CancellationToken
from autogen_core.tools import FunctionTool

from deepintshield import DeepintShield

shield = DeepintShield.from_env()


def ask_repo(repo_name: str, question: str) -> str:
    """Ask a free-form question about a public GitHub repository via MCP."""
    return str(
        shield.mcp.call(
            server="DeepWiki",
            tool="ask_question",
            arguments={"repoName": repo_name, "question": question},
        )
    )


tool = FunctionTool(ask_repo, description="Ask a question about a public GitHub repository via MCP.")


async def main() -> None:
    result = await tool.run_json(
        {"repo_name": "facebook/react", "question": "What is the reconciler?"},
        CancellationToken(),
    )
    print(tool.return_value_as_string(result))


asyncio.run(main())
