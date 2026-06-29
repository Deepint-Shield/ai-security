"""DeepintShield-managed MCP tools dropped into a LangGraph ToolNode."""
from langchain_core.messages import AIMessage
from langgraph.prebuilt import ToolNode

from deepintshield import DeepintShield, Tool

shield = DeepintShield.from_env()

tool_specs = [
    Tool(
        server="DeepWiki",
        name="ask_question",
        description="Ask a free-form question about a public GitHub repository.",
        schema={
            "type": "object",
            "properties": {"repoName": {"type": "string"}, "question": {"type": "string"}},
            "required": ["repoName", "question"],
        },
    ),
]

mcp_tools = shield.mcp.to_langchain(tool_specs)  # ready-to-use BaseTool list
tool_node = ToolNode(mcp_tools)

call = AIMessage(
    content="",
    tool_calls=[{
        "name": "DeepWiki-ask_question",
        "args": {"repoName": "facebook/react", "question": "What is the reconciler?"},
        "id": "1",
    }],
)
print(tool_node.invoke({"messages": [call]}))
