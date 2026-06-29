"""09 - MCP tools (Model Context Protocol).

Register an MCP server on the gateway first (Config -> MCP, or
POST /api/mcp/client), then list + call its tools through the gateway - every
call is routed, governed, and logged. This example targets the public DeepWiki
MCP server (register name "DeepWiki", connection_type "http",
connection_string "https://mcp.deepwiki.com/mcp").
"""
from deepintshield import DeepintShield
from deepintshield.mcp import MCPClient

shield = DeepintShield.from_env()
mcp = MCPClient(shield)

# Tools the gateway has synced from every registered MCP server.
tools = mcp.list_tools()
print("synced MCP tools:", [t.name for t in tools][:10])

# Call a governed MCP tool through the gateway.
result = mcp.call(server="DeepWiki", tool="read_wiki_structure", arguments={"repoName": "facebook/react"})
print(result)
