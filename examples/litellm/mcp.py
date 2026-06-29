"""LiteLLM: surface governed MCP tools as OpenAI-format tools through DeepintShield.

shield.mcp.to_openai(...) renders MCP tool specs as OpenAI `tools`, and
shield.mcp.run_openai_tool_calls(...) executes the model's tool calls through the
gateway (resolving the MCP server + applying tool governance). Needs an MCP
server (e.g. DeepWiki) registered on the gateway.
"""
from deepintshield import DeepintShield, Tool

shield = DeepintShield.from_env()

tools = shield.mcp.to_openai(
    [
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
)

resp = shield.litellm().completion(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "What is the reconciler in facebook/react?"}],
    tools=tools,
)

message = resp.choices[0].message
if message.tool_calls:
    # Run the MCP tool calls through the gateway and print the results.
    print(shield.mcp.run_openai_tool_calls(message.tool_calls))
else:
    print(message.content)
