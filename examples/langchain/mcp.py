"""shield.mcp.to_langchain(tools) yields BaseTools for a create_tool_calling_agent."""
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate

from deepintshield import DeepintShield, Tool

shield = DeepintShield.from_env()
llm = shield.langchain(model="gpt-4o-mini")

tools = [
    Tool(
        server="DeepWiki",
        name="ask_question",
        description="Ask a free-form question about a public GitHub repository.",
        schema={
            "type": "object",
            "properties": {
                "repoName": {"type": "string", "description": "owner/name"},
                "question": {"type": "string"},
            },
            "required": ["repoName", "question"],
        },
    ),
]

mcp_tools = shield.mcp.to_langchain(tools)

prompt = ChatPromptTemplate.from_messages([
    ("system", "Answer questions about GitHub repos using the DeepWiki tools."),
    ("user", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])

agent = create_tool_calling_agent(llm, mcp_tools, prompt)
executor = AgentExecutor(agent=agent, tools=mcp_tools)

result = executor.invoke({"input": "How does facebook/react organize its reconciler?"})
print(result["output"])
