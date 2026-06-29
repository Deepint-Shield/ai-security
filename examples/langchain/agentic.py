"""shield.agentic.guard() is a LangChain callback that gates every tool call via the PDP."""
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import tool

from deepintshield import DeepintShield

shield = DeepintShield.from_env()
llm = shield.langchain(model="gpt-4o-mini")


@tool
def write_ledger(row: str) -> str:
    """Append a row to the finance ledger."""
    return f"wrote {row}"


prompt = ChatPromptTemplate.from_messages([
    ("system", "You record finance entries using the write_ledger tool."),
    ("user", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])

agent = create_tool_calling_agent(llm, [write_ledger], prompt)
executor = AgentExecutor(agent=agent, tools=[write_ledger])

# One handler covers every tool the agent calls; a block aborts the tool.
guard = shield.agentic.guard()
result = executor.invoke({"input": "Record amount=12.5"}, config={"callbacks": [guard]})

print(result["output"])
