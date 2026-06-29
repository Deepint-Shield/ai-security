"""Native langchain_openai.ChatOpenAI pointed at the gateway (drop into any LangGraph node)."""
from deepintshield import DeepintShield

shield = DeepintShield.from_env()

# LangGraph builds on LangChain chat models; shield.langchain(model=...) returns a
# native langchain_openai.ChatOpenAI already pointed at the gateway. Use shield.langgraph()
# for the guard nodes (input_guard / tool_guard / output_guard).
model = shield.langchain(model="gpt-4o-mini")
print(model.invoke("hello").content)
