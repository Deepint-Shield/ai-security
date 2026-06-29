"""shield.langchain(...) returns a native LangChain chat model pointed at the gateway."""
from langchain_core.messages import HumanMessage

from deepintshield import DeepintShield

shield = DeepintShield.from_env()
llm = shield.langchain(model="gpt-4o-mini")

response = llm.invoke([HumanMessage(content="hello")])
print(response.content)
