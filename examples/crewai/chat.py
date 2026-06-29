"""CrewAI: get a native crewai.LLM bound to the gateway and call it."""
from deepintshield import DeepintShield

shield = DeepintShield.from_env()

# Native crewai.LLM pointed at the gateway - drop into any CrewAI Agent.
llm = shield.crewai().llm("gpt-4o-mini")

reply = llm.call("Reply with the single word: pong")
print(reply)
