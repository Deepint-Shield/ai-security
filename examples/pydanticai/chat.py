"""PydanticAI agent routed through the DeepintShield gateway."""
from deepintshield import DeepintShield

shield = DeepintShield.from_env()

agent = shield.pydanticai(model="gpt-4o-mini", instructions="Be concise.")
result = agent.run_sync("hello")
print(result.output)
