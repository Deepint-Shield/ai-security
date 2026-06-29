"""Route the OpenAI Agents SDK through the DeepintShield gateway."""
from agents import Agent, Runner

from deepintshield import DeepintShield

shield = DeepintShield.from_env()
shield.openai_agents().apply()  # set the Agents SDK default client to the gateway

agent = Agent(name="Assistant", instructions="Be concise.")
result = Runner.run_sync(agent, "hello")

print(result.final_output)
