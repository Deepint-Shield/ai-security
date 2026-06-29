"""Gate OpenAI Agents SDK function tools through the PDP."""
from agents import Agent, Runner, function_tool

from deepintshield import DeepintShield

shield = DeepintShield.from_env()
shield.openai_agents().apply()


@function_tool
def delete_record(record_id: str) -> str:
    return f"deleted {record_id}"


agent = Agent(name="Ops", instructions="Use the tools.", tools=[delete_record])
shield.agentic.guard(agent)  # gate every FunctionTool on the agent through the PDP

result = Runner.run_sync(agent, "delete record 42")

print(result.final_output)
