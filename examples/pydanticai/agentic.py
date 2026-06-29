"""Gate a PydanticAI agent's tools in place via the DeepintShield PDP."""
from pydantic_ai import Agent

from deepintshield import DeepintShield

shield = DeepintShield.from_env()

pydantic_agent = Agent(shield.pydanticai().model("gpt-4o-mini"))


@pydantic_agent.tool_plain
def charge_card(amount: float) -> str:
    return f"charged {amount}"


shield.agentic.guard(pydantic_agent)  # gates every tool call through the PDP
print(pydantic_agent.run_sync("charge 9.99 to the card").output)
