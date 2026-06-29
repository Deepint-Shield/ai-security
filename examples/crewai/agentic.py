"""CrewAI: gate every tool call through the agentic PDP with one line."""
from crewai.tools import tool

from deepintshield import DeepintShield, DeepintShieldBlockedError

shield = DeepintShield.from_env()


@tool("delete_database")
def delete_database(name: str) -> str:
    """Permanently delete a database by name."""
    return f"deleted {name}"


# Instrument the CrewAI BaseTool(s) in place - each call now runs the PDP first.
shield.agentic.guard([delete_database])

try:
    print(delete_database.run(name="prod"))
except DeepintShieldBlockedError as e:
    print("blocked by policy:", e)
