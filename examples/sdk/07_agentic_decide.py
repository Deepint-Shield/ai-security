"""07 - Agentic policy decision point (PDP)."""
from deepintshield import DeepintShield

shield = DeepintShield.from_env()

decision = shield.agentic.decide(
    tool="delete_database",
    args={"name": "prod"},
    prompt="drop the production database",
)
print(decision.verdict)
print(decision.reason)
