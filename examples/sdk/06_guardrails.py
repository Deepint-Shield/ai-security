"""06 - Guardrails (screen text before it reaches the model)."""
from deepintshield import DeepintShield

shield = DeepintShield.from_env()

result = shield.evaluate_guardrail(
    stage="input",
    input="My email is jane.doe@example.com, store it.",
)
print("allowed:", result.allowed)
print("decision:", result.decision)
print("reason:", result.reason)
