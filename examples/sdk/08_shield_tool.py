"""08 - Govern a tool-call with the @shield_tool decorator."""
from deepintshield import DeepintShield, GuardrailDenied, shield_tool

shield = DeepintShield.from_env()


@shield_tool(tool="refund_payment", client=shield)
def refund_payment(order_id: str, amount: float) -> str:
    # Only runs if the agentic PDP allows the action.
    return f"refunded ${amount:.2f} for {order_id}"


try:
    print(refund_payment(order_id="A-1001", amount=19.99))
except GuardrailDenied as e:
    # The PDP denied the call (e.g. no matching allow policy) - the body never ran.
    print("blocked by policy:", e)
