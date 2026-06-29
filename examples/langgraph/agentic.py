"""Auto-governed LangGraph: constructing the client gates every compiled graph."""
from typing import TypedDict

from langgraph.graph import END, StateGraph

from deepintshield import DeepintShield, GuardrailDenied

shield = DeepintShield.from_env()  # patches StateGraph.compile -> every node PDP-gated


class State(TypedDict):
    text: str


def transfer_funds(state: State) -> State:
    return {"text": f"transferred: {state['text']}"}


graph = StateGraph(State)
graph.add_node("transfer_funds", transfer_funds)
graph.set_entry_point("transfer_funds")
graph.add_edge("transfer_funds", END)

app = graph.compile()  # already governed - no extra wiring

try:
    print(app.invoke({"text": "$1000 to acct 42"}))
except GuardrailDenied as e:
    print("denied by policy:", e)
