"""OpenAI SDK drop-in: agentic tool authorization through DeepintShield.

The model proposes a tool call with the stock OpenAI client; before executing it,
we ask the gateway's policy decision point (/api/agentic-security/decide) whether
the action is allowed. Same OpenAI code, plus one authorization call.
"""
import json
import os

import httpx
from openai import OpenAI

BASE = os.environ["DEEPINTSHIELD_BASE_URL"].rstrip("/")
VK = os.environ["DEEPINTSHIELD_VIRTUAL_KEY"]

client = OpenAI(base_url=BASE + "/v1", api_key=VK)


def authorize(tool, arguments):
    resp = httpx.post(
        f"{BASE}/api/agentic-security/decide",
        headers={"Authorization": f"Bearer {VK}"},
        json={"agent": "demo-agent", "tool": tool, "args_digest": "sha256:demo"},
        timeout=30,
    )
    return resp.json().get("verdict", "DENY")


tools = [
    {
        "type": "function",
        "function": {
            "name": "delete_record",
            "description": "Permanently delete a database record",
            "parameters": {
                "type": "object",
                "properties": {"id": {"type": "string"}},
                "required": ["id"],
            },
        },
    }
]

resp = client.chat.completions.create(
    model="openai/gpt-4o-mini",
    messages=[{"role": "user", "content": "Delete record A-1001."}],
    tools=tools,
)
choice = resp.choices[0].message

if not choice.tool_calls:
    print(choice.content)
else:
    call = choice.tool_calls[0]
    verdict = authorize(call.function.name, call.function.arguments)
    print(f"tool={call.function.name} args={call.function.arguments} -> verdict={verdict}")
    print("executing tool" if verdict == "ALLOW" else "blocked by agentic policy")
