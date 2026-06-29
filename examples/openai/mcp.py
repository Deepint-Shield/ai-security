"""OpenAI SDK drop-in: tool calling through DeepintShield.

DeepintShield can surface MCP-server tools through the same OpenAI `tools`
interface, so an MCP-backed agent looks exactly like ordinary OpenAI function
calling. Here a local tool stands in for an MCP tool to show the full round trip.
"""
import json
import os

from openai import OpenAI

client = OpenAI(
    base_url=os.environ["DEEPINTSHIELD_BASE_URL"].rstrip("/") + "/v1",
    api_key=os.environ["DEEPINTSHIELD_VIRTUAL_KEY"],
)

tools = [
    {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get the current weather for a city",
            "parameters": {
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"],
            },
        },
    }
]


def get_weather(city):
    return f"{city}: 22C, clear skies"


messages = [{"role": "user", "content": "What's the weather in Paris?"}]
first = client.chat.completions.create(model="openai/gpt-4o-mini", messages=messages, tools=tools)
choice = first.choices[0].message

if not choice.tool_calls:
    print(choice.content)
else:
    call = choice.tool_calls[0]
    result = get_weather(**json.loads(call.function.arguments))
    messages += [choice, {"role": "tool", "tool_call_id": call.id, "content": result}]
    final = client.chat.completions.create(model="openai/gpt-4o-mini", messages=messages, tools=tools)
    print(final.choices[0].message.content)
