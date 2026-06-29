"""OpenAI SDK drop-in: chat completions through DeepintShield.

Point the stock OpenAI client at the gateway and keep your code - every call is
now routed, guardrailed, cached, and logged.

    pip install openai
    export DEEPINTSHIELD_BASE_URL=http://localhost:8080
    export DEEPINTSHIELD_VIRTUAL_KEY=<virtual-key>
    python chat.py
"""
import os

from openai import OpenAI

client = OpenAI(
    base_url=os.environ["DEEPINTSHIELD_BASE_URL"].rstrip("/") + "/v1",
    api_key=os.environ["DEEPINTSHIELD_VIRTUAL_KEY"],
)

resp = client.chat.completions.create(
    model="openai/gpt-4o-mini",
    messages=[{"role": "user", "content": "Name three primary colors."}],
)
print(resp.choices[0].message.content)
