"""AutoGen model client routed through the DeepintShield gateway."""
import asyncio

from autogen_core.models import UserMessage

from deepintshield import DeepintShield

shield = DeepintShield.from_env()
client = shield.autogen().model_client("gpt-4o-mini")  # OpenAIChatCompletionClient


async def chat() -> str:
    result = await client.create(
        [UserMessage(content="Name three primary colors.", source="user")]
    )
    return result.content


print(asyncio.run(chat()))
