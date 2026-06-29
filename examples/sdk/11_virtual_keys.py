"""11 - Virtual keys & governance headers."""
from deepintshield import DeepintShield

shield = DeepintShield.from_env()

# The virtual key + identity headers the SDK attaches to every request.
headers = shield.create_headers(provider="openai")
print(headers)
