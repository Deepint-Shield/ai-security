"use client";

import { Badge } from "@/components/ui/badge";
import { Globe, Layers, Shuffle } from "lucide-react";
import { Callout, CodeBlock, DocPageHeader, FieldLabel, InlineCode, PageShell, SectionCard, TocCard } from "../_shared/docs-ui";

interface ProviderEntry {
	name: string;
	key: string;
	description: string;
	install: string;
	quickCode: string;
	manualCode: string;
	passthroughCode?: string;
	features: string[];
}

const providers: ProviderEntry[] = [
	{
		name: "OpenAI",
		key: "openai",
		description: "GPT-4o, GPT-4o-mini, o1, and all OpenAI models",
		install: 'pip install "deepintshield[openai]"',
		quickCode: `from deepintshield import DeepintShield

shield = DeepintShield(virtual_key="sk-bf-your-virtual-key")
client = shield.openai()

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello!"}],
)
print(response.choices[0].message.content)`,
		manualCode: `from openai import OpenAI

client = OpenAI(
    base_url="https://app.deepintshield.com/openai",
    api_key="sk-bf-your-virtual-key",
    default_headers={"x-bf-vk": "sk-bf-your-virtual-key"},
)`,
		passthroughCode: `from deepintshield import DeepintShield

shield = DeepintShield.from_env()
client = shield.openai(passthrough=True)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello!"}],
)`,
		features: ["Chat completions", "Streaming", "Function calling", "Vision", "Passthrough mode"],
	},
	{
		name: "Anthropic",
		key: "anthropic",
		description: "Claude 4.6, Claude 4.5, and all Anthropic models",
		install: 'pip install "deepintshield[anthropic]"',
		quickCode: `from deepintshield import DeepintShield

shield = DeepintShield(virtual_key="sk-bf-your-virtual-key")
client = shield.anthropic()

response = client.messages.create(
    model="anthropic/claude-sonnet-4-5",
    max_tokens=256,
    messages=[{"role": "user", "content": "Hello!"}],
)
print(response.content[0].text)`,
		manualCode: `import anthropic

client = anthropic.Anthropic(
    base_url="https://app.deepintshield.com/anthropic",
    api_key="sk-bf-your-virtual-key",
    default_headers={"x-bf-vk": "sk-bf-your-virtual-key"},
)`,
		passthroughCode: `from deepintshield import DeepintShield

shield = DeepintShield.from_env()
client = shield.anthropic(passthrough=True)

response = client.messages.create(
    model="claude-sonnet-4-5",
    max_tokens=256,
    messages=[{"role": "user", "content": "Hello!"}],
)`,
		features: ["Messages API", "Streaming", "Tool use", "Vision", "Passthrough mode"],
	},
	{
		name: "Google GenAI",
		key: "genai",
		description: "Gemini 2.0 Flash, Gemini Pro, and all Google models",
		install: 'pip install "deepintshield[genai]"',
		quickCode: `from deepintshield import DeepintShield

shield = DeepintShield(virtual_key="sk-bf-your-virtual-key")
client = shield.genai()

response = client.models.generate_content(
    model="gemini-2.0-flash",
    contents="Hello from Google GenAI!",
)
print(response.text)`,
		manualCode: `from google import genai
from google.genai.types import HttpOptions

client = genai.Client(
    api_key="sk-bf-your-virtual-key",
    http_options=HttpOptions(
        base_url="https://app.deepintshield.com/genai",
        headers={"x-bf-vk": "sk-bf-your-virtual-key"},
    ),
)`,
		passthroughCode: `from deepintshield import DeepintShield

shield = DeepintShield.from_env()
client = shield.genai(passthrough=True)`,
		features: ["Generate content", "Streaming", "Multimodal", "Passthrough mode"],
	},
	{
		name: "AWS Bedrock",
		key: "bedrock",
		description: "Claude, Titan, Llama, and all Bedrock-hosted models",
		install: 'pip install "deepintshield[bedrock]"',
		quickCode: `from deepintshield import DeepintShield

shield = DeepintShield(virtual_key="sk-bf-your-virtual-key")
client = shield.bedrock(region_name="us-east-1")

response = client.converse(
    modelId="anthropic.claude-3-sonnet-20240229-v1:0",
    messages=[{"role": "user", "content": [{"text": "Hello!"}]}],
)`,
		manualCode: `import boto3

client = boto3.client(
    "bedrock-runtime",
    region_name="us-east-1",
    endpoint_url="https://app.deepintshield.com/bedrock",
    aws_access_key_id="deepintshield-dummy-key",
    aws_secret_access_key="deepintshield-dummy-secret",
)
client.meta.events.register(
    "before-sign.bedrock-runtime.*",
    lambda request, **_: request.headers.__setitem__("x-bf-vk", "sk-bf-your-virtual-key"),
)`,
		features: ["Invoke model", "Streaming", "Converse API", "Custom region support"],
	},
	{
		name: "LiteLLM",
		key: "litellm",
		description: "Unified interface for 100+ LLM providers via LiteLLM",
		install: 'pip install "deepintshield[litellm]"',
		quickCode: `from deepintshield import DeepintShield

shield = DeepintShield(virtual_key="sk-bf-your-virtual-key")
litellm = shield.litellm()

response = litellm.completion(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello via LiteLLM!"}],
)`,
		manualCode: `from litellm import completion

response = completion(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello!"}],
    base_url="https://app.deepintshield.com/litellm",
    api_key="sk-bf-your-virtual-key",
    extra_headers={"x-bf-vk": "sk-bf-your-virtual-key"},
)`,
		features: ["OpenAI-compatible", "100+ providers", "Fallbacks", "Load balancing"],
	},
	{
		name: "LangChain",
		key: "langchain",
		description: "LangChain ChatModels routed through DeepintShield",
		install: 'pip install "deepintshield[langchain]"',
		quickCode: `from deepintshield import DeepintShield
from langchain_core.messages import HumanMessage

shield = DeepintShield(virtual_key="sk-bf-your-virtual-key")
llm = shield.langchain(model="gpt-4o-mini")

response = llm.invoke([HumanMessage(content="Hello from LangChain!")])
print(response.content)`,
		manualCode: `from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    model="gpt-4o-mini",
    openai_api_base="https://app.deepintshield.com/langchain",
    openai_api_key="sk-bf-your-virtual-key",
    default_headers={"x-bf-vk": "sk-bf-your-virtual-key"},
)`,
		features: ["ChatModel", "LCEL chains", "Streaming", "Tool calling"],
	},
	{
		name: "PydanticAI",
		key: "pydanticai",
		description: "PydanticAI agents with structured outputs via DeepintShield",
		install: 'pip install "deepintshield[pydanticai]"',
		quickCode: `from deepintshield import DeepintShield

shield = DeepintShield(virtual_key="sk-bf-your-virtual-key")
agent = shield.pydanticai().build_agent(
    model="gpt-4o-mini",
    instructions="Be concise and helpful.",
)

result = agent.run_sync("Hello!")
print(result.output)`,
		manualCode: `from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

provider = OpenAIProvider(
    base_url="https://app.deepintshield.com/pydanticai/v1",
    api_key="sk-bf-your-virtual-key",
)
agent = Agent(OpenAIChatModel("gpt-4o-mini", provider=provider))`,
		features: ["Structured outputs", "Type-safe", "Agent workflows"],
	},
];

export default function ProvidersGuidePage() {
	return (
		<PageShell>
			<DocPageHeader
				eyebrowIcon={Globe}
				eyebrow="Provider Integration"
				title="LLM Provider Integration Guide"
				subtitle="DeepintShield supports all major LLM providers through a unified gateway. Route any provider's traffic through guardrails using the native SDK you already know."
			/>

			<TocCard items={providers.map((p) => ({ id: p.key, label: p.name }))} />

			<SectionCard
				icon={Layers}
				tone="primary"
				title="How Provider Routing Works"
				description="DeepintShield acts as a transparent gateway between your application and LLM providers. Your code uses the native provider SDK but points at the DeepintShield gateway instead of the provider's API."
			>
				<div className="border-border/60 bg-card/40 rounded-xl border p-4 shadow-[0_1px_0_rgba(255,255,255,0.04)_inset]">
					<img src="/docs/provider-routing.svg" alt="Provider routing diagram" className="mx-auto w-full max-w-3xl" />
				</div>
				<Callout icon={Layers} tone="primary" title="Virtual API Key">
					You never pass provider credentials through the SDK. All authentication uses a Virtual API Key (<InlineCode>x-bf-vk</InlineCode>{" "}
					header), and DeepintShield handles provider key management.
				</Callout>
			</SectionCard>

			<SectionCard
				icon={Shuffle}
				tone="amber"
				title="Dynamic Provider Selection"
				description="Switch providers at runtime without changing code."
			>
				<CodeBlock
					code={`import os
from deepintshield import DeepintShield

shield = DeepintShield.from_env()

# Dispatch on a config value - every method returns a native SDK client
provider_name = os.getenv("LLM_PROVIDER", "openai")
client = {
    "openai": shield.openai,
    "anthropic": shield.anthropic,
    "genai": shield.genai,
    "bedrock": shield.bedrock,
    "litellm": shield.litellm,
    "langchain": shield.langchain,
    "pydanticai": shield.pydanticai,
}[provider_name]()

# Every provider method accepts passthrough=True where supported
# shield.openai(passthrough=True), shield.anthropic(passthrough=True), ...`}
				/>
			</SectionCard>

			{providers.map((provider) => (
				<SectionCard
					key={provider.key}
					id={provider.key}
					icon={Globe}
					tone="blue"
					title={provider.name}
					badge={provider.key}
					description={provider.description}
				>
					<div className="space-y-3">
						<FieldLabel>Install</FieldLabel>
						<CodeBlock language="bash" code={provider.install} />
					</div>
					<div className="space-y-3">
						<FieldLabel>
							Provider Adapter <span className="text-muted-foreground/70 tracking-normal normal-case">(recommended)</span>
						</FieldLabel>
						<CodeBlock code={provider.quickCode} />
					</div>
					<div className="space-y-3">
						<FieldLabel>Manual Setup</FieldLabel>
						<CodeBlock code={provider.manualCode} />
					</div>
					{provider.passthroughCode && (
						<div className="space-y-3">
							<FieldLabel>Passthrough Mode</FieldLabel>
							<CodeBlock code={provider.passthroughCode} />
						</div>
					)}
					<div className="border-border/40 flex flex-wrap gap-2 border-t pt-3">
						{provider.features.map((feature) => (
							<Badge key={feature} variant="outline" className="rounded-full text-[10px] font-medium tracking-[0.12em] uppercase">
								{feature}
							</Badge>
						))}
					</div>
				</SectionCard>
			))}
		</PageShell>
	);
}
