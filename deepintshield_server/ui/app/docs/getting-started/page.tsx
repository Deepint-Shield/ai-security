"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Check, Code, Globe, Key, Rocket, Shield, Terminal, Zap } from "lucide-react";
import Link from "next/link";
import { AccentIcon, CodeBlock, DocPageHeader, PageShell, StepCard } from "../_shared/docs-ui";

const providers = ["OpenAI", "Anthropic", "Google GenAI", "AWS Bedrock", "Azure OpenAI", "LiteLLM"];

const keyOptions = ["Scoped providers and models", "Budget limits and rate limits", "Team / user assignment", "Expiration date"];

const guardrailRules = [
	{ name: "PII Detection", desc: "Block or redact personal information" },
	{ name: "Prompt Injection", desc: "Detect and block injection attempts" },
	{ name: "Toxicity Filter", desc: "Block harmful or toxic content" },
	{ name: "Custom Rules", desc: "Regex, keyword, and semantic rules" },
];

const nextSteps = [
	{ title: "SDK Deep Dive", href: "/docs/sdk-guide", desc: "Full SDK API reference and advanced patterns", icon: Code },
	{ title: "Provider Guide", href: "/docs/providers-guide", desc: "Detailed setup for each LLM provider", icon: Globe },
	{ title: "Guardrails Guide", href: "/docs/guardrails-guide", desc: "Configure safety policies and detectors", icon: Shield },
	{ title: "UI Guide", href: "/docs/ui-guide", desc: "Complete walkthrough of every UI feature", icon: Rocket },
];

export default function GettingStartedPage() {
	return (
		<PageShell>
			<DocPageHeader
				eyebrowIcon={Rocket}
				eyebrow="Getting Started"
				title="Getting Started with DeepintShield"
				subtitle="Get from zero to a fully guarded AI application in minutes. Connect a provider, create a virtual key, and make your first guarded LLM call."
			/>

			{/* Prerequisites */}
			<Card className="border-primary/20 from-primary/8 via-primary/4 bg-gradient-to-br to-transparent">
				<CardHeader>
					<div className="flex items-center justify-between gap-3">
						<CardTitle className="text-[11px] font-semibold tracking-[0.18em] uppercase">Prerequisites</CardTitle>
						<span className="text-muted-foreground text-[10px] font-medium tracking-[0.16em] uppercase">4 required</span>
					</div>
				</CardHeader>
				<CardContent>
					<div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
						{["Python 3.10+", "DeepintShield account", "LLM provider API key", "pip or uv"].map((req) => (
							<div key={req} className="border-border/50 bg-background/40 flex items-center gap-2.5 rounded-lg border px-3 py-2">
								<span className="bg-primary/15 text-primary inline-flex h-5 w-5 items-center justify-center rounded-full">
									<Check className="h-3 w-3" />
								</span>
								<span className="text-foreground text-sm">{req}</span>
							</div>
						))}
					</div>
				</CardContent>
			</Card>

			{/* Step 1 */}
			<StepCard
				number={1}
				icon={Globe}
				title="Configure a Provider"
				description="Add at least one LLM provider in the DeepintShield UI. Navigate to Model Hub > AI Providers and add your provider API keys."
			>
				<div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
					{providers.map((p) => (
						<div
							key={p}
							className="border-border/50 bg-background/40 hover:border-primary/30 hover:bg-primary/5 flex items-center gap-2.5 rounded-lg border px-3 py-2 transition-colors"
						>
							<AccentIcon icon={Globe} tone="primary" size="sm" />
							<span className="text-foreground text-sm">{p}</span>
						</div>
					))}
				</div>
				<p className="text-muted-foreground text-sm">
					Navigate to{" "}
					<Link href="/workspace/providers" className="text-primary font-medium hover:underline">
						Model Hub &gt; AI Providers
					</Link>{" "}
					to add your provider credentials.
				</p>
			</StepCard>

			{/* Step 2 */}
			<StepCard
				number={2}
				icon={Key}
				title="Create a Virtual API Key"
				description="Virtual API Keys authenticate SDK requests and scope access to specific providers, models, and policies."
			>
				<p className="text-muted-foreground text-sm">
					Navigate to{" "}
					<Link href="/workspace/access/virtual-keys" className="text-primary font-medium hover:underline">
						Access &amp; Credentials &gt; Virtual API Keys
					</Link>{" "}
					and create a new key.
				</p>
				<div className="border-border/60 bg-card/40 rounded-xl border p-4 shadow-[0_1px_0_rgba(255,255,255,0.04)_inset]">
					<p className="text-foreground text-[11px] font-semibold tracking-[0.18em] uppercase">Key Configuration Options</p>
					<ul className="mt-2.5 grid gap-1.5 sm:grid-cols-2">
						{keyOptions.map((o) => (
							<li key={o} className="text-muted-foreground flex items-center gap-2 text-sm">
								<Check className="text-primary h-3.5 w-3.5 shrink-0" />
								{o}
							</li>
						))}
					</ul>
				</div>
			</StepCard>

			{/* Step 3 */}
			<StepCard
				number={3}
				icon={Terminal}
				title="Install the SDK"
				description="Install the DeepintShield Python SDK and set your environment variables."
			>
				<CodeBlock
					language="bash"
					code={`# Install with your preferred provider extras
pip install "deepintshield[openai]"

# Set your virtual key
export DEEPINTSHIELD_VIRTUAL_KEY="sk-bf-your-virtual-key"`}
				/>
			</StepCard>

			{/* Step 4 */}
			<StepCard
				number={4}
				icon={Code}
				title="Make Your First Request"
				description="Route an LLM call through DeepintShield. The SDK makes it as simple as changing the base URL."
			>
				<CodeBlock
					code={`from deepintshield import DeepintShield

shield = DeepintShield.from_env()
client = shield.openai()

# Use the OpenAI SDK normally - guardrails are applied automatically
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "What is the capital of France?"}],
)

print(response.choices[0].message.content)
# -> "The capital of France is Paris."`}
				/>
				<p className="text-muted-foreground text-sm">
					Check the{" "}
					<Link href="/workspace/logs" className="text-primary font-medium hover:underline">
						AI Logs
					</Link>{" "}
					page to see your request with guardrail evaluation details.
				</p>
			</StepCard>

			{/* Step 5 */}
			<StepCard
				number={5}
				icon={Shield}
				title="Configure Guardrails"
				description="Set up guardrail policies to protect your AI applications. Guardrails run automatically on every request."
			>
				<p className="text-muted-foreground text-sm">
					Navigate to{" "}
					<Link href="/workspace/guardrails/configuration" className="text-primary font-medium hover:underline">
						AI Guardrails &gt; Policies
					</Link>{" "}
					to create your first policy.
				</p>
				<div className="grid gap-2.5 sm:grid-cols-2">
					{guardrailRules.map((rule) => (
						<div
							key={rule.name}
							className="border-border/50 bg-background/40 hover:border-primary/30 rounded-xl border p-3.5 transition-colors"
						>
							<p className="text-foreground text-sm font-semibold">{rule.name}</p>
							<p className="text-muted-foreground mt-1 text-xs">{rule.desc}</p>
						</div>
					))}
				</div>
			</StepCard>

			{/* Next Steps */}
			<Card className="border-emerald-500/20 bg-gradient-to-br from-emerald-500/8 via-emerald-500/4 to-transparent">
				<CardHeader>
					<div className="flex items-center gap-3">
						<AccentIcon icon={Zap} tone="green" />
						<div>
							<CardTitle className="text-base">You&apos;re all set - what&apos;s next?</CardTitle>
							<p className="text-muted-foreground mt-1 text-sm">Explore deeper guides to get the most out of DeepintShield.</p>
						</div>
					</div>
				</CardHeader>
				<CardContent>
					<div className="grid gap-3 sm:grid-cols-2">
						{nextSteps.map((next) => {
							const Icon = next.icon;
							return (
								<Link
									key={next.title}
									href={next.href}
									className="border-border/50 bg-background/60 hover:border-primary/40 hover:bg-primary/5 group flex items-start gap-3 rounded-xl border p-3.5 transition-all"
								>
									<AccentIcon icon={Icon} tone="primary" size="sm" />
									<div className="min-w-0">
										<p className="text-foreground text-sm font-semibold">{next.title}</p>
										<p className="text-muted-foreground mt-0.5 text-xs">{next.desc}</p>
									</div>
								</Link>
							);
						})}
					</div>
				</CardContent>
			</Card>
		</PageShell>
	);
}
