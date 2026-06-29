"use client";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
	BarChart3,
	Construction,
	DatabaseZap,
	FolderGit,
	Globe,
	KeyRound,
	Layers,
	LayoutGrid,
	Monitor,
	ScrollText,
	Settings,
	Shield,
	ShieldCheck,
	Shuffle,
	TrendingUp,
	Users,
} from "lucide-react";
import Link from "next/link";
import { AccentIcon, type AccentTone, type IconType, BulletList, DocPageHeader, PageShell, SectionCard } from "../_shared/docs-ui";

interface FeatureSection {
	icon: IconType;
	title: string;
	path: string;
	description: string;
	capabilities: string[];
	tone: AccentTone;
	badge?: string;
}

const featureSections: FeatureSection[] = [
	{
		icon: BarChart3,
		tone: "primary",
		title: "Analytics Dashboard",
		path: "/workspace/dashboard",
		description:
			"The central command center providing real-time visibility into your AI operations. The dashboard aggregates telemetry across all providers and applications.",
		capabilities: [
			"Real-time request volume and latency charts",
			"Provider distribution and error rate visualization",
			"Cost tracking across models and teams",
			"Top-level guardrail decision summaries",
			"Time-range filters and auto-refresh controls",
		],
	},
	{
		icon: ScrollText,
		tone: "blue",
		title: "AI Logs",
		path: "/workspace/logs",
		description:
			"Complete audit trail of every LLM request flowing through DeepintShield. Each log entry includes the full request / response, guardrail evaluations, latency breakdown, and metadata.",
		capabilities: [
			"Full request / response inspection with syntax highlighting",
			"Guardrail evaluation traces and finding details",
			"Filterable by provider, model, status, virtual key, and time range",
			"Real-time streaming via WebSocket",
			"Export capabilities for compliance and analysis",
			"Token count and cost per request",
		],
	},
	{
		icon: ShieldCheck,
		tone: "green",
		title: "Guardrail Metrics",
		path: "/workspace/analytics/guardrails",
		description:
			"Dedicated analytics view for guardrail performance. Understand how your safety policies are performing across input, output, action, and RAG stages.",
		capabilities: [
			"Decision distribution charts (allow, block, deny)",
			"Policy-level breakdown showing which rules fire most often",
			"Latency impact analysis for guardrail evaluation overhead",
			"Finding type distribution (PII, injection, toxicity, etc.)",
			"Stage-based filtering (input, output, action, mcp, rag)",
		],
	},
	{
		icon: DatabaseZap,
		tone: "purple",
		title: "AI Providers",
		path: "/workspace/providers",
		description:
			"Configure and manage connections to LLM providers. Add provider API keys, set default models, and control which providers are available to your applications.",
		capabilities: [
			"Add / edit / remove provider configurations (OpenAI, Anthropic, Bedrock, GenAI, etc.)",
			"Provider health monitoring and connectivity testing",
			"Default model selection per provider",
			"Custom base URL support for self-hosted models",
			"Provider-level rate limiting and budget controls",
		],
	},
	{
		icon: Construction,
		tone: "amber",
		title: "AI Guardrails",
		path: "/workspace/guardrails/configuration",
		description:
			"Define and manage guardrail policies that protect your AI applications. Policies are evaluated at runtime for every request, covering input validation, output safety, tool execution, and RAG security.",
		capabilities: [
			"Visual policy editor with rule builder",
			"Stage-based policies: input, output, action, MCP, RAG",
			"Built-in detectors: PII, prompt injection, toxicity, jailbreak, custom regex",
			"Decision modes: block, warn, log-only, approval-required",
			"Policy priority and ordering controls",
			"Test mode for validating policies before production deployment",
		],
		badge: "Core Feature",
	},
	{
		icon: Shuffle,
		tone: "orange",
		title: "Model Routing",
		path: "/workspace/routing-rules",
		description:
			"Control how requests are distributed across providers and models. Define routing rules based on user identity, request metadata, cost constraints, or custom logic.",
		capabilities: [
			"Conditional routing based on request attributes",
			"Weighted traffic splitting across providers",
			"Fallback chains for provider failures",
			"Cost-based routing for budget optimization",
			"A / B testing support for model comparisons",
		],
	},
	{
		icon: TrendingUp,
		tone: "green",
		title: "Load Balancer",
		path: "/workspace/adaptive-routing",
		description:
			"Automatic load balancing and failover across LLM providers. The adaptive router monitors provider health and routes traffic for optimal performance.",
		capabilities: [
			"Automatic failover when providers become unhealthy",
			"Latency-based routing to fastest available provider",
			"Circuit breaker patterns for provider protection",
			"Health check configuration and monitoring",
			"Real-time provider status dashboard",
		],
	},
	{
		icon: LayoutGrid,
		tone: "blue",
		title: "MCP Registry",
		path: "/workspace/mcp-registry",
		description:
			"Register and manage MCP (Model Context Protocol) tool servers. The registry tracks all connected tool endpoints and their available tools.",
		capabilities: [
			"Register MCP server endpoints with connection details",
			"Tool discovery and capability inspection",
			"Server health monitoring and connectivity testing",
			"Tool grouping and access control",
			"Execution policy configuration per server",
		],
	},
	{
		icon: Settings,
		tone: "primary",
		title: "MCP Config",
		path: "/workspace/mcp-settings",
		description:
			"Configure MCP gateway behavior including execution policies, timeout settings, and approval workflows for tool invocations.",
		capabilities: [
			"Global MCP execution timeout settings",
			"Default approval policies for tool calls",
			"Tool-level override configurations",
			"Audit logging settings for MCP activity",
		],
	},
	{
		icon: Monitor,
		tone: "purple",
		title: "MCP & Agents Logs",
		path: "/workspace/mcp-logs",
		description:
			"Detailed logs of all MCP tool invocations flowing through the gateway. Track which tools are being called, by whom, and their results.",
		capabilities: [
			"Full tool invocation request / response inspection",
			"Server and tool name filtering",
			"Guardrail evaluation traces for MCP calls",
			"Duration and error tracking per invocation",
			"Real-time streaming updates",
		],
	},
	{
		icon: Users,
		tone: "amber",
		title: "Governance Hub",
		path: "/workspace/governance",
		description:
			"Manage organizational access control, team structures, and accountability. The governance hub provides centralized control over who can access what.",
		capabilities: [
			"User invitation and role management",
			"Team creation with scoped permissions",
			"Member budget allocation and cost tracking",
			"Audit trail of all administrative actions",
		],
		badge: "Enterprise",
	},
	{
		icon: KeyRound,
		tone: "orange",
		title: "Virtual API Keys",
		path: "/workspace/access/virtual-keys",
		description:
			"Create and manage Virtual API Keys that scope access to specific providers, models, and policies. Virtual keys are the primary authentication mechanism for SDK users.",
		capabilities: [
			"Create keys scoped to specific providers and models",
			"Set budget limits and rate limits per key",
			"Team and user assignment for accountability",
			"Key rotation and revocation controls",
			"Usage analytics per virtual key",
		],
	},
	{
		icon: Globe,
		tone: "blue",
		title: "Observability Integrations",
		path: "/workspace/observability",
		description:
			"Export telemetry data to external observability platforms. Integrate DeepintShield data into your existing monitoring and alerting workflows.",
		capabilities: [
			"OTLP export to OpenTelemetry collectors",
			"Custom webhook destinations",
			"Configurable export filters and sampling",
			"Telemetry data preview before export",
		],
	},
	{
		icon: FolderGit,
		tone: "green",
		title: "Prompt Playground",
		path: "/workspace/prompt-repo",
		description:
			"Manage and test prompt templates with version control. The prompt playground provides a workspace for creating, testing, and deploying prompt blueprints.",
		capabilities: [
			"Visual prompt editor with variable support",
			"Version history and diff view",
			"Live testing with real model calls",
			"Folder organization for prompt libraries",
			"Deployment tracks for staged rollouts",
		],
	},
	{
		icon: Settings,
		tone: "purple",
		title: "Platform Settings",
		path: "/workspace/config",
		description:
			"Global platform configuration including client defaults, caching behavior, performance tuning, and authentication settings.",
		capabilities: [
			"Client-side configuration (default model, timeout, retries)",
			"Response caching with configurable TTL",
			"Performance tuning (connection pools, batch sizes)",
			"Authentication and SSO configuration",
			"Logging verbosity controls",
		],
	},
];

const navTips = [
	{ label: "Keyboard Shortcut", desc: "Press ⌘K (Mac) or Ctrl+K (Windows) to focus the sidebar search" },
	{ label: "Sidebar Search", desc: "Type in the search bar to filter navigation items by name" },
	{ label: "Collapsible Sidebar", desc: "Click the panel icon to collapse / expand the sidebar" },
	{ label: "Sub-Menus", desc: "Click parent items (Analytics, Model Hub, etc.) to expand sub-navigation" },
	{ label: "Keyboard Navigation", desc: "Use arrow keys in search results, Enter to navigate" },
	{ label: "WebSocket Status", desc: "A green dot appears next to AI Logs when live streaming is connected" },
];

function slugify(s: string) {
	return s.toLowerCase().replace(/\s+/g, "-");
}

export default function UIGuidePage() {
	return (
		<PageShell>
			<DocPageHeader
				eyebrowIcon={Monitor}
				eyebrow="Platform Guide"
				title="User Interface Guide"
				subtitle="Complete walkthrough of every feature and component in the DeepintShield management console. Learn how to configure, monitor, and manage your AI security posture."
			/>

			{/* Quick Navigation */}
			<Card className="border-primary/20 from-primary/8 via-primary/4 bg-gradient-to-br to-transparent">
				<CardHeader>
					<div className="flex items-center justify-between gap-3">
						<div>
							<CardTitle className="text-[11px] font-semibold tracking-[0.18em] uppercase">Quick Navigation</CardTitle>
							<p className="text-muted-foreground mt-1 text-xs">Jump to any feature section</p>
						</div>
						<Badge variant="outline" className="rounded-full text-[10px] font-medium">
							{featureSections.length} sections
						</Badge>
					</div>
				</CardHeader>
				<CardContent>
					<div className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
						{featureSections.map((section) => {
							const Icon = section.icon;
							return (
								<a
									key={section.title}
									href={`#${slugify(section.title)}`}
									className="border-border/40 bg-background/40 text-muted-foreground hover:border-primary/40 hover:bg-primary/5 hover:text-foreground group flex items-center gap-2.5 rounded-lg border px-3 py-2 text-sm transition-all"
								>
									<Icon className="h-3.5 w-3.5" />
									{section.title}
								</a>
							);
						})}
					</div>
				</CardContent>
			</Card>

			{/* Navigation Tips */}
			<SectionCard icon={Layers} tone="blue" title="Navigation Tips" description="Small shortcuts that make the console faster to use.">
				<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
					{navTips.map((tip) => (
						<div
							key={tip.label}
							className="border-border/50 bg-background/40 hover:border-primary/30 rounded-xl border p-3.5 transition-colors"
						>
							<p className="text-foreground text-sm font-semibold">{tip.label}</p>
							<p className="text-muted-foreground mt-1 text-xs leading-relaxed">{tip.desc}</p>
						</div>
					))}
				</div>
			</SectionCard>

			{featureSections.map((section) => (
				<Card key={section.title} id={slugify(section.title)} className="scroll-mt-20">
					<CardHeader>
						<div className="flex items-start justify-between gap-3">
							<div className="flex items-start gap-3">
								<AccentIcon icon={section.icon} tone={section.tone} />
								<div className="min-w-0">
									<CardTitle className="flex flex-wrap items-center gap-2 text-lg">
										{section.title}
										{section.badge && (
											<Badge variant="secondary" className="rounded-full text-[10px] font-semibold tracking-[0.14em] uppercase">
												{section.badge}
											</Badge>
										)}
									</CardTitle>
									<Link href={section.path} className="text-primary mt-1 inline-flex items-center gap-1 font-mono text-xs hover:underline">
										{section.path}
									</Link>
								</div>
							</div>
							<Shield className="text-muted-foreground/40 hidden h-5 w-5 shrink-0 sm:block" />
						</div>
					</CardHeader>
					<CardContent className="space-y-4">
						<p className="text-muted-foreground text-sm leading-relaxed">{section.description}</p>
						<div className="border-border/50 bg-background/30 space-y-3 rounded-xl border p-4">
							<p className="text-foreground text-[10px] font-semibold tracking-[0.18em] uppercase">Capabilities</p>
							<BulletList tone={section.tone} items={section.capabilities} />
						</div>
					</CardContent>
				</Card>
			))}
		</PageShell>
	);
}
