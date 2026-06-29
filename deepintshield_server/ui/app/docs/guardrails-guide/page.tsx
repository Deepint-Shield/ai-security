"use client";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { AlertTriangle, Construction, Eye, Layers, Lock, ScanSearch, Shield, ShieldCheck, Sparkles } from "lucide-react";
import Link from "next/link";
import { AccentIcon, type AccentTone, BulletList, CodeBlock, DocPageHeader, FieldLabel, PageShell, SectionCard } from "../_shared/docs-ui";

interface Stage {
	id: string;
	title: string;
	icon: React.ComponentType<{ className?: string }>;
	tone: AccentTone;
	description: string;
	detectors: string[];
	code: string;
}

const stages: Stage[] = [
	{
		id: "input",
		title: "Input Stage",
		icon: ScanSearch,
		tone: "blue",
		description:
			"Evaluates user prompts before they reach the LLM. Catches prompt injection, PII leakage, and policy violations before any model processing occurs.",
		detectors: [
			"Prompt injection detection",
			"PII detection (email, SSN, phone, etc.)",
			"Toxicity and harmful content filtering",
			"Custom regex and keyword rules",
			"Topic restriction and boundary enforcement",
		],
		code: `# SDK: Scan input before sending to LLM
scanner = Scanner(config)
result = scanner.scan_input(user_message)
if result.blocked:
    return f"Request blocked: {result.reason}"`,
	},
	{
		id: "output",
		title: "Output Stage",
		icon: Eye,
		tone: "green",
		description:
			"Evaluates model responses before delivery to the user. Prevents data leakage, hallucination of sensitive information, and toxic content in responses.",
		detectors: [
			"PII redaction in model outputs",
			"Hallucination detection",
			"Toxic content filtering",
			"Custom output validation rules",
			"Data leakage prevention",
		],
		code: `# SDK: Scan output before showing to user
result = scanner.scan_output(model_response)
safe_response = result.sanitized_output or model_response`,
	},
	{
		id: "action",
		title: "Action Stage",
		icon: AlertTriangle,
		tone: "orange",
		description:
			"Evaluates tool/function calls before execution. Controls which tools agents can invoke, validates arguments, and enforces domain restrictions.",
		detectors: [
			"Tool allowlist / blocklist",
			"Argument validation and sanitization",
			"Domain restriction enforcement",
			"Action class (read/write/delete) controls",
			"Rate limiting per tool",
		],
		code: `# SDK: Evaluate tool call before execution
from deepintshield import DeepintShield, ToolInvocation

shield = DeepintShield.from_env()

tool = ToolInvocation(
    tool_name="execute_sql",
    tool_input={"query": "DROP TABLE users"},
    action_class="write",
    domains=["database.prod"],
)
result = shield.agent.evaluate_tool(tool)`,
	},
	{
		id: "mcp",
		title: "MCP Stage",
		icon: Lock,
		tone: "purple",
		description:
			"Evaluates MCP (Model Context Protocol) tool invocations. Applies server-specific policies, validates tool permissions, and enforces approval workflows.",
		detectors: [
			"MCP server authorization",
			"Tool-level permission checks",
			"Approval workflow enforcement",
			"Server label validation",
			"Cross-server policy evaluation",
		],
		code: `# SDK: Evaluate MCP tool invocation
from deepintshield import DeepintShield, ToolInvocation

shield = DeepintShield.from_env()

tool = ToolInvocation(
    tool_name="query_database",
    tool_input={"sql": "SELECT * FROM users"},
    server_label="postgres-mcp",  # triggers MCP stage
    action_class="read",
)
result = shield.agent.evaluate_tool(tool)`,
	},
	{
		id: "rag",
		title: "RAG Stage",
		icon: Shield,
		tone: "red",
		description:
			"Evaluates retrieved documents before they are included in the LLM context. Detects injection attacks embedded in documents, enforces access control, and validates trust scores.",
		detectors: [
			"Document injection detection",
			"Trust score validation",
			"ACL-based access control",
			"PII detection in retrieved content",
			"Source health verification",
			"Quarantine enforcement",
		],
		code: `# SDK: Evaluate RAG chunks
from deepintshield import DeepintShield, build_chunk, filter_chunks

shield = DeepintShield.from_env()

chunks = [build_chunk(content="...", chunk_id="c-1", document_id="d-1")]
evaluation = shield.rag.evaluate(
    query="User question",
    retrieved_chunks=chunks,
    source_id="knowledge-base",
)
safe_chunks = filter_chunks(chunks, evaluation)`,
	},
];

const decisions: { decision: string; desc: string; tone: AccentTone }[] = [
	{ decision: "allow", desc: "Request passes all guardrail checks", tone: "green" },
	{ decision: "block / deny", desc: "Request is blocked and an error is returned to the caller", tone: "red" },
	{ decision: "approval_required", desc: "Request requires manual approval before proceeding", tone: "amber" },
	{ decision: "warn", desc: "Request is allowed but a warning is logged for review", tone: "orange" },
];

const decisionBadgeClass: Record<AccentTone, string> = {
	primary: "bg-primary/15 text-primary border-primary/30",
	blue: "bg-blue-500/15 text-blue-600 dark:text-blue-400 border-blue-500/30",
	green: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30",
	amber: "bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30",
	red: "bg-rose-500/15 text-rose-600 dark:text-rose-400 border-rose-500/30",
	purple: "bg-violet-500/15 text-violet-600 dark:text-violet-400 border-violet-500/30",
	orange: "bg-orange-500/15 text-orange-600 dark:text-orange-400 border-orange-500/30",
};

const policyEditorItems = [
	{ step: "Create policies", desc: "Define new guardrail rules with the visual policy builder" },
	{ step: "Select stages", desc: "Choose which stages (input, output, action, mcp, rag) the policy applies to" },
	{ step: "Configure detectors", desc: "Add PII detection, injection detection, toxicity filters, and custom rules" },
	{ step: "Set decisions", desc: "Choose block, warn, or log-only for each finding type" },
	{ step: "Set priority", desc: "Control evaluation order when multiple policies match" },
	{ step: "Test policies", desc: "Validate with sample inputs before production deployment" },
];

export default function GuardrailsGuidePage() {
	return (
		<PageShell>
			<DocPageHeader
				eyebrowIcon={Construction}
				eyebrow="Guardrails"
				title="AI Guardrails Guide"
				subtitle="DeepintShield guardrails evaluate every AI interaction at five distinct stages. Configure policies in the UI and the SDK enforces them automatically."
			/>

			<SectionCard
				icon={Layers}
				tone="primary"
				title="Guardrail Pipeline"
				description="Five evaluation stages cover every step of an AI interaction - from input arrival, through tool calls, retrieved context, and finally model output."
			>
				<div className="border-border/60 bg-card/40 rounded-xl border p-4 shadow-[0_1px_0_rgba(255,255,255,0.04)_inset]">
					<img src="/docs/guardrail-pipeline.svg" alt="Guardrail pipeline diagram" className="mx-auto w-full max-w-3xl" />
				</div>
			</SectionCard>

			<SectionCard
				icon={Sparkles}
				tone="amber"
				title="Decision Types"
				description="Every guardrail evaluation returns one of these decisions."
			>
				<div className="grid gap-3 sm:grid-cols-2">
					{decisions.map((d) => (
						<div key={d.decision} className="border-border/50 bg-background/40 flex items-start gap-3 rounded-xl border p-3.5">
							<Badge
								className={cn(
									"shrink-0 rounded-full border text-[10px] font-semibold tracking-[0.14em] uppercase",
									decisionBadgeClass[d.tone],
								)}
							>
								{d.decision}
							</Badge>
							<p className="text-muted-foreground text-sm leading-relaxed">{d.desc}</p>
						</div>
					))}
				</div>
			</SectionCard>

			{stages.map((stage) => (
				<SectionCard
					key={stage.id}
					id={stage.id}
					icon={stage.icon}
					tone={stage.tone}
					title={stage.title}
					badge={stage.id}
					description={stage.description}
				>
					<div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
						<div className="border-border/50 bg-background/30 flex flex-col gap-2.5 rounded-xl border p-4">
							<div className="flex items-center gap-2">
								<AccentIcon icon={ShieldCheck} tone={stage.tone} size="sm" />
								<FieldLabel>Available Detectors</FieldLabel>
							</div>
							<BulletList tone={stage.tone} items={stage.detectors} />
						</div>
						<div className="space-y-2">
							<FieldLabel>SDK Usage</FieldLabel>
							<CodeBlock code={stage.code} />
						</div>
					</div>
				</SectionCard>
			))}

			<Card className="border-primary/20 from-primary/8 via-primary/4 bg-gradient-to-br to-transparent">
				<CardHeader>
					<div className="flex items-start gap-3">
						<AccentIcon icon={Construction} tone="primary" />
						<div>
							<CardTitle className="text-lg">Configuring Guardrails in the UI</CardTitle>
							<p className="text-muted-foreground mt-1 text-sm leading-relaxed">
								Navigate to{" "}
								<Link href="/workspace/guardrails/configuration" className="text-primary font-medium hover:underline">
									AI Guardrails &gt; Policies
								</Link>{" "}
								to manage guardrail configurations.
							</p>
						</div>
					</div>
				</CardHeader>
				<CardContent>
					<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
						{policyEditorItems.map((item) => (
							<div
								key={item.step}
								className="border-border/50 bg-background/50 hover:border-primary/30 hover:bg-primary/5 rounded-xl border p-3.5 transition-colors"
							>
								<p className="text-foreground text-sm font-semibold">{item.step}</p>
								<p className="text-muted-foreground mt-1 text-xs leading-relaxed">{item.desc}</p>
							</div>
						))}
					</div>
				</CardContent>
			</Card>
		</PageShell>
	);
}
