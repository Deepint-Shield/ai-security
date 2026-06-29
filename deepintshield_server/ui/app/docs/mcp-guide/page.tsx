"use client";

import { Code, Layers, LayoutGrid, MonitorCog, ScrollText, Settings, Shield, ToolCase, Wrench } from "lucide-react";
import Link from "next/link";
import { AccentIcon, Callout, CodeBlock, DataTable, DocPageHeader, InlineCode, PageShell, SectionCard } from "../_shared/docs-ui";

const uiComponents = [
	{
		icon: LayoutGrid,
		title: "MCP Registry",
		path: "/workspace/mcp-registry",
		desc: "Register MCP servers, discover available tools, and monitor server health. Each entry includes the endpoint URL, supported tools, and connection status.",
	},
	{
		icon: Settings,
		title: "MCP Config",
		path: "/workspace/mcp-settings",
		desc: "Configure gateway-wide MCP policies including default timeouts, retry behavior, approval workflows, and execution logging settings.",
	},
	{
		icon: ScrollText,
		title: "MCP & Agents Logs",
		path: "/workspace/mcp-logs",
		desc: "Real-time log of all MCP tool invocations. Inspect request / response payloads, guardrail evaluations, durations, and error details.",
	},
	{
		icon: Shield,
		title: "MCP Guardrails",
		path: "/workspace/guardrails/configuration",
		desc: "Configure guardrail policies specifically for MCP tool invocations. Apply server-level and tool-level restrictions.",
	},
];

const toolFields: [string, string, string][] = [
	["tool_name", "str", "Name of the tool being invoked (e.g. 'query_database')"],
	["tool_input", "str | dict", "Arguments passed to the tool"],
	["server_label", "str", "MCP server identifier - triggers MCP stage when set"],
	["action_class", "str", "Operation type: 'read', 'write', or 'delete'"],
	["domains", "list[str]", "Network / resource domains the tool accesses"],
	["metadata", "dict", "Additional context for policy evaluation"],
];

export default function MCPGuidePage() {
	return (
		<PageShell>
			<DocPageHeader
				eyebrowIcon={ToolCase}
				eyebrow="MCP Gateway"
				title="MCP Gateway Guide"
				subtitle="Secure and govern tool execution across MCP (Model Context Protocol) servers. The MCP Gateway provides centralized control over which tools agents can invoke and under what conditions."
			/>

			<SectionCard
				icon={Layers}
				tone="primary"
				title="MCP Gateway Architecture"
				description="Every tool call from your AI agent is routed through DeepintShield. Tool guard, human approval, audit logging, and rate limiting run before the request reaches the MCP server."
			>
				<div className="border-border/60 bg-card/40 rounded-xl border p-4 shadow-[0_1px_0_rgba(255,255,255,0.04)_inset]">
					<img src="/docs/mcp-pipeline.svg" alt="MCP gateway architecture diagram" className="mx-auto w-full max-w-3xl" />
				</div>
			</SectionCard>

			<SectionCard
				icon={MonitorCog}
				tone="blue"
				title="MCP Management in the UI"
				description="Four dedicated console areas cover the full lifecycle - registration, configuration, monitoring, and guardrail policy."
			>
				<div className="grid gap-3.5 sm:grid-cols-2">
					{uiComponents.map((item) => (
						<Link
							key={item.title}
							href={item.path}
							className="border-border/50 bg-background/40 hover:border-primary/40 hover:bg-primary/5 group flex flex-col gap-2.5 rounded-xl border p-4 transition-all"
						>
							<div className="flex items-center gap-2.5">
								<AccentIcon icon={item.icon} tone="primary" size="sm" />
								<p className="text-foreground text-sm font-semibold">{item.title}</p>
							</div>
							<p className="text-muted-foreground text-xs leading-relaxed">{item.desc}</p>
							<span className="text-primary mt-auto inline-flex items-center gap-1 text-[11px] font-medium tracking-[0.14em] uppercase transition-transform group-hover:translate-x-0.5">
								Open in UI →
							</span>
						</Link>
					))}
				</div>
			</SectionCard>

			<SectionCard
				icon={Code}
				tone="purple"
				title="SDK Integration"
				description={
					<>
						Use the <InlineCode>ToolInvocation</InlineCode> type with a <InlineCode>server_label</InlineCode> to trigger MCP-specific
						evaluation.
					</>
				}
			>
				<CodeBlock
					code={`from deepintshield import DeepintShield, ToolInvocation

shield = DeepintShield.from_env()

# Evaluate an MCP tool invocation
tool = ToolInvocation(
    tool_name="create_issue",
    tool_input={
        "title": "Bug fix needed",
        "body": "Details of the bug...",
        "repo": "my-org/my-repo",
    },
    server_label="github-mcp",    # triggers MCP stage evaluation
    action_class="write",          # read | write | delete
    domains=["github.com"],        # domain restrictions
)

result = shield.agent.evaluate_tool(tool)

if result.is_allowed:
    print("Tool call approved - proceed with execution")
else:
    print(f"Tool call blocked: {result.decision}")
    for reason in result.reasons:
        print(f"  Reason: {reason}")`}
				/>
				<Callout icon={Shield} tone="purple" title="MCP routing">
					When <InlineCode>server_label</InlineCode> is set, the SDK automatically routes the evaluation through the MCP guardrail stage
					instead of the generic action stage.
				</Callout>
			</SectionCard>

			<SectionCard
				icon={Wrench}
				tone="amber"
				title="ToolInvocation Fields"
				description="Every field on the request - what to fill in for each evaluation context."
			>
				<DataTable
					headers={["Field", "Type", "Description"]}
					rows={toolFields.map(([field, type_, desc]) => [
						<code key="f" className="text-primary font-mono text-xs">
							{field}
						</code>,
						<code key="t" className="text-muted-foreground font-mono text-xs">
							{type_}
						</code>,
						<span key="d" className="text-muted-foreground text-xs">
							{desc}
						</span>,
					])}
				/>
			</SectionCard>
		</PageShell>
	);
}
