"use client";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { CodeEditor } from "@/components/ui/codeEditor";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { getExampleBaseUrl } from "@/lib/utils/port";
import { AlertTriangle, Copy, ListChecks, Rocket } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";

type Language = "python" | "typescript";

// The onboarding now offers ONE flow - the DeepintShield SDK. Manual
// raw-HTTP recipes and the gateway-side "Agent Mode" are deprecated as
// onboarding entry points because they bypass the guardrails + PDP
// contract the SDK enforces by default. The example shape stays a
// per-language map so the language switcher behavior is unchanged.
type Examples = {
	sdk: {
		[L in Language]: string;
	};
};

// Common editor options to reduce duplication
const EditorOptions = {
	scrollBeyondLastLine: false,
	minimap: { enabled: false },
	lineNumbers: "off",
	folding: false,
	lineDecorationsWidth: 0,
	lineNumbersMinChars: 0,
	glyphMargin: false,
} as const;

interface CodeBlockProps {
	code: string;
	language: string;
	onLanguageChange?: (language: string) => void;
	showLanguageSelect?: boolean;
	readonly?: boolean;
}

function CodeBlock({ code, language, onLanguageChange, showLanguageSelect = false, readonly = true }: CodeBlockProps) {
	const copyToClipboard = () => {
		navigator.clipboard.writeText(code);
		toast.success("Copied to clipboard");
	};

	return (
		<div className="relative">
			<div className="absolute top-4 right-4 z-10 flex items-center gap-2">
				{showLanguageSelect && onLanguageChange && (
					<Select value={language} onValueChange={onLanguageChange}>
						<SelectTrigger className="h-8 w-fit text-xs">
							<SelectValue />
						</SelectTrigger>
						<SelectContent>
							<SelectItem className="text-xs" value="python">
								Python
							</SelectItem>
							<SelectItem className="text-xs" value="typescript">
								TypeScript
							</SelectItem>
						</SelectContent>
					</Select>
				)}
				<Button variant="ghost" size="icon" onClick={copyToClipboard} aria-label="Copy to clipboard">
					<Copy className="size-4" />
				</Button>
			</div>
			<CodeEditor className="w-full" code={code} lang={language} readonly={readonly} height={300} fontSize={14} options={EditorOptions} />
		</div>
	);
}

interface MCPEmptyStateProps {
	error?: string | null;
	statusIndicator?: React.ReactNode;
}

export function MCPEmptyState({ error, statusIndicator }: MCPEmptyStateProps) {
	const [language, setLanguage] = useState<Language>("python");

	// Generate examples dynamically using the port utility
	const examples: Examples = useMemo(() => {
		const baseUrl = getExampleBaseUrl();

		return {
			sdk: {
				python: `# pip install 'deepintshield[openai]'
from deepintshield import DeepintShield, Tool

shield = DeepintShield(
    virtual_key="sk-bf-...",
    base_url="${baseUrl}",
)

# Option 1 - direct call (skip the LLM, just exercise an MCP tool)
result = shield.mcp.call(
    server="DeepWiki",          # case-sensitive client name from MCP Registry
    tool="ask_question",        # bare tool name; no '<server>-' prefix
    repoName="facebook/react",
    question="What is Suspense?",
)
print(result.text)

# Option 2 - full OpenAI tool-calling loop
openai = shield.openai()
tools = [
    Tool(server="DeepWiki", name="ask_question",
         description="Ask a question about a public GitHub repository.",
         schema={"type": "object",
                 "properties": {"repoName": {"type": "string"},
                                "question": {"type": "string"}},
                 "required": ["repoName", "question"]}),
]
messages = [{"role": "user", "content": "Summarize facebook/react's reconciler."}]
first = openai.chat.completions.create(
    model="gpt-4o-mini",
    messages=messages,
    tools=shield.mcp.to_openai(tools),
    tool_choice="required",
)
assistant = first.choices[0].message
messages.append(assistant.model_dump(exclude_none=True))
messages.extend(shield.mcp.run_openai_tool_calls(assistant.tool_calls))

final = openai.chat.completions.create(model="gpt-4o-mini", messages=messages)
print(final.choices[0].message.content)`,
				typescript: `// The deepintshield SDK is currently Python-only - the unified
// SDK flow shown in the Python tab is the only supported entry point
// for MCP + agents. A TypeScript SDK is on the roadmap and will mirror
// the same one-client surface (no raw-HTTP loop, no separate agent mode).
//
// Tracking issue: https://github.com/deepint-shield/ai-security/issues
//
// For now, install the Python SDK in your tooling layer or proxy MCP
// calls through a small Python service; do not hand-roll a raw HTTP
// loop against /openai - that path bypasses the PDP + guardrail bridge
// the unified SDK enforces.`,
			},
		};
	}, []);

	const isUnexpectedError = error && error.includes("An unexpected error occurred");

	return (
		<div className="flex w-full flex-col items-center justify-center space-y-6 bg-transparent">
			{error && (
				<Alert>
					<AlertTriangle className="h-4 w-4" />
					<AlertDescription>
						{isUnexpectedError ? "Looks like you haven't configured the log store in your config file." : error}
					</AlertDescription>
				</Alert>
			)}

			<div className="w-full space-y-6">
				{/* Hero header */}
				<div className="flex flex-row items-end gap-4">
					<div className="flex items-start gap-3">
						<span className="inline-flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-primary/12 text-primary shadow-[inset_0_1px_0_rgba(255,255,255,0.18),0_8px_24px_-12px_rgba(34,211,196,0.45)]">
							<Rocket className="h-5 w-5" />
						</span>
						<div className="space-y-1">
							<div className="text-muted-foreground text-[11px] font-semibold uppercase tracking-[0.18em]">MCP & Agents Logs</div>
							<h3 className="text-2xl font-semibold tracking-tight leading-none">Get started with MCP Execution</h3>
							{/* <p className="text-muted-foreground text-sm">
								Execute your first governed tool call and activity will start appearing here.
							</p> */}
						</div>
					</div>
					{statusIndicator ? <div className="ml-auto">{statusIndicator}</div> : null}
				</div>

				{/* Unified flow - the DeepintShield SDK is the only supported entry
				    point. It covers direct MCP calls, the OpenAI tool-calling loop,
				    and gateway-side autonomous execution under a single client. The
				    old separate "Manual Tool Execution" and "Agent Mode" tabs were
				    raw-HTTP recipes that bypassed guardrails + PDP; they're removed
				    so operators don't accidentally adopt an unsupervised path. */}
				<div className="space-y-3">
					<p className="text-muted-foreground text-sm leading-relaxed">
						<span className="rounded-md bg-emerald-100 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300">
							Unified SDK
						</span>{" "}
						The <code className="bg-muted rounded px-1 font-mono text-xs">deepintshield</code> Python SDK is the single supported flow.
						The same client handles direct MCP calls, the OpenAI tool-calling loop, and gateway-side autonomous execution - every path
						runs through guardrails + the PDP and shows up in AI Logs, MCP & Agents Logs, Agentic Security, and Guardrail Metrics
						automatically. No raw-HTTP loop needed.
					</p>
					<div className="rounded-2xl border border-border/60 bg-card/40 p-1 shadow-[0_1px_2px_rgba(11,42,49,0.04),0_8px_18px_-12px_rgba(11,42,49,0.10)]">
						<CodeBlock
							code={examples.sdk[language]}
							language={language}
							onLanguageChange={(newLang) => setLanguage(newLang as Language)}
							showLanguageSelect
						/>
					</div>
				</div>

				{/* Prerequisites */}
				<div className="rounded-2xl border border-border/60 bg-card/60 p-5 shadow-[0_1px_2px_rgba(11,42,49,0.04),0_8px_18px_-12px_rgba(11,42,49,0.10)]">
					<div className="mb-3 flex items-center gap-2.5">
						<span className="text-primary inline-flex h-7 w-7 items-center justify-center rounded-lg border border-primary/20 bg-primary/10">
							<ListChecks className="h-4 w-4" />
						</span>
						<h4 className="text-foreground text-sm font-semibold tracking-tight">Prerequisites</h4>
					</div>
					<ol className="space-y-2.5 text-sm">
						{[
							<>Configure MCP servers in the MCP Hub (e.g., filesystem, web_search)</>,
							<>
								Set <code className="bg-muted rounded px-1 font-mono text-xs">tools_to_execute</code> to whitelist available tools
							</>,
							<>
								For Agent Mode: configure <code className="bg-muted rounded px-1 font-mono text-xs">tools_to_auto_execute</code> for
								autonomous execution
							</>,
						].map((item, i) => (
							<li key={i} className="flex items-start gap-3">
								<span className="text-primary inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-primary/30 bg-primary/10 text-[10px] font-semibold tabular-nums">
									{i + 1}
								</span>
								<span className="text-foreground/90 leading-relaxed">{item}</span>
							</li>
						))}
					</ol>
				</div>
			</div>
		</div>
	);
}
