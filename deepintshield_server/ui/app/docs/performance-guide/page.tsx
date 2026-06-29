"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Cpu, DollarSign, Gauge, Layers, ShieldCheck, Zap } from "lucide-react";
import {
	AccentIcon,
	Callout,
	DataTable,
	DocPageHeader,
	InlineCode,
	PageShell,
} from "../_shared/docs-ui";

// Five concrete latency/cost knobs DeepintShield ships with - all on by
// default unless the row says otherwise. Keep this page short; deeper tuning
// belongs in operator runbooks, not the user-facing docs.
const FEATURES = [
	{
		icon: Cpu,
		tone: "primary" as const,
		title: "Embedded guard runtime",
		default: "On",
		summary:
			"Guard evaluation runs in-process inside the gateway - no RPC hop. Saves ~20–300ms per request in single-binary deployments.",
		flag: "DEEPINTSHIELD_GUARD_USE_EMBEDDED_RUNTIME=true",
	},
	{
		icon: Zap,
		tone: "blue" as const,
		title: "Speculative dispatch",
		default: "Off (opt-in)",
		summary:
			"Fire the provider call in parallel with input-guard evaluation. Allow-path latency becomes max(guards, model) instead of sum. Denied requests discard the model response.",
		flag: "DEEPINTSHIELD_GUARD_SPECULATIVE_INPUT_GUARDS=true",
	},
	{
		icon: Layers,
		tone: "green" as const,
		title: "Async post-guards",
		default: "On (auto)",
		summary:
			"When no output policy needs to block or redact, the post-LLM evaluation goes to a background goroutine. Audit findings still persist; the user sees the response immediately.",
		flag: "DEEPINTSHIELD_GUARD_ASYNC_POST_GUARDS=true",
	},
	{
		icon: Gauge,
		tone: "amber" as const,
		title: "Per-category timeouts",
		default: "Opt-in",
		summary:
			"Tighten budgets per check class: PII <150ms, toxicity ~600ms, jailbreak ~1200ms. Slow classifiers no longer pull the whole p99 up to a flat 1500ms ceiling.",
		flag: `DEEPINTSHIELD_GUARD_TIMEOUTS_BY_CATEGORY='{"pii":150,"toxicity":600,"jailbreak":1200}'`,
	},
	{
		icon: DollarSign,
		tone: "purple" as const,
		title: "Semantic cache short-circuit",
		default: "On",
		summary:
			"Semantic cache runs before guard evaluation. A fuzzy hit short-circuits the whole pipeline - no guard call, no provider call. Cuts cost on templated/chat workloads by up to 60%.",
		flag: "DEEPINTSHIELD_SEMANTIC_LOOKUP_AFTER_GUARDS=true (to revert)",
	},
];

export default function PerformanceGuidePage() {
	return (
		<PageShell>
			<DocPageHeader
				eyebrowIcon={Zap}
				eyebrow="Performance & Cost"
				title="Real-time guardrails, by default"
				subtitle="Five optimizations ship enabled (or one flag away) so the fast path stays sub-5ms and templated traffic costs less."
			/>

			<Callout icon={ShieldCheck} tone="green" title="Defaults are safe">
				Every &quot;On&quot; default below preserves the original blocking semantics - guards still deny, still
				redact, still log. The optimizations only reclaim time you weren&apos;t spending on safety to begin with.
			</Callout>

			<div className="grid gap-4 lg:grid-cols-2">
				{FEATURES.map((feat) => (
					<Card key={feat.title} className="scroll-mt-20">
						<CardHeader>
							<div className="flex items-start gap-3">
								<AccentIcon icon={feat.icon} tone={feat.tone} />
								<div className="min-w-0 flex-1">
									<CardTitle className="flex items-center justify-between gap-2 text-base">
										<span>{feat.title}</span>
										<span className="text-[10px] font-semibold tracking-[0.14em] uppercase text-muted-foreground">
											Default: {feat.default}
										</span>
									</CardTitle>
								</div>
							</div>
						</CardHeader>
						<CardContent className="space-y-3">
							<p className="text-sm leading-relaxed text-muted-foreground">{feat.summary}</p>
							<InlineCode>{feat.flag}</InlineCode>
						</CardContent>
					</Card>
				))}
			</div>

			<Card className="scroll-mt-20">
				<CardHeader>
					<CardTitle className="text-base">What you can expect</CardTitle>
				</CardHeader>
				<CardContent>
					<DataTable
						headers={["Metric", "DeepintShield default", "Why"]}
						rows={[
							[
								"Guardrail latency (p50)",
								<span key="lat" className="font-semibold text-cyan-700 dark:text-cyan-300">
									&lt;5ms
								</span>,
								"Embedded runtime + decision cache + local-rule fast path",
							],
							[
								"Allow-path total latency",
								<span key="allow" className="font-semibold text-cyan-700 dark:text-cyan-300">
									max(guards, model)
								</span>,
								"Speculative dispatch when enabled (non-streaming requests)",
							],
							[
								"LLM cost saved",
								<span key="cost" className="font-semibold text-emerald-700 dark:text-emerald-300">
									Up to 90%
								</span>,
								"Semantic cache short-circuit on templated / repeated prompts",
							],
							[
								"Tail latency (p99)",
								<span key="tail" className="font-semibold text-amber-700 dark:text-amber-300">
									Down ~30–50%
								</span>,
								"Per-category timeouts replace the flat 1500ms ceiling",
							],
						]}
					/>
				</CardContent>
			</Card>

			<Callout icon={Gauge} tone="primary" title="Need to tune further?">
				The five flags above live in <InlineCode>config.json</InlineCode> (
				<InlineCode>plugins.guardrails.config</InlineCode>) or the matching environment variables. Operators can flip
				any one at runtime without restarting the gateway when set via plugin config.
			</Callout>
		</PageShell>
	);
}
