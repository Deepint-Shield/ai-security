"use client";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
	getErrorMessage,
	useCreateGuardrailPolicyVersionMutation,
	useGetGuardrailPoliciesQuery,
	useGetGuardrailPolicyVersionsQuery,
	usePublishGuardrailPolicyVersionMutation,
	useUpdateGuardrailPolicyMutation,
} from "@/lib/store";
import type { GuardrailPolicy } from "@/lib/types/guardrails";
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib";
import { Info, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

// GuardrailsView - the OSS deterministic-guardrails surface. The master switch
// drives the DEFAULT policy's enabled/enforcement fields; the regex + PII
// selections are persisted as a published policy version whose definition
// mirrors the server runtime defaults (handlers/guardrails_patterns.go). ML/LLM
// detectors, custom cards, domain packs and partner providers are Cloud/Enterprise.

type RegexPreset = { key: string; label: string; rule: string; severity: string; on_fail: string; priority: number; summary: string };

const INPUT_REGEX_PRESETS: RegexPreset[] = [
	{ key: "prompt_injection", label: "Prompt injection / jailbreak", rule: "(?i)(ignore previous instructions|reveal system prompt|developer mode|jailbreak|bypass safety|override policy)", severity: "high", on_fail: "deny", priority: 10, summary: "Prompt injection or jailbreak attempt detected" },
	{ key: "credentials", label: "Secrets / credentials", rule: "(?i)(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]+PRIVATE KEY-----|sk-[a-zA-Z0-9]{20,}|api[_-]?key)", severity: "critical", on_fail: "redact", priority: 20, summary: "Sensitive credential material detected" },
	{ key: "high_risk_actions", label: "High-risk action chains", rule: "(?i)(disable approval|override reviewer|rm -rf|drop table|wire transfer|exfiltrate data|delete bucket)", severity: "critical", on_fail: "deny", priority: 40, summary: "High-risk action chain blocked" },
];
const OUTPUT_REGEX_PRESETS: RegexPreset[] = [
	{ key: "unsafe_claim", label: "Unsafe / unsupported claims", rule: "(?i)(guaranteed cure|certain outcome|no evidence needed)", severity: "medium", on_fail: "redact", priority: 20, summary: "Potentially unsafe unsupported claim detected" },
];
const PII_CATEGORIES = [
	{ key: "email", label: "Email" },
	{ key: "phone", label: "Phone" },
	{ key: "ssn", label: "SSN" },
	{ key: "credit_card", label: "Credit card" },
];
const DEFAULT_INPUT_PII = ["ssn", "credit_card"];
const DEFAULT_OUTPUT_PII = ["email", "phone", "ssn", "credit_card"];

function regexCheck(p: RegexPreset): Record<string, unknown> {
	const action: Record<string, unknown> = { on_fail: p.on_fail };
	if (p.on_fail === "redact") action.redact_with = "[REDACTED]";
	return { name: "regex_match", enabled: true, priority: p.priority, config: { rule: p.rule, severity: p.severity, summary: p.summary }, action };
}
function piiCheck(categories: string[], priority: number): Record<string, unknown> {
	return { name: "detect_pii", enabled: true, priority, config: { categories, severity: "high", summary: "Sensitive personal or payment data detected" }, action: { on_fail: "redact", redact_with: "[REDACTED]" } };
}

export default function GuardrailsView() {
	const hasSettingsUpdateAccess = useRbac(RbacResource.Settings, RbacOperation.Update);
	// Revalidate on mount so a hard refresh reflects server truth rather than a
	// stale cross-session cache snapshot (persistence.ts). The warm snapshot still
	// renders instantly; this just kicks a background refetch to reconcile.
	const { data: policies, isLoading } = useGetGuardrailPoliciesQuery(undefined, { refetchOnMountOrArgChange: true });
	const [updatePolicy, { isLoading: isSaving }] = useUpdateGuardrailPolicyMutation();
	const [createVersion] = useCreateGuardrailPolicyVersionMutation();
	const [publishVersion] = usePublishGuardrailPolicyVersionMutation();

	// Pick the default policy as the thing the controls bind to.
	const targetPolicy: GuardrailPolicy | undefined = useMemo(() => {
		if (!policies || policies.length === 0) return undefined;
		return policies.find((p) => p.is_default) ?? policies[0];
	}, [policies]);

	const { data: versions } = useGetGuardrailPolicyVersionsQuery(targetPolicy?.id ?? "", { skip: !targetPolicy });

	// Active definition = the published version (else the newest).
	const activeDefinition = useMemo<Record<string, unknown> | undefined>(() => {
		if (!versions || versions.length === 0) return undefined;
		const sorted = [...versions].sort((a, b) => b.version - a.version);
		const published = sorted.find((v) => v.status === "published");
		return (published ?? sorted[0])?.definition;
	}, [versions]);

	const [enabled, setEnabled] = useState(false);
	const [blocking, setBlocking] = useState(false);
	const [redact, setRedact] = useState(false);
	const [inputRegex, setInputRegex] = useState<string[]>(INPUT_REGEX_PRESETS.map((p) => p.key));
	const [outputRegex, setOutputRegex] = useState<string[]>(OUTPUT_REGEX_PRESETS.map((p) => p.key));
	const [inputPII, setInputPII] = useState<string[]>(DEFAULT_INPUT_PII);
	const [outputPII, setOutputPII] = useState<string[]>(DEFAULT_OUTPUT_PII);

	useEffect(() => {
		if (!targetPolicy) return;
		setEnabled(targetPolicy.enabled);
		setBlocking(targetPolicy.execution_mode === "sync");
		setRedact(targetPolicy.enforcement_mode === "redact");
	}, [targetPolicy]);

	// Hydrate the regex/PII selections from the active version definition.
	useEffect(() => {
		if (!activeDefinition) return;
		const parseStage = (checks: unknown, presets: RegexPreset[]): { regex: string[]; pii: string[] } => {
			const regex: string[] = [];
			let pii: string[] = [];
			if (Array.isArray(checks)) {
				for (const c of checks as Array<Record<string, any>>) {
					if (c?.name === "regex_match" && c?.enabled !== false) {
						const preset = presets.find((x) => x.rule === c?.config?.rule);
						if (preset) regex.push(preset.key);
					} else if (c?.name === "detect_pii" && c?.enabled !== false && Array.isArray(c?.config?.categories)) {
						pii = (c.config.categories as unknown[]).filter((x): x is string => typeof x === "string");
					}
				}
			}
			return { regex, pii };
		};
		const inp = parseStage(activeDefinition.input_guardrails, INPUT_REGEX_PRESETS);
		const out = parseStage(activeDefinition.output_guardrails, OUTPUT_REGEX_PRESETS);
		setInputRegex(inp.regex);
		setInputPII(inp.pii);
		setOutputRegex(out.regex);
		setOutputPII(out.pii);
	}, [activeDefinition]);

	const toggle = (list: string[], key: string): string[] => (list.includes(key) ? list.filter((k) => k !== key) : [...list, key]);

	const handleSave = useCallback(async () => {
		if (!targetPolicy) return;
		try {
			// 1. policy-level toggles (enable / block / redact)
			await updatePolicy({
				id: targetPolicy.id,
				data: {
					name: targetPolicy.name,
					description: targetPolicy.description,
					domain_pack_id: targetPolicy.domain_pack_id ?? undefined,
					apply_to_all_workspaces: targetPolicy.workspace_id == null,
					scope: targetPolicy.scope,
					scopes: targetPolicy.scopes,
					enforcement_mode: redact ? "redact" : "block",
					execution_mode: blocking ? "sync" : "async",
					shadow_until: targetPolicy.shadow_until ?? null,
					sampling_rate: targetPolicy.sampling_rate,
					timeout_ms: targetPolicy.timeout_ms,
					enabled,
					metadata: targetPolicy.metadata,
				},
			}).unwrap();

			// 2. publish a new version carrying the selected regex presets + PII
			//    categories, preserving any non-deterministic parts of the definition.
			const base = (activeDefinition ?? {}) as Record<string, unknown>;
			const definition: Record<string, unknown> = {
				rules: base.rules ?? [],
				blocked_domains: base.blocked_domains ?? [],
				allowed_action_classes: base.allowed_action_classes ?? [],
				denied_action_classes: base.denied_action_classes ?? [],
				input_guardrails: [...INPUT_REGEX_PRESETS.filter((p) => inputRegex.includes(p.key)).map(regexCheck), ...(inputPII.length ? [piiCheck(inputPII, 30)] : [])],
				output_guardrails: [...(outputPII.length ? [piiCheck(outputPII, 10)] : []), ...OUTPUT_REGEX_PRESETS.filter((p) => outputRegex.includes(p.key)).map(regexCheck)],
			};
			const created = await createVersion({ id: targetPolicy.id, data: { definition } }).unwrap();
			await publishVersion({ id: targetPolicy.id, version_id: created.id }).unwrap();

			toast.success("Guardrail settings updated successfully.");
		} catch (error) {
			toast.error(getErrorMessage(error));
		}
	}, [targetPolicy, enabled, blocking, redact, inputRegex, outputRegex, inputPII, outputPII, activeDefinition, updatePolicy, createVersion, publishVersion]);

	return (
		<div className="workspace-page-shell space-y-5">
			<header className="space-y-1.5">
				<div className="text-muted-foreground text-[11px] font-semibold tracking-[0.18em] uppercase">Settings</div>
				<div className="flex items-center gap-2.5">
					<span className="bg-primary/12 text-primary inline-flex h-9 w-9 items-center justify-center rounded-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
						<ShieldCheck className="h-4 w-4" />
					</span>
					<div>
						<h1 className="text-2xl leading-none font-semibold tracking-tight">Guardrails</h1>
						<p className="text-muted-foreground mt-1 text-sm">Deterministic regex + PII guardrails on inference traffic.</p>
					</div>
				</div>
			</header>

			<Alert variant="default" className="border-blue-20">
				<Info className="h-4 w-4 text-blue-600" />
				<AlertDescription>
					Advanced ML guardrails (DeBERTa / RoBERTa detectors, custom cards, domain packs, partner providers) are available on Cloud / Enterprise.
				</AlertDescription>
			</Alert>

			{isLoading && (
				<div className="flex items-center justify-center py-8">
					<p className="text-muted-foreground">Loading guardrail configuration...</p>
				</div>
			)}

			{!isLoading && !targetPolicy && (
				<div className="rounded-lg border p-4">
					<p className="text-sm font-medium">Loading the default guardrail policy…</p>
					<p className="text-muted-foreground mt-1 text-sm">A default deterministic policy (PII + regex) is provisioned automatically. If this persists, reload the page or restart the gateway.</p>
				</div>
			)}

			{!isLoading && targetPolicy && (
				<div className="space-y-4">
					{/* Master enable/disable - drives the default policy's enabled flag */}
					<div className="flex items-center justify-between space-x-2 rounded-lg border p-4">
						<div className="space-y-0.5">
							<Label htmlFor="guardrails-enabled" className="text-sm font-medium">
								Enable deterministic guardrails
							</Label>
							<p className="text-muted-foreground text-sm">
								Run the default guardrail policy (<b>{targetPolicy.name}</b>) on inference requests.
							</p>
						</div>
						<Switch id="guardrails-enabled" checked={enabled} onCheckedChange={setEnabled} />
					</div>

					{/* Blocking enforcement (execution_mode sync vs async) */}
					<div className="flex items-center justify-between space-x-2 rounded-lg border p-4">
						<div className="space-y-0.5">
							<Label htmlFor="guardrails-blocking" className="text-sm font-medium">
								Block on violations
							</Label>
							<p className="text-muted-foreground text-sm">When on, a violating request is short-circuited (sync). When off, checks run for observability only (async).</p>
						</div>
						<Switch id="guardrails-blocking" checked={blocking} disabled={!enabled} onCheckedChange={setBlocking} />
					</div>

					{/* Redact / mask (enforcement_mode redact vs block) */}
					<div className="flex items-center justify-between space-x-2 rounded-lg border p-4">
						<div className="space-y-0.5">
							<Label htmlFor="guardrails-redact" className="text-sm font-medium">
								Mask / redact PII
							</Label>
							<p className="text-muted-foreground text-sm">Redact matched PII and secrets in place instead of rejecting the whole request.</p>
						</div>
						<Switch id="guardrails-redact" checked={redact} disabled={!enabled} onCheckedChange={setRedact} />
					</div>

					{/* PII categories - select / deselect per stage */}
					<div className="space-y-3 rounded-lg border p-4">
						<div className="space-y-0.5">
							<Label className="text-sm font-medium">PII detection</Label>
							<p className="text-muted-foreground text-sm">Choose which personal-data categories are detected on each stage.</p>
						</div>
						<div className="grid gap-6 sm:grid-cols-2">
							<div className="space-y-2">
								<div className="text-muted-foreground text-xs font-semibold uppercase">On input</div>
								{PII_CATEGORIES.map((c) => (
									<label key={`in-${c.key}`} className="flex items-center gap-2 text-sm">
										<Checkbox checked={inputPII.includes(c.key)} disabled={!enabled} onCheckedChange={() => setInputPII((l) => toggle(l, c.key))} />
										{c.label}
									</label>
								))}
							</div>
							<div className="space-y-2">
								<div className="text-muted-foreground text-xs font-semibold uppercase">On output</div>
								{PII_CATEGORIES.map((c) => (
									<label key={`out-${c.key}`} className="flex items-center gap-2 text-sm">
										<Checkbox checked={outputPII.includes(c.key)} disabled={!enabled} onCheckedChange={() => setOutputPII((l) => toggle(l, c.key))} />
										{c.label}
									</label>
								))}
							</div>
						</div>
					</div>

					{/* Built-in regex rule presets */}
					<div className="space-y-3 rounded-lg border p-4">
						<div className="space-y-0.5">
							<Label className="text-sm font-medium">Regex rules</Label>
							<p className="text-muted-foreground text-sm">Built-in deterministic pattern checks. Toggle the ones you want enforced.</p>
						</div>
						<div className="grid gap-6 sm:grid-cols-2">
							<div className="space-y-2">
								<div className="text-muted-foreground text-xs font-semibold uppercase">Input</div>
								{INPUT_REGEX_PRESETS.map((p) => (
									<label key={p.key} className="flex items-center gap-2 text-sm">
										<Checkbox checked={inputRegex.includes(p.key)} disabled={!enabled} onCheckedChange={() => setInputRegex((l) => toggle(l, p.key))} />
										{p.label}
									</label>
								))}
							</div>
							<div className="space-y-2">
								<div className="text-muted-foreground text-xs font-semibold uppercase">Output</div>
								{OUTPUT_REGEX_PRESETS.map((p) => (
									<label key={p.key} className="flex items-center gap-2 text-sm">
										<Checkbox checked={outputRegex.includes(p.key)} disabled={!enabled} onCheckedChange={() => setOutputRegex((l) => toggle(l, p.key))} />
										{p.label}
									</label>
								))}
							</div>
						</div>
					</div>
				</div>
			)}

			<div className="flex justify-end pt-2">
				<Button onClick={handleSave} disabled={isSaving || !hasSettingsUpdateAccess || !targetPolicy}>
					{isSaving ? "Saving..." : "Save Changes"}
				</Button>
			</div>
		</div>
	);
}
