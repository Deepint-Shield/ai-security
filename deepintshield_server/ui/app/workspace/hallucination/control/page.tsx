"use client";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { MultiSelect } from "@/components/ui/multiSelect";
import { Switch } from "@/components/ui/switch";
import { getErrorMessage, useCreatePluginMutation, useGetPluginsQuery, useGetVirtualKeysQuery, useUpdatePluginMutation } from "@/lib/store";
import { SEMANTIC_CACHE_PLUGIN } from "@/lib/types/plugins";
import { Loader2, ScanSearch, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

// Hallucination Control - proactive, zero-latency mitigation applied in the
// gateway's PreLLMHook. Every technique here is prompt- or parameter-only
// (no extra round-trips, no added latency on the request path) and is wired
// to the semantic_cache plugin's hallucination_control_* config keys
// (plugins/semanticcache/hallucination_control.go + main.go). The dashboard
// "Improvement" chart reads a heuristic stamped onto each response after the
// techniques fire so operators can see them showing up in model output.
//
// This is the OSS scope: deterministic mitigation only. ML scoring/eval and
// ground-truth datasets are Cloud-only and intentionally not part of this page.

const TECHNIQUES = [
	{
		id: "grounding_directive",
		label: "Stay grounded",
		desc: "Tells the AI to only answer using the information you provided, and to say it doesn't know if the answer isn't there.",
	},
	{
		id: "anti_fabrication",
		label: "Don't make things up",
		desc: "Tells the AI not to invent facts, names, dates, or quotes - to leave them out when unsure.",
	},
	{
		id: "citation_required",
		label: "Require sources",
		desc: "Asks the AI to mark facts with their source. Works best when you share source material in the prompt.",
	},
	{
		id: "uncertainty_ack",
		label: "Hedge when unsure",
		desc: 'Asks the AI to say "might", "likely", or "I\'m not sure" instead of stating uncertain things as facts.',
	},
	{
		id: "temperature_clamp",
		label: "Reduce randomness",
		desc: "Makes the AI's answers more predictable and less random. Default cap is 0.4.",
	},
] as const;

const STRICTNESS_OPTIONS = [
	{ value: "low", label: "Low - gentle reminder" },
	{ value: "medium", label: "Medium - balanced (default)" },
	{ value: "high", label: "High - strict, refuse when no source" },
];

export default function HallucinationControlPage() {
	// Revalidate on mount so a hard reload reflects the saved server config instead
	// of a stale cross-session cache snapshot (see persistence.ts) - otherwise saved
	// hallucination settings appear to "not persist" on reload.
	const { data: plugins, isLoading: loading } = useGetPluginsQuery(undefined, { refetchOnMountOrArgChange: true });
	const [updatePlugin, { isLoading: isUpdating }] = useUpdatePluginMutation();
	const [createPlugin, { isLoading: isCreating }] = useCreatePluginMutation();

	const plugin = plugins?.find((p) => p.name === SEMANTIC_CACHE_PLUGIN);
	const config = (plugin?.config || {}) as Record<string, unknown>;

	const { data: virtualKeysData } = useGetVirtualKeysQuery({});
	const vkOptions = useMemo(
		() =>
			(virtualKeysData?.virtual_keys || []).map((vk) => ({
				value: vk.id,
				label: vk.name || vk.id,
			})),
		[virtualKeysData],
	);

	const [enabled, setEnabled] = useState(false);
	const [techniques, setTechniques] = useState<Record<string, boolean>>({
		grounding_directive: true,
		anti_fabrication: true,
		citation_required: false,
		uncertainty_ack: true,
		temperature_clamp: false,
	});
	const [strictness, setStrictness] = useState<string>("medium");
	const [tempCap, setTempCap] = useState<number>(0.4);
	const [vkScope, setVkScope] = useState<string[]>([]);

	useEffect(() => {
		if (!plugin?.config) return;
		setEnabled(Boolean(config.hallucination_control_enabled));
		const storedTech = Array.isArray(config.hallucination_control_techniques)
			? (config.hallucination_control_techniques as string[])
			: null;
		if (storedTech) {
			setTechniques(Object.fromEntries(TECHNIQUES.map((t) => [t.id, storedTech.includes(t.id)])));
		}
		if (typeof config.hallucination_control_strictness === "string" && config.hallucination_control_strictness) {
			setStrictness(config.hallucination_control_strictness as string);
		}
		if (typeof config.hallucination_control_temp_cap === "number" && config.hallucination_control_temp_cap > 0) {
			setTempCap(config.hallucination_control_temp_cap as number);
		}
		if (Array.isArray(config.hallucination_control_vk_scope)) {
			setVkScope((config.hallucination_control_vk_scope as unknown[]).filter((v): v is string => typeof v === "string"));
		}
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [plugin]);

	const handleSave = async () => {
		const techniqueList = TECHNIQUES.filter((t) => techniques[t.id]).map((t) => t.id);
		const nextConfig = {
			...(plugin?.config || {}),
			hallucination_control_enabled: enabled,
			hallucination_control_techniques: techniqueList,
			hallucination_control_strictness: strictness,
			hallucination_control_temp_cap: tempCap,
			hallucination_control_vk_scope: vkScope,
		};
		const isNotFound = (err: unknown) => (err as { status?: number } | undefined)?.status === 404;
		try {
			try {
				await updatePlugin({
					name: SEMANTIC_CACHE_PLUGIN,
					data: { enabled: plugin?.enabled ?? true, config: nextConfig },
				}).unwrap();
			} catch (err) {
				if (!isNotFound(err)) throw err;
				await createPlugin({ name: SEMANTIC_CACHE_PLUGIN, enabled: true, config: nextConfig, path: "" }).unwrap();
			}
			toast.success("Hallucination control saved");
		} catch (err) {
			toast.error(`Failed to save: ${getErrorMessage(err)}`);
		}
	};

	const busy = isUpdating || isCreating;

	return (
		<div className="workspace-page-shell flex flex-col gap-3">
			<div className="text-muted-foreground flex items-center gap-2 text-xs tracking-[0.18em] uppercase">
				<ScanSearch className="h-3.5 w-3.5" />
				Hallucination Control
			</div>
			<h1 className="text-2xl font-semibold tracking-tight">Control</h1>

			<div className="border-border/60 bg-card/70 mt-2 flex items-center justify-between gap-3 rounded-2xl border p-5 shadow-[0_1px_2px_rgba(11,42,49,0.04)]">
				<div>
					<h3 className="text-sm font-semibold">Hallucination control</h3>
					<p className="text-muted-foreground text-xs">Master switch. Off = no techniques applied; requests pass through unchanged.</p>
				</div>
				<Switch size="md" checked={enabled} disabled={loading} onCheckedChange={setEnabled} />
			</div>

			<div className="border-border/60 bg-card/70 space-y-4 rounded-2xl border p-5 shadow-[0_1px_2px_rgba(11,42,49,0.04)]">
				<h3 className="text-sm font-semibold">Techniques</h3>
				<div className="space-y-3">
					{TECHNIQUES.map((t) => (
						<div key={t.id} className="border-border/60 bg-card/40 flex items-start justify-between gap-3 rounded-xl border p-3">
							<div className="min-w-0">
								<p className="text-foreground text-sm font-medium">{t.label}</p>
								<p className="text-muted-foreground text-xs">{t.desc}</p>
							</div>
							<Switch
								size="md"
								checked={techniques[t.id] ?? false}
								onCheckedChange={(checked) => setTechniques((prev) => ({ ...prev, [t.id]: checked }))}
							/>
						</div>
					))}
				</div>
			</div>

			<div className="border-border/60 bg-card/70 space-y-3 rounded-2xl border p-5 shadow-[0_1px_2px_rgba(11,42,49,0.04)]">
				<h3 className="text-sm font-semibold">Advanced parameters</h3>
				<div className="grid grid-cols-1 gap-4 md:grid-cols-2">
					<div className="space-y-2">
						<Label htmlFor="hallucControl-strictness">Strictness</Label>
						<select
							id="hallucControl-strictness"
							value={strictness}
							onChange={(e) => setStrictness(e.target.value)}
							className="border-border/60 bg-background h-9 w-full rounded-md border px-3 text-sm"
						>
							{STRICTNESS_OPTIONS.map((s) => (
								<option key={s.value} value={s.value}>
									{s.label}
								</option>
							))}
						</select>
						<p className="text-muted-foreground text-xs">
							How firm the instructions are. High = refuse when there&apos;s no supporting info; Low = polite reminder.
						</p>
					</div>
					<div className="space-y-2">
						<Label htmlFor="hallucControl-tempcap">Temperature cap</Label>
						<Input
							id="hallucControl-tempcap"
							type="number"
							step="0.05"
							min="0"
							max="2"
							value={tempCap}
							onChange={(e) => setTempCap(parseFloat(e.target.value) || 0)}
						/>
						<p className="text-muted-foreground text-xs">
							Only used when &quot;Reduce randomness&quot; is on. Anything above this value gets capped down.
						</p>
					</div>
				</div>
			</div>

			<div className="border-border/60 bg-card/70 space-y-3 rounded-2xl border p-5 shadow-[0_1px_2px_rgba(11,42,49,0.04)]">
				<div className="flex items-baseline justify-between gap-2">
					<h3 className="text-sm font-semibold">Apply to virtual keys</h3>
					<span className="text-muted-foreground text-[10px]">
						{vkScope.length === 0 ? `Applies to all VKs (${vkOptions.length})` : `Applies to ${vkScope.length} of ${vkOptions.length} VKs`}
					</span>
				</div>
				<p className="text-muted-foreground text-xs">
					Leave empty to apply these techniques to every API key. Pick one or more to limit them to those keys - useful for testing before
					rolling out widely.
				</p>
				<MultiSelect
					options={vkOptions}
					defaultValue={vkScope}
					onValueChange={setVkScope}
					placeholder="All virtual keys"
					maxCount={4}
					searchable={vkOptions.length > 6}
					hideSelectAll={false}
					className="w-full"
				/>
			</div>

			<div className="flex justify-end gap-2 pt-2">
				<Button size="sm" onClick={handleSave} disabled={busy || loading}>
					{busy ? (
						<>
							<Loader2 className="h-3.5 w-3.5 animate-spin" />
							Saving...
						</>
					) : (
						<>
							<ShieldCheck className="h-3.5 w-3.5" />
							Save
						</>
					)}
				</Button>
			</div>
		</div>
	);
}
