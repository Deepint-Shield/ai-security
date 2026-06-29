"use client";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { MultiSelect } from "@/components/ui/multiSelect";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { getErrorMessage, useCreatePluginMutation, useGetPluginsQuery, useGetProvidersQuery, useGetVirtualKeysQuery, useUpdatePluginMutation } from "@/lib/store";
import { CacheConfig, ModelProviderName } from "@/lib/types/config";
import { SEMANTIC_CACHE_PLUGIN } from "@/lib/types/plugins";
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib";
import {
	Boxes,
	Brain,
	BrainCircuit,
	Check,
	ChevronDown,
	Database,
	GitBranch,
	KeySquare,
	Layers,
	Loader2,
			Plus,
	Rocket,
			Server,
	ShieldCheck,
		Wrench,
	Zap,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

// HuggingFace embedding-model menu shown in the cache-config sheet. Ordered
// lightest -> highest quality so the dropdown reads top-down by cost. Latency
// figures are CPU-only, single-text, on the local deepintshield_models sidecar
// (BGE family + MiniLM, batch size 1, max 256 tokens). Wall-clock will be
// lower on GPU and higher under concurrent load.
const EMBEDDING_MODEL_OPTIONS = [
	{
		value: "sentence-transformers/all-MiniLM-L6-v2",
		label: "MiniLM-L6-v2 (lightest)",
		dimension: 384,
		latencyHint: "~3-5 ms · 384-dim",
	},
	{
		value: "BAAI/bge-small-en-v1.5",
		label: "BGE-small EN v1.5",
		dimension: 384,
		latencyHint: "~5-8 ms · 384-dim",
	},
	{
		value: "BAAI/bge-base-en-v1.5",
		label: "BGE-base EN v1.5 (balanced)",
		dimension: 768,
		latencyHint: "~10-15 ms · 768-dim",
	},
	{
		value: "BAAI/bge-large-en-v1.5",
		label: "BGE-large EN v1.5 (optimal)",
		dimension: 1024,
		latencyHint: "~25-40 ms · 1024-dim",
	},
] as const;

const DEFAULT_EMBEDDING_MODEL = EMBEDDING_MODEL_OPTIONS[2].value; // BGE-base, balanced default

// VK-routed embedding models - used when the operator picks "Workspace VK"
// instead of the local huggingface sidecar. Each option is keyed by the
// provider's model name; the gateway routes through the selected VK's
// API key at request time. Listed cheapest first so the dropdown reads
// top-down by cost.
const EMBEDDING_VIA_VK_MODEL_OPTIONS = [
	{
		value: "text-embedding-3-small",
		provider: "openai",
		label: "OpenAI text-embedding-3-small (cheapest)",
		dimension: 1536,
		costHint: "~$0.02 / 1M tokens · 1536-dim",
	},
	{
		value: "text-embedding-3-large",
		provider: "openai",
		label: "OpenAI text-embedding-3-large (higher quality)",
		dimension: 3072,
		costHint: "~$0.13 / 1M tokens · 3072-dim",
	},
	{
		value: "text-embedding-004",
		provider: "gemini",
		label: "Gemini text-embedding-004",
		dimension: 768,
		costHint: "Free up to 1500 RPM · 768-dim",
	},
] as const;
const DEFAULT_EMBEDDING_VIA_VK_MODEL = EMBEDDING_VIA_VK_MODEL_OPTIONS[0].value;

// RECOMMENDED cost-optimization preset - every fresh workspace ships with these
// values via seedRecommendedPlugins in deepintshield_server/transports/
// deepintshield-http/handlers/workspace.go:recommendedSemanticCacheDefaults.
// Keep this object in sync with that map; both sides MUST agree on the same
// numbers or operators get surprises when they tweak one knob in the UI and
// the seed for the next workspace they create still uses old values.
//
// Every technique here is safe-on-by-default:
//   - cache misses + async-first paths fail open (no added wall-clock latency)
//   - sidecar errors fail open (request goes through untouched)
//   - drift samplers (1% each) keep an audit trail of un-optimized traffic so
//     operators can A/B against the baseline if quality dips
//
// Cascade routing stays OFF by default because the operator must first
// pick the cheap/mid/premium VK tiers in the UI before the router has
// anything to dispatch to.
const defaultCacheConfig: CacheConfig = {
	// ── Semantic Cache ────────────────────────────────────────────
	// Embeddings route through a workspace VK (LLM provider); `provider` follows
	// the chosen embedding VK. Default to openai until one is selected.
	provider: "openai" as ModelProviderName,
	keys: [],
	embedding_model: DEFAULT_EMBEDDING_MODEL,
	dimension: 0,
	ttl_seconds: 3600, // 1h - covers typical "what did the user just ask" windows
	threshold: 0.70, // 0.70 hits ~30% more paraphrased queries vs 0.75
	conversation_history_threshold: 3,
	exclude_system_prompt: false,
	cache_by_model: false, // share buckets across model tiers (gpt-4o + gpt-4o-mini)
	cache_by_provider: true,
	auto_scope_enabled: true,
	auto_scope_mode: "conservative",
	shared_vk_policy: "exact_only_when_unscoped",
	scope_signal_order: ["governance_user_id", "request_user", "metadata.cache_scope", "metadata.use_case", "responses_conversation", "session_id"],
	metadata_scope_keys: ["cache_scope", "use_case"],
	// Optional: route embedding calls through a workspace VK instead of the
	// local huggingface sidecar. When embedding_via_vk_enabled, the server
	// resolves the VK's API key at request time and POSTs to the chosen
	// provider's embedding endpoint (e.g. openai text-embedding-3-small).
	embedding_via_vk_enabled: true,
	embedding_vk_id: "",
	embedding_via_vk_model: "text-embedding-3-small",

	// ── Provider Prompt Caching ───────────────────────────────────
	prompt_cache_enabled: true,
	prompt_cache_providers: ["anthropic", "openai", "bedrock", "google"],
	prompt_cache_anthropic_ttl: "5m",
	prompt_cache_google_ttl: "1h",
	prompt_cache_min_static_tokens: 1024,
	prompt_cache_breakpoints: ["system", "tools"],

	// ── Coalescing + Guardrail Cache (pure-win) ───────────────────
	coalescing_enabled: true,
	coalescing_max_in_flight: 1000,
	coalescing_wait_timeout_ms: 30000,
	guardrail_cache_enabled: true,
	guardrail_cache_ttl_seconds: 3600,
	guardrail_cache_max_entries: 10000,
};

const PROMPT_CACHE_PROVIDER_OPTIONS = [
	{ value: "anthropic", label: "Anthropic" },
	{ value: "openai", label: "OpenAI" },
	{ value: "bedrock", label: "Amazon Bedrock" },
	{ value: "google", label: "Google (Gemini)" },
];

const PROMPT_CACHE_BREAKPOINT_OPTIONS = [
	{ value: "system", label: "System message" },
	{ value: "tools", label: "Tool definitions" },
	{ value: "large_blocks", label: "Large user/assistant blocks (≥ 4096 tokens)" },
];

interface PluginsFormProps {
	isVectorStoreEnabled: boolean;
}

export default function PluginsForm({ isVectorStoreEnabled }: PluginsFormProps) {
	const hasSettingsUpdateAccess = useRbac(RbacResource.Settings, RbacOperation.Update);
	const [cacheConfig, setCacheConfig] = useState<CacheConfig>(defaultCacheConfig);
	const [originalCacheEnabled, setOriginalCacheEnabled] = useState<boolean>(true);
	const [serverCacheConfig, setServerCacheConfig] = useState<CacheConfig>(defaultCacheConfig);
	const [serverCacheEnabled, setServerCacheEnabled] = useState<boolean>(false);
	const [savedDialogOpen, setSavedDialogOpen] = useState<boolean>(false);

	// Revalidate on mount so the "requires a provider" warning + the semantic-cache
	// gate reflect real config, not a stale/empty cross-session cache snapshot
	// (see persistence.ts) - otherwise the warning shows despite a configured provider.
	const { data: providersData, error: providersError, isLoading: providersLoading } = useGetProvidersQuery(undefined, {
		refetchOnMountOrArgChange: true,
	});
	// Virtual keys feed the per-feature "Apply to specific VKs" multi-select on
	// each routing/cache card. Empty selection = apply to all VKs (default).
	const { data: virtualKeysData } = useGetVirtualKeysQuery({}, { refetchOnMountOrArgChange: true });
	const vkOptions = useMemo(
		() =>
			(virtualKeysData?.virtual_keys || []).map((vk) => ({
				value: vk.id,
				label: vk.name || vk.id,
			})),
		[virtualKeysData],
	);

	const virtualKeys = useMemo(() => virtualKeysData?.virtual_keys || [], [virtualKeysData]);

	const providers = useMemo(() => providersData || [], [providersData]);

	// Semantic-cache embeddings always route through a workspace virtual key (the
	// local Hugging Face sidecar path was removed). The embedding-model dropdown is
	// derived strictly from the selected VK: every embedding-capable model
	// configured on that VK's provider keys, with a curated per-provider fallback.
	const embeddingModelsForVK = (vkId: string | undefined) => {
		const vk = virtualKeys.find((v) => v.id === vkId) ?? null;
		const provs = new Set((vk?.provider_configs || []).map((pc) => String(pc.provider).toLowerCase()));
		const seen = new Set<string>();
		const out: { value: string; provider: string; label: string; dimension: number; costHint: string }[] = [];
		for (const prov of providers) {
			const pname = String(prov.name).toLowerCase();
			if (provs.size > 0 && !provs.has(pname)) continue;
			for (const k of prov.keys || []) {
				for (const m of k.models || []) {
					const model = String(m);
					if (!/embed/i.test(model) || seen.has(model)) continue;
					seen.add(model);
					const known = EMBEDDING_VIA_VK_MODEL_OPTIONS.find((o) => o.value === model);
					out.push({ value: model, provider: pname, label: known?.label ?? model, dimension: known?.dimension ?? 0, costHint: known?.costHint ?? "" });
				}
			}
		}
		if (out.length > 0) return out;
		const fb = provs.size === 0 ? EMBEDDING_VIA_VK_MODEL_OPTIONS : EMBEDDING_VIA_VK_MODEL_OPTIONS.filter((o) => provs.has(o.provider));
		return fb.map((o) => ({ value: o.value, provider: o.provider, label: o.label, dimension: o.dimension, costHint: o.costHint }));
	};
	const embeddingModelOptions = useMemo(
		// eslint-disable-next-line react-hooks/exhaustive-deps
		() => embeddingModelsForVK(cacheConfig.embedding_vk_id),
		[providers, virtualKeys, cacheConfig.embedding_vk_id],
	);

	useEffect(() => {
		if (providersError) {
			toast.error(`Failed to load providers: ${getErrorMessage(providersError as any)}`);
		}
	}, [providersError]);

	// RTK Query hooks. Revalidate on mount so a hard refresh reflects server
	// truth instead of a stale cross-session cache snapshot (see persistence.ts).
	const { data: plugins, isLoading: loading } = useGetPluginsQuery(undefined, { refetchOnMountOrArgChange: true });
	const [updatePlugin, { isLoading: isUpdating }] = useUpdatePluginMutation();
	const [createPlugin, { isLoading: isCreating }] = useCreatePluginMutation();

	// Get semantic cache plugin and its config
	const semanticCachePlugin = useMemo(() => plugins?.find((plugin) => plugin.name === SEMANTIC_CACHE_PLUGIN), [plugins]);

	const isSemanticCacheEnabled = Boolean(semanticCachePlugin?.enabled);

	// Initialize cache config from plugin data
	useEffect(() => {
		if (semanticCachePlugin?.config) {
			const config = { ...defaultCacheConfig, ...semanticCachePlugin.config };
			setCacheConfig(config);
			setServerCacheConfig(config);
			setOriginalCacheEnabled(semanticCachePlugin.enabled);
			setServerCacheEnabled(semanticCachePlugin.enabled);
		}
	}, [semanticCachePlugin]);

	// Embeddings always route through a workspace virtual key, so keep the
	// VK-routing flag on; the cache provider follows the selected VK below.
	useEffect(() => {
		if (cacheConfig.embedding_via_vk_enabled !== true) {
			setCacheConfig((prev) => ({ ...prev, embedding_via_vk_enabled: true }));
		}
	}, [cacheConfig.embedding_via_vk_enabled]);

	const hasChanges = useMemo(() => {
		if (originalCacheEnabled !== serverCacheEnabled) return true;

		return (
			cacheConfig.provider !== serverCacheConfig.provider ||
			cacheConfig.embedding_model !== serverCacheConfig.embedding_model ||
			cacheConfig.dimension !== serverCacheConfig.dimension ||
			cacheConfig.ttl_seconds !== serverCacheConfig.ttl_seconds ||
			cacheConfig.threshold !== serverCacheConfig.threshold ||
			cacheConfig.conversation_history_threshold !== serverCacheConfig.conversation_history_threshold ||
			cacheConfig.exclude_system_prompt !== serverCacheConfig.exclude_system_prompt ||
			cacheConfig.cache_by_model !== serverCacheConfig.cache_by_model ||
			cacheConfig.cache_by_provider !== serverCacheConfig.cache_by_provider ||
			cacheConfig.auto_scope_enabled !== serverCacheConfig.auto_scope_enabled ||
			cacheConfig.auto_scope_mode !== serverCacheConfig.auto_scope_mode ||
			cacheConfig.shared_vk_policy !== serverCacheConfig.shared_vk_policy ||
			JSON.stringify(cacheConfig.scope_signal_order || []) !== JSON.stringify(serverCacheConfig.scope_signal_order || []) ||
			JSON.stringify(cacheConfig.metadata_scope_keys || []) !== JSON.stringify(serverCacheConfig.metadata_scope_keys || []) ||
			cacheConfig.prompt_cache_enabled !== serverCacheConfig.prompt_cache_enabled ||
			cacheConfig.prompt_cache_anthropic_ttl !== serverCacheConfig.prompt_cache_anthropic_ttl ||
			cacheConfig.prompt_cache_google_ttl !== serverCacheConfig.prompt_cache_google_ttl ||
			cacheConfig.prompt_cache_min_static_tokens !== serverCacheConfig.prompt_cache_min_static_tokens ||
			JSON.stringify(cacheConfig.prompt_cache_providers || []) !== JSON.stringify(serverCacheConfig.prompt_cache_providers || []) ||
			JSON.stringify(cacheConfig.prompt_cache_breakpoints || []) !== JSON.stringify(serverCacheConfig.prompt_cache_breakpoints || []) ||
			cacheConfig.coalescing_enabled !== serverCacheConfig.coalescing_enabled ||
			cacheConfig.coalescing_max_in_flight !== serverCacheConfig.coalescing_max_in_flight ||
			cacheConfig.coalescing_wait_timeout_ms !== serverCacheConfig.coalescing_wait_timeout_ms ||
			JSON.stringify(cacheConfig.coalescing_vk_scope || []) !== JSON.stringify(serverCacheConfig.coalescing_vk_scope || []) ||
			JSON.stringify(cacheConfig.semantic_cache_vk_scope || []) !== JSON.stringify(serverCacheConfig.semantic_cache_vk_scope || []) ||
			JSON.stringify(cacheConfig.prompt_cache_vk_scope || []) !== JSON.stringify(serverCacheConfig.prompt_cache_vk_scope || []) ||
			JSON.stringify(cacheConfig.guardrail_cache_vk_scope || []) !== JSON.stringify(serverCacheConfig.guardrail_cache_vk_scope || []) ||
			JSON.stringify(cacheConfig.mcp_tool_ttls || {}) !== JSON.stringify(serverCacheConfig.mcp_tool_ttls || {}) ||
			cacheConfig.guardrail_cache_enabled !== serverCacheConfig.guardrail_cache_enabled ||
			cacheConfig.guardrail_cache_ttl_seconds !== serverCacheConfig.guardrail_cache_ttl_seconds ||
			cacheConfig.guardrail_cache_max_entries !== serverCacheConfig.guardrail_cache_max_entries ||
			// Embedding-via-VK comparisons. Without these the Save button stays
			// disabled even after the operator edits one of these fields, because
			// hasChanges short-circuits to false.
			cacheConfig.embedding_via_vk_enabled !== serverCacheConfig.embedding_via_vk_enabled ||
			cacheConfig.embedding_vk_id !== serverCacheConfig.embedding_vk_id ||
			cacheConfig.embedding_via_vk_model !== serverCacheConfig.embedding_via_vk_model
		);
	}, [cacheConfig, serverCacheConfig, originalCacheEnabled, serverCacheEnabled]);

	// Handle semantic cache toggle (create or update)
	const handleSemanticCacheToggle = (enabled: boolean) => {
		setOriginalCacheEnabled(enabled);
	};

	// Update cache config locally
	const updateCacheConfigLocal = (updates: Partial<CacheConfig>) => {
		setCacheConfig((prev) => ({ ...prev, ...updates }));
	};

	// Save all changes. The semantic_cache plugin is shipped with default
	// config from config.json and bootstraps into the configstore on first
	// gateway start - so by the time a user reaches this page the row already
	// exists in DB even though the cached `plugins` list may not have surfaced
	// it yet (stale RTK Query cache, or list endpoint returned an empty
	// runtime view). Trying create-first and falling back to update on 409
	// was racy; instead, try update-first and fall back to create only on a
	// real 404 (plugin genuinely not in DB).
	const handleSave = async () => {
		const isNotFound = (err: unknown) => {
			const status = (err as { status?: number } | undefined)?.status;
			return status === 404;
		};
		const isConflict = (err: unknown) => {
			const status = (err as { status?: number } | undefined)?.status;
			return status === 409;
		};

		try {
			try {
				await updatePlugin({
					name: SEMANTIC_CACHE_PLUGIN,
					data: { enabled: originalCacheEnabled, config: cacheConfig },
				}).unwrap();
			} catch (err) {
				if (!isNotFound(err)) throw err;
				// Plugin really doesn't exist in DB yet - create it.
				try {
					await createPlugin({
						name: SEMANTIC_CACHE_PLUGIN,
						enabled: originalCacheEnabled,
						config: cacheConfig,
						path: "",
					}).unwrap();
				} catch (createErr) {
					// Race: another tab created it between our update and create.
					// Retry the update once before giving up.
					if (isConflict(createErr)) {
						await updatePlugin({
							name: SEMANTIC_CACHE_PLUGIN,
							data: { enabled: originalCacheEnabled, config: cacheConfig },
						}).unwrap();
					} else {
						throw createErr;
					}
				}
			}
			setServerCacheConfig(cacheConfig);
			setServerCacheEnabled(originalCacheEnabled);
			setSavedDialogOpen(true);
		} catch (error) {
			const errorMessage = getErrorMessage(error);
			toast.error(`Failed to update plugin configuration: ${errorMessage}`);
		}
	};

	if (loading) {
		return (
			<Card>
				<CardContent className="p-6">
					<div className="text-muted-foreground">Loading plugins configuration...</div>
				</CardContent>
			</Card>
		);
	}

	// The two top-level techniques are independent: prompt cache works without
	// semantic cache (it just trims provider input tokens) and vice versa.
	// We surface each as its own tab with a master switch up top and the
	// detailed parameters collapsed under "Advanced".
	const semanticEnabled = originalCacheEnabled && isVectorStoreEnabled;
	const promptCacheEnabled = cacheConfig.prompt_cache_enabled ?? true;
	const semanticCacheBlocked = !isVectorStoreEnabled || providersLoading || providers.length === 0;
	const savingsBusy = isUpdating || isCreating;

	// Per-tab enablement signal - drives the small status dot on each tab
	// trigger so operators can see at a glance which techniques are running
	// without having to click through every tab.
	const tabOn: Record<string, boolean> = {
		"caches":
			promptCacheEnabled ||
			semanticEnabled ||
			Boolean(cacheConfig.mcp_tool_ttls && Object.keys(cacheConfig.mcp_tool_ttls).length > 0) ||
			(cacheConfig.guardrail_cache_enabled ?? true),
	};

	return (
		<div className="space-y-4">
			{/* Sticky action bar - keeps Save accessible regardless of which tab is open. */}
			<div className="sticky top-0 z-20 flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-border/60 bg-card px-4 py-2.5">
				<div className="flex items-center gap-2 text-xs">
					{savingsBusy ? (
						<>
							<Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
							<span className="text-muted-foreground">Saving changes…</span>
						</>
					) : hasChanges ? (
						<>
							<span className="relative flex h-2 w-2">
								<span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-amber-500/60" />
								<span className="relative inline-flex h-2 w-2 rounded-full bg-amber-500" />
							</span>
							<span className="font-medium text-foreground">Unsaved changes</span>
							<span className="text-muted-foreground">- review the toggle highlighted in the active tab.</span>
						</>
					) : (
						<>
							<Check className="h-3.5 w-3.5 text-emerald-500" />
							<span className="text-muted-foreground">All changes saved.</span>
						</>
					)}
				</div>
				<Button onClick={handleSave} disabled={!hasChanges || savingsBusy || !hasSettingsUpdateAccess} size="sm">
					{savingsBusy ? (
						<>
							<Loader2 className="h-3.5 w-3.5 animate-spin" />
							Saving…
						</>
					) : (
						"Save changes"
					)}
				</Button>
			</div>

			<Tabs defaultValue="caches" className="w-full">
				<TabsList className="w-full justify-start gap-1 rounded-2xl border border-border/60 bg-card p-1.5">
					<CostTabTrigger value="caches" testId="cost-tab-caches" icon={<Layers className="h-3.5 w-3.5" />} label="Caches" on={tabOn["caches"]} />
				</TabsList>

				{/* Prompt Cache + Semantic Cache moved into the Caches tab so all
				    cache-related surfaces sit in one place. See TabsContent
				    value="caches" below. */}

				{/* ──────────────────────── ROUTING ──────────────────────── */}

				{/* ──────────────────────── CACHES (all layers) ──────────────────────── */}
				<TabsContent value="caches" className="space-y-4">
					{/* <p className="text-muted-foreground text-xs">All cache layers in one place: provider prompt cache (KV reuse at the model), semantic (Redis-backed cosine match), MCP tool output, and guardrail decision reuse. Lock-free reads on the hot path; per-VK partitioned - never crosses tenants.</p> */}

					{/* 1. Provider Prompt Caching */}
					<SectionCard
						title="Provider Prompt Caching"
						enabled={promptCacheEnabled}
						onToggle={(checked) => updateCacheConfigLocal({ prompt_cache_enabled: checked })}
						badge="Recommended"
						icon={<Server className="h-4 w-4" />}
					>
						{/* Provider chips are surfaced at the top level - small, scannable, primary control. */}
						<div className="space-y-2">
							<Label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Providers</Label>
							<div className="flex flex-wrap gap-2">
								{PROMPT_CACHE_PROVIDER_OPTIONS.map((option) => {
									const selected = (cacheConfig.prompt_cache_providers || []).includes(option.value);
									return (
										<ChipToggle
											key={option.value}
											selected={selected}
											disabled={!promptCacheEnabled}
											label={option.label}
											onClick={() => {
												const current = cacheConfig.prompt_cache_providers || [];
												const next = current.includes(option.value)
													? current.filter((v) => v !== option.value)
													: [...current, option.value];
												updateCacheConfigLocal({ prompt_cache_providers: next });
											}}
										/>
									);
								})}
							</div>
							{/* <p className="text-muted-foreground text-xs">
								Selected providers keep their cache hints; others are stripped before forwarding.
							</p> */}
						</div>

						<AdvancedDisclosure label="Advanced parameters">
							<div className="grid grid-cols-1 gap-4 md:grid-cols-3">
								<div className="space-y-2">
									<Label htmlFor="prompt_cache_anthropic_ttl">Anthropic Cache TTL</Label>
									<Select
										value={cacheConfig.prompt_cache_anthropic_ttl || "5m"}
										onValueChange={(value) =>
											updateCacheConfigLocal({ prompt_cache_anthropic_ttl: value as "5m" | "1h" })
										}
									>
										<SelectTrigger className="w-full">
											<SelectValue placeholder="Select TTL" />
										</SelectTrigger>
										<SelectContent>
											<SelectItem value="5m">5 minutes (default)</SelectItem>
											<SelectItem value="1h">1 hour (2× write premium)</SelectItem>
										</SelectContent>
									</Select>
									<p className="text-muted-foreground text-xs">Best for slow, repetitive traffic.</p>
								</div>

								<div className="space-y-2">
									<Label htmlFor="prompt_cache_google_ttl">Gemini Cache TTL</Label>
									<Select
										value={cacheConfig.prompt_cache_google_ttl || "1h"}
										onValueChange={(value) =>
											updateCacheConfigLocal({ prompt_cache_google_ttl: value as "5m" | "1h" | "6h" | "24h" })
										}
									>
										<SelectTrigger className="w-full">
											<SelectValue placeholder="Select TTL" />
										</SelectTrigger>
										<SelectContent>
											<SelectItem value="5m">5 minutes</SelectItem>
											<SelectItem value="1h">1 hour (default)</SelectItem>
											<SelectItem value="6h">6 hours</SelectItem>
											<SelectItem value="24h">24 hours</SelectItem>
										</SelectContent>
									</Select>
									<p className="text-muted-foreground text-xs">How long cached prefixes stay valid. Longer means more reuse needed to be worth it.</p>
								</div>

								<div className="space-y-2">
									<Label htmlFor="prompt_cache_min_static_tokens">Min Static Prefix (tokens)</Label>
									<Input
										id="prompt_cache_min_static_tokens"
										type="number"
										min="0"
										value={cacheConfig.prompt_cache_min_static_tokens ?? 1024}
										onChange={(e) => {
											const parsed = parseInt(e.target.value);
											if (!Number.isNaN(parsed)) {
												updateCacheConfigLocal({ prompt_cache_min_static_tokens: parsed });
											}
										}}
									/>
									{/* <p className="text-muted-foreground text-xs">OpenAI min is 1024; Gemini caching is only profitable above ~32K.</p> */}
								</div>
							</div>

							<div className="space-y-2">
								<Label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Cache Breakpoints</Label>
								<div className="flex flex-wrap gap-2">
									{PROMPT_CACHE_BREAKPOINT_OPTIONS.map((option) => {
										const selected = (cacheConfig.prompt_cache_breakpoints || []).includes(option.value);
										return (
											<ChipToggle
												key={option.value}
												selected={selected}
												label={option.label}
												onClick={() => {
													const current = cacheConfig.prompt_cache_breakpoints || [];
													const next = current.includes(option.value)
														? current.filter((v) => v !== option.value)
														: [...current, option.value];
													updateCacheConfigLocal({ prompt_cache_breakpoints: next });
												}}
											/>
										);
									})}
								</div>
								{/* <p className="text-muted-foreground text-xs">Which static portions of the prompt the SDK marks as cacheable.</p> */}
							</div>
						</AdvancedDisclosure>
						<VKScopeField
							label="Apply to virtual keys"
							options={vkOptions}
							value={cacheConfig.prompt_cache_vk_scope || []}
							onChange={(next) => updateCacheConfigLocal({ prompt_cache_vk_scope: next })}
						/>
					</SectionCard>

					{/* 2. Semantic Cache */}
					<SectionCard
						title="Semantic Caching"
						enabled={semanticEnabled}
						onToggle={(checked) => {
							if (isVectorStoreEnabled) handleSemanticCacheToggle(checked);
						}}
						disabled={semanticCacheBlocked}
						icon={<Brain className="h-4 w-4" />}
						disabledHint={
							!isVectorStoreEnabled ? (
								<span className="text-destructive font-medium">Requires vector store to be configured and enabled in config.json.</span>
							) : !providersLoading && providers.length === 0 ? (
								<span className="text-destructive font-medium">Requires at least one provider to be configured.</span>
							) : null
						}
					>
						{semanticEnabled && providersLoading ? (
							<div className="flex items-center justify-center py-4">
								<Loader2 className="h-4 w-4 animate-spin" />
							</div>
						) : semanticEnabled ? (
							<>
								<div className="grid grid-cols-1 gap-4 md:grid-cols-3">
									<div className="space-y-2">
										<Label htmlFor="embedding_vk_id">Embedding Virtual Key</Label>
										<Select
											value={cacheConfig.embedding_vk_id || ""}
											onValueChange={(value) => {
												// Derive the model list from the chosen VK and snap to a model it can serve.
												const vk = virtualKeys.find((v) => v.id === value) ?? null;
												const primaryProvider = (vk?.provider_configs?.[0]?.provider as ModelProviderName) || cacheConfig.provider;
												const valid = embeddingModelsForVK(value);
												const stillValid = valid.some((o) => o.value === cacheConfig.embedding_via_vk_model);
												const nextModel = stillValid ? cacheConfig.embedding_via_vk_model : (valid[0]?.value ?? DEFAULT_EMBEDDING_VIA_VK_MODEL);
												const nextOpt = valid.find((o) => o.value === nextModel);
												updateCacheConfigLocal({
													embedding_via_vk_enabled: true,
													embedding_vk_id: value,
													embedding_via_vk_model: nextModel,
													provider: primaryProvider,
													...(nextOpt?.dimension ? { dimension: nextOpt.dimension } : {}),
												});
											}}
										>
											<SelectTrigger id="embedding_vk_id" className="w-full">
												<SelectValue placeholder={vkOptions.length === 0 ? "No virtual keys configured" : "Select a virtual key"} />
											</SelectTrigger>
											<SelectContent>
												{vkOptions.map((vk) => (
													<SelectItem key={vk.value} value={vk.value}>
														{vk.label}
													</SelectItem>
												))}
											</SelectContent>
										</Select>
										<p className="text-muted-foreground text-xs">Embeddings are generated through this virtual key&apos;s LLM provider.</p>
									</div>
									<div className="space-y-2">
										<Label htmlFor="embedding_via_vk_model">Embedding Model</Label>
										<Select
											value={cacheConfig.embedding_via_vk_model || ""}
											onValueChange={(value) => {
												const option = embeddingModelOptions.find((o) => o.value === value);
												updateCacheConfigLocal({ embedding_via_vk_model: value, ...(option?.dimension ? { dimension: option.dimension } : {}) });
											}}
										>
											<SelectTrigger id="embedding_via_vk_model" className="w-full">
												<SelectValue placeholder={embeddingModelOptions.length === 0 ? "Select a virtual key first" : "Select embedding model"} />
											</SelectTrigger>
											<SelectContent>
												{embeddingModelOptions.map((opt) => (
													<SelectItem key={opt.value} value={opt.value}>
														<div className="flex flex-col">
															<span>{opt.label}</span>
															{opt.costHint ? <span className="text-muted-foreground text-xs">{opt.costHint}</span> : null}
														</div>
													</SelectItem>
												))}
											</SelectContent>
										</Select>
										<p className="text-muted-foreground text-xs">Populated from the selected virtual key.</p>
									</div>
									<div className="space-y-2">
										<Label htmlFor="threshold">Similarity Threshold</Label>
										<Input
											id="threshold"
											type="number"
											min="0"
											max="1"
											step="0.01"
											value={cacheConfig.threshold === undefined || Number.isNaN(cacheConfig.threshold) ? "" : cacheConfig.threshold}
											onChange={(e) => {
												const value = e.target.value;
												if (value === "") {
													updateCacheConfigLocal({ threshold: undefined });
													return;
												}
												const parsed = parseFloat(value);
												if (!Number.isNaN(parsed)) {
													updateCacheConfigLocal({ threshold: parsed });
												}
											}}
										/>
										<p className="text-muted-foreground text-xs">0.80 is the recommended default.</p>
									</div>
								</div>

								<AdvancedDisclosure label="Advanced parameters">
									<div className="grid grid-cols-1 gap-4 md:grid-cols-3">
										<div className="space-y-2">
											<Label htmlFor="ttl">TTL (seconds)</Label>
											<Input
												id="ttl"
												type="number"
												min="1"
												value={cacheConfig.ttl_seconds === undefined || Number.isNaN(cacheConfig.ttl_seconds) ? "" : cacheConfig.ttl_seconds}
												onChange={(e) => {
													const value = e.target.value;
													if (value === "") {
														updateCacheConfigLocal({ ttl_seconds: undefined });
														return;
													}
													const parsed = parseInt(value);
													if (!Number.isNaN(parsed)) {
														updateCacheConfigLocal({ ttl_seconds: parsed });
													}
												}}
											/>
										</div>
										<div className="space-y-2">
											<Label htmlFor="dimension">Dimension</Label>
											<Input
												id="dimension"
												type="number"
												min="0"
												value={cacheConfig.dimension === undefined || Number.isNaN(cacheConfig.dimension) ? "" : cacheConfig.dimension}
												onChange={(e) => {
													const value = e.target.value;
													if (value === "") {
														updateCacheConfigLocal({ dimension: undefined });
														return;
													}
													const parsed = parseInt(value);
													if (!Number.isNaN(parsed)) {
														updateCacheConfigLocal({ dimension: parsed });
													}
												}}
											/>
										</div>
										<div className="space-y-2">
											<Label htmlFor="conversation_history_threshold">Conversation History Threshold</Label>
											<Input
												id="conversation_history_threshold"
												type="number"
												min="1"
												max="50"
												value={cacheConfig.conversation_history_threshold || 3}
												onChange={(e) => updateCacheConfigLocal({ conversation_history_threshold: parseInt(e.target.value) || 3 })}
											/>
											<p className="text-muted-foreground text-xs">Stop caching once a conversation has more messages than this.</p>
										</div>
									</div>

									<div className="grid grid-cols-1 gap-3 md:grid-cols-3">
										<MiniSwitch
											label="Exclude system prompt"
											description="Don't include system messages when matching cached responses"
											checked={cacheConfig.exclude_system_prompt || false}
											onCheckedChange={(checked) => updateCacheConfigLocal({ exclude_system_prompt: checked })}
										/>
										<MiniSwitch
											label="Cache by model"
											description="Keep separate caches per model"
											checked={cacheConfig.cache_by_model}
											onCheckedChange={(checked) => updateCacheConfigLocal({ cache_by_model: checked })}
										/>
										<MiniSwitch
											label="Cache by provider"
											description="Keep separate caches per provider"
											checked={cacheConfig.cache_by_provider}
											onCheckedChange={(checked) => updateCacheConfigLocal({ cache_by_provider: checked })}
										/>
									</div>

									{/* <div className="space-y-2 pt-2">
										<p className="text-muted-foreground text-xs">
											Every cache entry is anchored on the request&apos;s virtual API key. Settings below sub-partition the cache <em>within</em> a virtual key - never broaden scope to tenant or workspace.
										</p>
									</div> */}

									<div className="grid grid-cols-1 gap-4 md:grid-cols-2">
										<div className="space-y-2">
											<Label htmlFor="auto_scope_mode">Automatic Scope Mode</Label>
											<Select
												value={cacheConfig.auto_scope_mode || "conservative"}
												onValueChange={(value) => updateCacheConfigLocal({ auto_scope_mode: value as CacheConfig["auto_scope_mode"] })}
											>
												<SelectTrigger className="w-full">
													<SelectValue placeholder="Select mode" />
												</SelectTrigger>
												<SelectContent>
													<SelectItem value="conservative">Conservative (default)</SelectItem>
													<SelectItem value="balanced">Balanced</SelectItem>
													<SelectItem value="aggressive">Aggressive</SelectItem>
												</SelectContent>
											</Select>
										</div>
										<div className="space-y-2">
											<Label htmlFor="shared_vk_policy">Shared Virtual Key Policy</Label>
											<Select
												value={cacheConfig.shared_vk_policy || "exact_only_when_unscoped"}
												onValueChange={(value) => updateCacheConfigLocal({ shared_vk_policy: value as CacheConfig["shared_vk_policy"] })}
											>
												<SelectTrigger className="w-full">
													<SelectValue placeholder="Select policy" />
												</SelectTrigger>
												<SelectContent>
													<SelectItem value="exact_only_when_unscoped">Exact only when unscoped</SelectItem>
													<SelectItem value="allow_semantic_when_unscoped">Allow semantic when unscoped</SelectItem>
												</SelectContent>
											</Select>
										</div>
									</div>

									<div className="space-y-2">
										<Label htmlFor="metadata_scope_keys">Metadata Scope Keys</Label>
										<Input
											id="metadata_scope_keys"
											placeholder="cache_scope, use_case"
											value={(cacheConfig.metadata_scope_keys || []).join(", ")}
											onChange={(e) =>
												updateCacheConfigLocal({
													metadata_scope_keys: e.target.value
														.split(",")
														.map((value) => value.trim())
														.filter(Boolean),
												})
											}
										/>
									</div>

									<div className="space-y-2">
										<Label htmlFor="scope_signal_order">Scope Signal Order</Label>
										<Input
											id="scope_signal_order"
											placeholder="governance_user_id, request_user, metadata.cache_scope"
											value={(cacheConfig.scope_signal_order || []).join(", ")}
											onChange={(e) =>
												updateCacheConfigLocal({
													scope_signal_order: e.target.value
														.split(",")
														.map((value) => value.trim())
														.filter(Boolean),
												})
											}
										/>
									</div>

									<MiniSwitch
										label="Automatic cache scope"
										description="Automatically choose how to group cached results - by user, session, metadata, or conversation."
										checked={cacheConfig.auto_scope_enabled ?? true}
										onCheckedChange={(checked) => updateCacheConfigLocal({ auto_scope_enabled: checked })}
									/>
{/* 
									<p className="text-muted-foreground text-xs">
										Embedding provider keys inherit from the main provider configuration. Key rotations take effect immediately - no restart required.
									</p> */}
								</AdvancedDisclosure>
								<VKScopeField
									label="Apply to virtual keys"
									options={vkOptions}
									value={cacheConfig.semantic_cache_vk_scope || []}
									onChange={(next) => updateCacheConfigLocal({ semantic_cache_vk_scope: next })}
								/>
							</>
						) : null}
					</SectionCard>

					{/* 3. Per-Tool MCP TTL */}
					<SectionCard
						title="Per-Tool MCP Cache TTL"
						enabled={!!cacheConfig.mcp_tool_ttls && Object.keys(cacheConfig.mcp_tool_ttls).length > 0}
						onToggle={(checked) => {
							if (!checked) {
								updateCacheConfigLocal({ mcp_tool_ttls: {} });
							} else if (!cacheConfig.mcp_tool_ttls || Object.keys(cacheConfig.mcp_tool_ttls).length === 0) {
								updateCacheConfigLocal({ mcp_tool_ttls: { "example-tool": "1h" } });
							}
						}}
						icon={<Wrench className="h-4 w-4" />}
					>
						<AdvancedDisclosure label="Per-tool TTL overrides">
							<MCPToolTTLEditor
								value={cacheConfig.mcp_tool_ttls || {}}
								onChange={(next) => updateCacheConfigLocal({ mcp_tool_ttls: next })}
							/>
							<p className="text-muted-foreground text-xs">
								Use the fully-qualified tool name <code className="font-mono">&lt;server&gt;-&lt;tool&gt;</code>. Set TTL to <code className="font-mono">0s</code> to disable caching for that tool.
							</p>
						</AdvancedDisclosure>
					</SectionCard>

					{/* 4. Guardrail Evaluation Cache */}
					<SectionCard
						title="Guardrail Evaluation Cache"
						enabled={cacheConfig.guardrail_cache_enabled ?? true}
						onToggle={(checked) => updateCacheConfigLocal({ guardrail_cache_enabled: checked })}
						badge="Recommended"
						icon={<ShieldCheck className="h-4 w-4" />}
					>
						<AdvancedDisclosure label="Advanced parameters">
							<div className="grid grid-cols-1 gap-4 md:grid-cols-2">
								<div className="space-y-2">
									<Label htmlFor="guardrail_cache_ttl_seconds">TTL (seconds)</Label>
									<Input
										id="guardrail_cache_ttl_seconds"
										type="number"
										min="60"
										value={cacheConfig.guardrail_cache_ttl_seconds ?? 3600}
										onChange={(e) => {
											const parsed = parseInt(e.target.value);
											if (!Number.isNaN(parsed)) updateCacheConfigLocal({ guardrail_cache_ttl_seconds: parsed });
										}}
									/>
								</div>
								<div className="space-y-2">
									<Label htmlFor="guardrail_cache_max_entries">Max entries</Label>
									<Input
										id="guardrail_cache_max_entries"
										type="number"
										min="100"
										value={cacheConfig.guardrail_cache_max_entries ?? 10000}
										onChange={(e) => {
											const parsed = parseInt(e.target.value);
											if (!Number.isNaN(parsed)) updateCacheConfigLocal({ guardrail_cache_max_entries: parsed });
										}}
									/>
								</div>
							</div>
							{/* <p className="text-muted-foreground text-xs">
								Cache is automatically invalidated when policy version changes - no manual flush needed.
							</p> */}
						</AdvancedDisclosure>
						<VKScopeField
							label="Apply to virtual keys"
							options={vkOptions}
							value={cacheConfig.guardrail_cache_vk_scope || []}
							onChange={(next) => updateCacheConfigLocal({ guardrail_cache_vk_scope: next })}
						/>
					</SectionCard>
				</TabsContent>

				{/* ──────────────────────── PROMPT OPTIMIZATION ──────────────────────── */}

				{/* ──────────────────────── RAG OPTIMIZATION ──────────────────────── */}

				{/* ──────────────────────── SUMMARIZATION ──────────────────────── */}

				{/* ──────────────────────── PARALLEL TOOLS ──────────────────────── */}

			</Tabs>

			<Dialog open={savedDialogOpen} onOpenChange={setSavedDialogOpen}>
				<DialogContent className="sm:max-w-sm">
					<DialogHeader>
						<DialogTitle>Saved</DialogTitle>
						<DialogDescription>Your Cost Optimization settings have been saved.</DialogDescription>
					</DialogHeader>
					<DialogFooter>
						<Button size="sm" onClick={() => setSavedDialogOpen(false)}>
							Close
						</Button>
					</DialogFooter>
				</DialogContent>
			</Dialog>
		</div>
	);
}

// MCPToolTTLEditor is a small key/value editor for the per-tool TTL map. Keeps
// adding/removing rows lightweight; doesn't need a heavyweight form library
// for what amounts to a `Record<string, string>` shape.
function MCPToolTTLEditor({ value, onChange }: { value: Record<string, string>; onChange: (next: Record<string, string>) => void }) {
	const entries = Object.entries(value);
	return (
		<div className="space-y-2">
			{entries.map(([tool, ttl], idx) => (
				<div key={`${tool}-${idx}`} className="flex items-center gap-2">
					<Input
						value={tool}
						placeholder="server-tool_name"
						className="flex-1 font-mono text-xs"
						onChange={(e) => {
							const next: Record<string, string> = {};
							entries.forEach(([k, v], i) => {
								if (i === idx) next[e.target.value] = v;
								else next[k] = v;
							});
							onChange(next);
						}}
					/>
					<Input
						value={ttl}
						placeholder="1h, 30s, 0s"
						className="w-24 font-mono text-xs"
						onChange={(e) => {
							onChange({ ...value, [tool]: e.target.value });
						}}
					/>
					<Button
						variant="ghost"
						size="sm"
						className="h-8 px-2 text-xs text-muted-foreground hover:text-destructive"
						onClick={() => {
							const next = { ...value };
							delete next[tool];
							onChange(next);
						}}
					>
						Remove
					</Button>
				</div>
			))}
			<Button
				variant="outline"
				size="sm"
				className="h-8 text-xs"
				onClick={() => {
					let n = 1;
					while (value[`new-tool-${n}`] !== undefined) n++;
					onChange({ ...value, [`new-tool-${n}`]: "1h" });
				}}
			>
				+ Add tool override
			</Button>
		</div>
	);
}

// ──────────────────────────────────────────────────────────────────────────────
// Small layout primitives used across both cost-optimization tabs. Defined in
// this file because they're not reused elsewhere and they share state-shape
// assumptions with the parent form.
// ──────────────────────────────────────────────────────────────────────────────

// ChipToggle is the multi-select pill used across all three chip groups
// (prompt-cache providers, prompt-cache breakpoints, batch-routing providers).
// Selected state shows a check icon + filled primary tint; unselected shows
// a plus icon hint + muted outline. The visual contrast solves the "which
// chips am I actually on?" question without needing a separate legend.
// CostTabTrigger keeps each tab trigger identical - same paddings, same
// active-state colors - and adds a small dot that lights up green when the
// feature(s) on that tab are enabled. Lets operators scan the tab strip
// without having to click through every tab to inspect each toggle.
function CostTabTrigger({
	value,
	testId,
	icon,
	label,
	on,
}: {
	value: string;
	testId: string;
	icon: React.ReactNode;
	label: string;
	on: boolean;
}) {
	return (
		<TabsTrigger
			value={value}
			data-testid={testId}
			className="gap-1.5 rounded-xl px-3 py-1.5 text-xs font-medium data-[state=active]:bg-primary/10 data-[state=active]:text-primary"
		>
			{icon}
			{label}
			<span
				aria-hidden
				className={`ml-0.5 inline-block h-1.5 w-1.5 rounded-full transition-colors ${
					on ? "bg-emerald-500 shadow-[0_0_0_2px_rgba(16,185,129,0.18)]" : "bg-muted-foreground/25"
				}`}
			/>
		</TabsTrigger>
	);
}

function ChipToggle({
	selected,
	label,
	onClick,
	disabled,
}: {
	selected: boolean;
	label: string;
	onClick: () => void;
	disabled?: boolean;
}) {
	return (
		<button
			type="button"
			role="checkbox"
			aria-checked={selected}
			disabled={disabled}
			onClick={onClick}
			className={`group inline-flex cursor-pointer items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
				selected
					? "border-primary/70 bg-primary/15 text-primary hover:bg-primary/20"
					: "border-border/70 bg-background/60 text-muted-foreground hover:border-primary/40 hover:text-foreground"
			}`}
		>
			{selected ? <Check className="h-3 w-3" /> : <Plus className="h-3 w-3 opacity-50 group-hover:opacity-80" />}
			{label}
		</button>
	);
}

// VKScopeField wraps the existing MultiSelect with copy + empty-state hint
// tailored for "apply this feature to a subset of virtual keys". Used on
// every routing/cache card that exposes a *_vk_scope field. An empty selection
// means "apply to all VKs" - the field describes this explicitly so operators
// don't have to learn the convention from documentation.
function VKScopeField({
	label,
	options,
	value,
	onChange,
}: {
	label: string;
	options: { value: string; label: string }[];
	value: string[];
	onChange: (next: string[]) => void;
}) {
	const allCount = options.length;
	const selectedCount = value.length;
	return (
		<div className="space-y-2 border-t border-border/40 pt-3">
			<div className="flex items-baseline justify-between gap-2">
				<Label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">{label}</Label>
				<span className="text-[10px] text-muted-foreground">
					{selectedCount === 0
						? `Applies to all VKs (${allCount})`
						: `Applies to ${selectedCount} of ${allCount} VKs`}
				</span>
			</div>
			<MultiSelect
				options={options}
				defaultValue={value}
				onValueChange={onChange}
				placeholder="All virtual keys"
				maxCount={3}
				searchable={options.length > 6}
				hideSelectAll={false}
				className="w-full"
			/>
			{/* <p className="text-muted-foreground text-xs">
				Leave empty to apply this feature to every VK. Pick one or more to limit it to those VKs only.
			</p> */}
		</div>
	);
}

function SectionCard({
	title,
	enabled,
	onToggle,
	disabled,
	disabledHint,
	badge,
	icon,
	children,
}: {
	title: string;
	// description is accepted for source-doc readability at the call sites but
	// not rendered on the card. Optional so callers can omit it freely.
	description?: string;
	enabled: boolean;
	onToggle: (next: boolean) => void;
	disabled?: boolean;
	disabledHint?: React.ReactNode;
	badge?: string;
	icon?: React.ReactNode;
	children?: React.ReactNode;
}) {
	return (
		<div
			className={`group relative rounded-2xl border bg-card p-5 transition-colors ${
				enabled ? "border-primary/30" : "border-border/60"
			} ${disabled ? "opacity-70" : ""}`}
		>
			<div className="flex items-center justify-between gap-4">
				<div className="flex flex-1 items-center gap-3">
					{icon ? (
						<div
							className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border transition-colors ${
								enabled
									? "border-primary/40 bg-primary/10 text-primary"
									: "border-border/60 bg-muted/40 text-muted-foreground"
							}`}
						>
							{icon}
						</div>
					) : null}
					<div className="flex flex-wrap items-center gap-2">
						<h3 className="text-sm font-semibold leading-none">{title}</h3>
						{badge ? (
							<span className="rounded-full border border-primary/40 bg-primary/10 px-2 py-0.5 text-[10px] font-medium text-primary uppercase tracking-wider">
								{badge}
							</span>
						) : null}
						{disabledHint ? <p className="basis-full pt-1 text-xs">{disabledHint}</p> : null}
					</div>
				</div>
				<Switch size="md" checked={enabled} disabled={disabled} onCheckedChange={onToggle} />
			</div>
			{enabled && children ? <div className="mt-4 space-y-4 border-t border-border/40 pt-4">{children}</div> : null}
		</div>
	);
}

function AdvancedDisclosure({ label, children }: { label: string; children: React.ReactNode }) {
	const [open, setOpen] = useState(false);
	return (
		<Collapsible open={open} onOpenChange={setOpen}>
			<CollapsibleTrigger
				className={`group flex w-full items-center justify-between gap-2 rounded-xl border bg-card/40 px-3.5 py-2 text-xs font-medium transition-all hover:bg-card/70 ${
					open ? "border-primary/30 text-foreground" : "border-border/60 text-muted-foreground hover:text-foreground"
				}`}
			>
				<span className="inline-flex items-center gap-2">
					<span
						aria-hidden
						className={`inline-flex h-5 w-5 items-center justify-center rounded-md transition-colors ${
							open ? "bg-primary/10 text-primary" : "bg-muted/50 text-muted-foreground group-hover:bg-muted"
						}`}
					>
						<Wrench className="h-3 w-3" />
					</span>
					{label}
				</span>
				<ChevronDown className={`h-4 w-4 transition-transform ${open ? "rotate-180" : ""}`} />
			</CollapsibleTrigger>
			<CollapsibleContent className="space-y-4 pt-4">{children}</CollapsibleContent>
		</Collapsible>
	);
}

function MiniSwitch({
	label,
	description,
	checked,
	onCheckedChange,
}: {
	label: string;
	description: string;
	checked: boolean;
	onCheckedChange: (next: boolean) => void;
}) {
	return (
		<div className="flex h-fit items-center justify-between gap-3 rounded-lg border border-border/60 p-3">
			<div className="space-y-0.5 min-w-0">
				<Label className="text-xs font-medium">{label}</Label>
				<p className="text-muted-foreground text-[11px] leading-snug">{description}</p>
			</div>
			<Switch size="md" checked={checked} onCheckedChange={onCheckedChange} />
		</div>
	);
}
