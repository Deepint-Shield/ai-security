import { ComboboxSelect } from "@/components/ui/combobox";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scrollArea";
import { Separator } from "@/components/ui/separator";
import ModelParameters from "@/components/ui/custom/modelParameters";
import { ModelParams } from "@/lib/types/prompts";
import { getProviderLabel } from "@/lib/constants/logs";
import { useGetAllKeysQuery, useGetProvidersQuery, useLazyGetModelsQuery } from "@/lib/store/apis/providersApi";
import { useCallback, useEffect, useMemo } from "react";
import { ModelProviderName } from "@/lib/types/config";
import { usePromptContext } from "../context";
import { ApiKeySelectorView } from "../components/apiKeySelectorView";

export function SettingsPanel() {
	const {
		provider,
		setProvider,
		model,
		setModel: onModelChange,
		modelParams,
		setModelParams: onModelParamsChange,
		apiKeyId,
		setApiKeyId,
	} = usePromptContext();

	const onProviderChange = useCallback(
		(p: string) => {
			setProvider(p);
			setApiKeyId("__auto__");
			onModelChange("");
			onModelParamsChange({} as ModelParams);
		},
		[setProvider, setApiKeyId, onModelChange, onModelParamsChange],
	);

	const onApiKeyIdChange = useCallback(
		(id: string) => {
			setApiKeyId(id);
		},
		[setApiKeyId],
	);
	// Dynamic providers. Revalidate on mount so the dropdown reflects server truth
	// instead of a stale/empty cross-session cache snapshot (see persistence.ts) -
	// otherwise the provider list can render "No results found" on a hard load.
	const { data: providers } = useGetProvidersQuery(undefined, { refetchOnMountOrArgChange: true });
	const configuredProviders = useMemo(() => (providers ?? []).filter((p) => (p.keys?.length ?? 0) > 0), [providers]);

	// Ensure current provider always has a label-resolved option (even before providers query loads)
	const providerOptions = useMemo(() => {
		const opts = configuredProviders.map((p) => ({ label: getProviderLabel(p.name), value: p.name }));
		if (provider && !opts.find((o) => o.value === provider)) {
			opts.unshift({ label: getProviderLabel(provider), value: provider as ModelProviderName });
		}
		return opts;
	}, [configuredProviders, provider]);

	// Get keys from the provider config (has models[] per key)
	const selectedProvider = useMemo(() => configuredProviders.find((p) => p.name === provider), [configuredProviders, provider]);
	const providerKeyConfigs = useMemo(() => selectedProvider?.keys ?? [], [selectedProvider]);

	// Keys for the API Key selector (from /api/keys endpoint, provider-filtered).
	// Revalidate on mount for the same reason as the provider list above.
	const { data: allKeys } = useGetAllKeysQuery(undefined, { refetchOnMountOrArgChange: true });
	const providerKeys = useMemo(() => (allKeys ?? []).filter((k) => k.provider === provider), [allKeys, provider]);

	// Fallback: fetch all models for this provider (used when any key has no models restriction)
	const [fetchModels, { data: modelsData }] = useLazyGetModelsQuery();
	useEffect(() => {
		if (provider) {
			fetchModels({ provider, limit: 100, unfiltered: true });
		}
	}, [provider, fetchModels]);
	const allProviderModels = useMemo(() => (modelsData?.models ?? []).map((m) => m.name), [modelsData]);

	// Build model list based on key selection
	const availableModels = useMemo(() => {
		if (apiKeyId !== "__auto__") {
			// Specific key selected - find it in provider config
			const key = providerKeyConfigs.find((k) => k.id === apiKeyId);
			if (key?.models && key.models.length > 0) {
				return key.models;
			}
			// Key has no model restriction → show all
			return allProviderModels;
		}

		// Auto mode - blend models from all keys
		// If any key has empty models (no restriction), show all models
		const hasUnrestrictedKey = providerKeyConfigs.some((k) => !k.models || k.models.length === 0);
		if (hasUnrestrictedKey || providerKeyConfigs.length === 0) {
			return allProviderModels;
		}

		// All keys have specific models - show unique union
		const modelSet = new Set<string>();
		for (const k of providerKeyConfigs) {
			for (const m of k.models ?? []) {
				modelSet.add(m);
			}
		}
		return Array.from(modelSet);
	}, [apiKeyId, providerKeyConfigs, allProviderModels]);

	const handleModelParamsChange = useCallback(
		(params: Record<string, any>) => {
			onModelParamsChange(params as ModelParams);
		},
		[onModelParamsChange],
	);

	return (
		<div className="flex h-full flex-col">
			<ScrollArea className="grow overflow-y-auto" viewportClassName="no-table">
				<div className="space-y-5 p-4">
					<div className="flex flex-col gap-1.5" data-testid="settings-provider">
						<Label className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">Provider</Label>
						<ComboboxSelect
							options={providerOptions}
							value={provider}
							onValueChange={(v) => v && onProviderChange(v)}
							placeholder="Select provider"
							hideClear
						/>
					</div>

					<div className="flex flex-col gap-1.5" data-testid="settings-model">
						<Label className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">Model</Label>
						<ComboboxSelect
							options={availableModels.map((m) => ({ label: m, value: m }))}
							value={model}
							onValueChange={(v) => v && onModelChange(v)}
							placeholder={!provider ? "Select a provider first" : "Select model"}
							hideClear
							disabled={!provider}
						/>
					</div>

					{providerKeys.length > 0 && !!provider && (
						<ApiKeySelectorView
							providerKeys={providerKeys}
							value={apiKeyId}
							onValueChange={(v) => onApiKeyIdChange(v ?? "__auto__")}
							disabled={!provider}
						/>
					)}

					{model && (
						<>
							<Separator />

							<div className="flex flex-col gap-3">
								<Label className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">Model Parameters</Label>
								<ModelParameters model={model} config={modelParams} onChange={handleModelParamsChange} hideFields={["promptTools"]} />
							</div>
						</>
					)}
				</div>
			</ScrollArea>
		</div>
	);
}
