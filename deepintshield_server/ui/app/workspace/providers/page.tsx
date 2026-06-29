"use client";

import ModelProviderConfig from "@/app/workspace/providers/views/modelProviderConfig";
import FullPageLoader from "@/components/fullPageLoader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { DefaultNetworkConfig, DefaultPerformanceConfig } from "@/lib/constants/config";
import { ProviderIconType, RenderProviderIcon } from "@/lib/constants/icons";
import { ProviderLabels, ProviderNames } from "@/lib/constants/logs";
import {
	getErrorMessage,
	setSelectedProvider,
	useAppDispatch,
	useAppSelector,
	useCreateProviderMutation,
	useGetProvidersQuery,
	useLazyGetProviderQuery,
} from "@/lib/store";
import { ModelProvider, ModelProviderName, ProviderStatus } from "@/lib/types/config";
import { cn } from "@/lib/utils";
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib";
import { AlertCircle, CheckCircle2, Plus, Settings2, Sparkles } from "lucide-react";
import { useRouter } from "next/navigation";
import { useQueryState } from "nuqs";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import AddCustomProviderSheet from "./dialogs/addNewCustomProviderSheet";
import ConfirmDeleteProviderDialog from "./dialogs/confirmDeleteProviderDialog";
import ConfirmRedirectionDialog from "./dialogs/confirmRedirection";

export default function Providers() {
	const dispatch = useAppDispatch();
	const router = useRouter();
	const hasProvidersAccess = useRbac(RbacResource.ModelProvider, RbacOperation.View);
	const hasSettingsOnly = useRbac(RbacResource.Settings, RbacOperation.View);
	const hasProviderCreateAccess = useRbac(RbacResource.ModelProvider, RbacOperation.Create);

	useEffect(() => {
		if (!hasProvidersAccess && hasSettingsOnly) {
			router.replace("/workspace/custom-pricing");
		}
	}, [hasProvidersAccess, hasSettingsOnly, router]);

	const selectedProvider = useAppSelector((state) => state.provider.selectedProvider);
	const providerFormIsDirty = useAppSelector((state) => state.provider.isDirty);

	const [showRedirectionDialog, setShowRedirectionDialog] = useState(false);
	const [showDeleteProviderDialog, setShowDeleteProviderDialog] = useState(false);
	const [pendingRedirection, setPendingRedirection] = useState<string | undefined>(undefined);
	const [showCustomProviderSheet, setShowCustomProviderSheet] = useState(false);
	const [provider, setProvider] = useQueryState("provider");

	// Always revalidate the provider list when this page mounts. The cross-reload
	// RTK cache (persistence.ts) replays the last snapshot into the store, and the
	// global refetchOnMountOrArgChange:false would otherwise serve that snapshot
	// without ever re-checking the server - so a key added right before a hard
	// refresh appears to "vanish" until a focus event triggers a refetch. The warm
	// snapshot still renders instantly (isLoading stays false); this just kicks a
	// background refetch that reconciles to the server's truth (which has the key).
	const { data: savedProviders, isLoading: isLoadingProviders } = useGetProvidersQuery(undefined, {
		refetchOnMountOrArgChange: true,
	});
	const [getProvider, { isLoading: isLoadingProvider }] = useLazyGetProviderQuery();
	const [createProvider] = useCreateProviderMutation();

	const configuredProviders = (savedProviders ?? []).slice().sort((a, b) => a.name.localeCompare(b.name));
	const configuredProviderNamesArr = configuredProviders.map((p) => p.name);
	const configuredProviderNamesKey = JSON.stringify(configuredProviderNamesArr);
	const configuredByName = new Map(configuredProviders.map((p) => [p.name, p]));

	useEffect(() => {
		if (!provider) return;
		const newSelectedProvider = configuredProviders.find((p) => p.name === provider);
		if (!newSelectedProvider) {
			dispatch(
				setSelectedProvider({
					name: provider as ModelProviderName,
					keys: [],
					concurrency_and_buffer_size: DefaultPerformanceConfig,
					network_config: DefaultNetworkConfig,
					custom_provider_config: undefined,
					proxy_config: undefined,
					send_back_raw_request: undefined,
					send_back_raw_response: undefined,
					provider_status: "error",
				}),
			);
			return;
		}

		dispatch(setSelectedProvider(newSelectedProvider));
		getProvider(provider)
			.unwrap()
			.then((providerInfo) => {
				dispatch(setSelectedProvider(providerInfo));
			})
			.catch((err) => {
				if (err.status === 404) {
					return;
				}
				toast.error("Something went wrong", {
					description: `We encountered an error while getting provider config: ${getErrorMessage(err)}`,
				});
			});
	}, [provider, isLoadingProviders]);

	useEffect(() => {
		if (selectedProvider || configuredProviders.length === 0 || provider) return;
		setProvider(configuredProviders[0].name);
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [selectedProvider, configuredProviderNamesKey]);

	useEffect(() => {
		if (!provider || configuredProviderNamesArr.length === 0) return;
		const isCurrentConfigured = configuredProviderNamesArr.includes(provider as ModelProviderName);
		if (!isCurrentConfigured) {
			setProvider(configuredProviderNamesArr[0]);
		}
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [provider, configuredProviderNamesKey]);

	if (!hasProvidersAccess && hasSettingsOnly) {
		return <FullPageLoader />;
	}
	if (isLoadingProviders) {
		return <FullPageLoader />;
	}

	const handleSelectKnownProvider = async (name: string) => {
		try {
			await createProvider({ provider: name as ModelProviderName, keys: [] }).unwrap();
			setProvider(name);
		} catch (err: any) {
			if (err?.status === 409) {
				setProvider(name);
				return;
			}
			toast.error("Failed to add provider", {
				description: getErrorMessage(err),
			});
		}
	};

	const handleSelectProvider = (name: string) => {
		if (providerFormIsDirty) {
			setPendingRedirection(name);
			setShowRedirectionDialog(true);
			return;
		}
		setProvider(name);
	};

	// Render the full provider catalog grid even when zero providers
	// are configured - that's the more useful entry point (operator
	// sees every supported provider as an add-able tile) than the
	// minimal "Add custom provider" empty-state. The right-hand pane
	// below already handles the no-selection case with its own
	// "select a provider" placeholder, so falling through here is
	// safe.

	const knownProviderNames = ProviderNames as readonly string[];
	const customConfiguredProviders = configuredProviders.filter((p) => !knownProviderNames.includes(p.name));
	const gridProviders: GridProviderEntry[] = [
		...knownProviderNames.map((name) => ({
			name,
			isCustom: false,
			configured: configuredByName.get(name as ModelProviderName),
		})),
		...customConfiguredProviders.map((p) => ({
			name: p.name,
			isCustom: true,
			configured: p,
		})),
	];

	return (
		<TooltipProvider>
			<div className="workspace-page-shell flex h-full flex-row gap-4">
				<ConfirmDeleteProviderDialog
					provider={selectedProvider!}
					show={showDeleteProviderDialog}
					onCancel={() => setShowDeleteProviderDialog(false)}
					onDelete={() => {
						const next = configuredProviders.filter((p) => p.name !== selectedProvider?.name)[0];
						setProvider(next?.name ?? null);
						setShowDeleteProviderDialog(false);
					}}
				/>
				<ConfirmRedirectionDialog
					show={showRedirectionDialog}
					onCancel={() => setShowRedirectionDialog(false)}
					onContinue={() => {
						setShowRedirectionDialog(false);
						if (pendingRedirection) setProvider(pendingRedirection);
						setPendingRedirection(undefined);
					}}
				/>
				<AddCustomProviderSheet
					show={showCustomProviderSheet}
					onClose={() => setShowCustomProviderSheet(false)}
					onSave={(providerName) => {
						setTimeout(() => setProvider(providerName), 300);
						setShowCustomProviderSheet(false);
					}}
				/>

				{/* Left: provider tile grid */}
				<aside
					className="flex shrink-0 flex-col"
					style={{ width: "420px", maxHeight: "calc(100vh - 70px)" }}
				>
					<div className="custom-scrollbar flex-1 overflow-y-auto">
						<div className="border-border/60 bg-card/40 rounded-2xl border p-3">
							<div className="mb-3 flex items-center justify-between gap-2 px-1">
								<div className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">
									Providers
								</div>
								<Button
									variant="ghost"
									size="sm"
									onClick={() => setShowCustomProviderSheet(true)}
									disabled={!hasProviderCreateAccess}
									data-testid="add-custom-provider-btn"
									className="h-6 px-1.5 text-[10px] uppercase tracking-wider"
								>
									<Settings2 className="h-3 w-3" />
									Custom
								</Button>
							</div>
							<div className="grid grid-cols-3 gap-2.5">
								{gridProviders.map((entry) => (
									<ProviderTile
										key={entry.name}
										entry={entry}
										isSelected={selectedProvider?.name === entry.name}
										canCreate={hasProviderCreateAccess}
										onSelect={handleSelectProvider}
										onAdd={handleSelectKnownProvider}
									/>
								))}
							</div>
						</div>
					</div>
				</aside>

				{/* Right: selected provider config */}
				<div className="flex min-w-0 flex-1 flex-col">
					{isLoadingProvider && (
						<div className="bg-muted/10 flex h-full w-full items-center justify-center rounded-2xl">
							<FullPageLoader />
						</div>
					)}
					{!isLoadingProvider && !selectedProvider && (
						<div className="border-border/60 bg-card/40 flex h-full w-full flex-col items-center justify-center gap-2 rounded-2xl border p-12">
							<span className="bg-muted text-muted-foreground inline-flex h-12 w-12 items-center justify-center rounded-2xl">
								<Sparkles className="h-5 w-5" strokeWidth={1.75} />
							</span>
							<h3 className="text-sm font-semibold">Select a provider</h3>
							<p className="text-muted-foreground text-xs">Pick a tile on the left to view and manage its keys.</p>
						</div>
					)}
					{!isLoadingProvider && selectedProvider && (
						<ModelProviderConfig provider={selectedProvider} onRequestDelete={() => setShowDeleteProviderDialog(true)} />
					)}
				</div>
			</div>
		</TooltipProvider>
	);
}

interface GridProviderEntry {
	name: string;
	isCustom: boolean;
	configured?: ModelProvider;
}

function ProviderTile({
	entry,
	isSelected,
	canCreate,
	onSelect,
	onAdd,
}: {
	entry: GridProviderEntry;
	isSelected: boolean;
	canCreate: boolean;
	onSelect: (name: string) => void;
	onAdd: (name: string) => void;
}) {
	const isConfigured = !!entry.configured;
	const label = entry.isCustom ? entry.name : ProviderLabels[entry.name as keyof typeof ProviderLabels] ?? entry.name;
	const iconProvider = (entry.isCustom ? entry.configured?.custom_provider_config?.base_provider_type : entry.name) as ProviderIconType;

	const tile = (
		<button
			type="button"
			onClick={() => {
				if (isConfigured) onSelect(entry.name);
				else onAdd(entry.name);
			}}
			disabled={!isConfigured && !canCreate}
			data-testid={`provider-tile-${entry.name.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}`}
			className={cn(
				"group relative flex aspect-square w-full flex-col items-center justify-center gap-2 overflow-hidden rounded-xl border p-3 transition-all",
				isSelected
					? "border-primary/60 bg-primary/8 shadow-[0_0_0_1px_rgba(34,211,196,0.18)_inset,0_4px_14px_-6px_rgba(34,211,196,0.30)]"
					: isConfigured
						? "border-border/60 bg-card hover:border-border hover:shadow-[0_4px_12px_-6px_rgba(15,23,42,0.18)]"
						: "border-border/40 bg-card/30 hover:border-border/80 hover:bg-card",
				!isConfigured && !canCreate && "cursor-not-allowed opacity-60",
			)}
			aria-pressed={isSelected}
			aria-label={isConfigured ? `Configure ${label}` : `Add ${label}`}
		>
			{/* Status dot top-right */}
			<span className="absolute right-1.5 top-1.5">
				{isConfigured ? (
					<span className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
						<CheckCircle2 className="h-3.5 w-3.5" strokeWidth={2.25} />
					</span>
				) : (
					<span className="inline-flex h-5 w-5 items-center justify-center rounded-full border border-dashed border-border bg-background/60 text-muted-foreground transition-colors group-hover:border-primary/60 group-hover:text-primary">
						<Plus className="h-3 w-3" strokeWidth={2.5} />
					</span>
				)}
			</span>

			{/* Issue indicator */}
			{isConfigured && <ProviderIssuesPill provider={entry.configured!} />}

			{/* Icon dominates the tile */}
			<RenderProviderIcon provider={iconProvider} size="lg" className="h-12 w-12 shrink-0 transition-transform group-hover:scale-105" />

			{/* Label */}
			<span className="line-clamp-1 max-w-full px-1 text-center text-[13px] font-semibold tracking-tight">
				{label}
			</span>
			{entry.isCustom && (
				<Badge variant="secondary" className="text-muted-foreground absolute bottom-1 left-1 px-1 py-0 text-[8px] font-bold leading-tight">
					CUSTOM
				</Badge>
			)}
		</button>
	);

	if (isConfigured) {
		return (
			<Tooltip>
				<TooltipTrigger asChild>{tile}</TooltipTrigger>
				<TooltipContent side="top">{label}</TooltipContent>
			</Tooltip>
		);
	}

	return (
		<Tooltip>
			<TooltipTrigger asChild>{tile}</TooltipTrigger>
			<TooltipContent side="top">Add {label}</TooltipContent>
		</Tooltip>
	);
}

function ProviderIssuesPill({ provider }: { provider: ModelProvider }) {
	const hasFailedKeys = provider.keys?.some((key: any) => key.status === "list_models_failed");
	const providerFailed = (provider as any).status === "list_models_failed";
	const providerError = (provider.provider_status as ProviderStatus) === "error";
	const hasFailed = hasFailedKeys || providerFailed || providerError;
	if (!hasFailed) return null;

	return (
		<span className="absolute left-1.5 top-1.5 inline-flex h-5 w-5 items-center justify-center rounded-full bg-amber-500/15 text-amber-600 dark:text-amber-400">
			<AlertCircle className="h-3.5 w-3.5" />
		</span>
	);
}
