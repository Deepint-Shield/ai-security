"use client";

import FullPageLoader from "@/components/fullPageLoader";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { setSelectedPlugin, useAppDispatch, useAppSelector, useGetPluginsQuery } from "@/lib/store";
import { cn } from "@/lib/utils";
import { CheckCircle2, Network } from "lucide-react";
import { useTheme } from "next-themes";
import Image from "next/image";
import { useQueryState } from "nuqs";
import { useEffect, useMemo } from "react";
import NewrelicView from "./plugins/newRelicView";
import OtelView from "./plugins/otelView";
import PrometheusView from "./plugins/prometheusView";

type SupportedPlatform = {
	id: string;
	name: string;
	icon: React.ReactNode;
	tag?: string;
	disabled?: boolean;
};

const supportedPlatformsList = (resolvedTheme: string): SupportedPlatform[] => [
	{
		id: "otel",
		name: "Open Telemetry",
		icon: (
			<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width={21} height={21}>
				<path
					fill="#f5a800"
					d="M67.648 69.797c-5.246 5.25-5.246 13.758 0 19.008 5.25 5.246 13.758 5.246 19.004 0 5.25-5.25 5.25-13.758 0-19.008-5.246-5.246-13.754-5.246-19.004 0Zm14.207 14.219a6.649 6.649 0 0 1-9.41 0 6.65 6.65 0 0 1 0-9.407 6.649 6.649 0 0 1 9.41 0c2.598 2.586 2.598 6.809 0 9.407ZM86.43 3.672l-8.235 8.234a4.17 4.17 0 0 0 0 5.875l32.149 32.149a4.17 4.17 0 0 0 5.875 0l8.234-8.235c1.61-1.61 1.61-4.261 0-5.87L92.29 3.671a4.159 4.159 0 0 0-5.86 0ZM28.738 108.895a3.763 3.763 0 0 0 0-5.31l-4.183-4.187a3.768 3.768 0 0 0-5.313 0l-8.644 8.649-.016.012-2.371-2.375c-1.313-1.313-3.45-1.313-4.75 0-1.313 1.312-1.313 3.449 0 4.75l14.246 14.242a3.353 3.353 0 0 0 4.746 0c1.3-1.313 1.313-3.45 0-4.746l-2.375-2.375.016-.012Zm0 0"
				/>
				<path
					fill="#425cc7"
					d="M72.297 27.313 54.004 45.605c-1.625 1.625-1.625 4.301 0 5.926L65.3 62.824c7.984-5.746 19.18-5.035 26.363 2.153l9.148-9.149c1.622-1.625 1.622-4.297 0-5.922L78.22 27.313a4.185 4.185 0 0 0-5.922 0ZM60.55 67.585l-6.672-6.672c-1.563-1.562-4.125-1.562-5.684 0l-23.53 23.54a4.036 4.036 0 0 0 0 5.687l13.331 13.332a4.036 4.036 0 0 0 5.688 0l15.132-15.157c-3.199-6.609-2.625-14.593 1.735-20.73Zm0 0"
				/>
			</svg>
		),
	},
	{
		id: "prometheus",
		name: "Prometheus",
		icon: <Image alt="Prometheus" src="/images/prometheus-logo.svg" width={21} height={21} className="-ml-0.5" />,
	},
	// {
	// 	id: "newrelic",
	// 	name: "New Relic",
	// 	icon: (
	// 		<svg viewBox="0 0 832.8 959.8" xmlns="http://www.w3.org/2000/svg" width="19" height="19">
	// 			<path d="M672.6 332.3l160.2-92.4v480L416.4 959.8V775.2l256.2-147.6z" fill="#00ac69" />
	// 			<path d="M416.4 184.6L160.2 332.3 0 239.9 416.4 0l416.4 239.9-160.2 92.4z" fill="#1ce783" />
	// 			<path d="M256.2 572.3L0 424.6V239.9l416.4 240v479.9l-160.2-92.2z" fill="#1d252c" />
	// 		</svg>
	// 	),
	// 	disabled: true,
	// },
];

export default function ObservabilityView() {
	const dispatch = useAppDispatch();
	const { data: plugins, isLoading } = useGetPluginsQuery();
	const [selectedPluginId, setSelectedPluginId] = useQueryState("plugin");
	const selectedPlugin = useAppSelector((state) => state.plugin.selectedPlugin);

	const { resolvedTheme } = useTheme();

	const supportedPlatforms = useMemo(() => supportedPlatformsList(resolvedTheme || "light"), [resolvedTheme]);

	// Map UI tab IDs to actual plugin names (prometheus tab uses telemetry plugin)
	const getPluginNameForTab = (tabId: string) => (tabId === "prometheus" ? "telemetry" : tabId);

	useEffect(() => {
		if (!plugins || plugins.length === 0) return;
		if (!selectedPluginId) {
			setSelectedPluginId(supportedPlatforms[0].id);
		} else {
			const pluginName = getPluginNameForTab(selectedPluginId);
			const plugin = plugins.find((plugin) => plugin.name === pluginName) ?? {
				name: selectedPluginId,
				enabled: false,
				config: {},
				isCustom: false,
				path: "",
			};
			dispatch(setSelectedPlugin(plugin));
		}
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [plugins]);

	useEffect(() => {
		if (selectedPluginId) {
			const pluginName = getPluginNameForTab(selectedPluginId);
			const plugin = plugins?.find((plugin) => plugin.name === pluginName) ?? {
				name: selectedPluginId,
				enabled: false,
				config: {},
				isCustom: false,
				path: "",
			};
			dispatch(setSelectedPlugin(plugin));
		} else {
			setSelectedPluginId(supportedPlatforms[0].id);
		}
	}, [selectedPluginId]);

	if (isLoading) {
		return <FullPageLoader />;
	}

	return (
		<div className="flex h-full flex-col gap-5">
			{/* Page header */}
			<div className="space-y-1.5">
				<div className="text-muted-foreground text-[11px] font-semibold uppercase tracking-[0.18em]">Integrations</div>
				<div className="flex items-center gap-2.5">
					<span className="inline-flex h-9 w-9 items-center justify-center rounded-xl bg-primary/12 text-primary shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
						<Network className="h-4.5 w-4.5" />
					</span>
					<div>
						<h1 className="text-2xl font-semibold tracking-tight leading-none">Observability</h1>
						{/* <p className="mt-1 text-muted-foreground text-xs">
							Forward traces and metrics to your existing observability stack - OpenTelemetry, Prometheus, and more.
						</p> */}
					</div>
				</div>
			</div>

			<TooltipProvider>
				<div className="flex h-full flex-row gap-4">
					{/* Left: provider tile grid (2 cards per row) */}
					<aside className="flex shrink-0 flex-col" style={{ width: "320px", maxHeight: "calc(100vh - 70px)" }}>
						<div className="custom-scrollbar flex-1 overflow-y-auto">
							<div className="border-border/60 bg-card/40 rounded-2xl border p-3">
								<div className="mb-3 flex items-center justify-between gap-2 px-1">
									<div className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">Providers</div>
								</div>
								<div className="grid grid-cols-2 gap-2.5">
									{supportedPlatforms.map((tab) => {
										const isActive = selectedPluginId === tab.id;
										const pluginName = getPluginNameForTab(tab.id);
										const pluginEntry = plugins?.find((p) => p.name === pluginName);
										const isEnabled = !!pluginEntry?.enabled;
										return (
											<ObservabilityProviderTile
												key={tab.id}
												tab={tab}
												isSelected={isActive}
												isEnabled={isEnabled}
												onSelect={() => {
													if (tab.disabled) return;
													setSelectedPluginId(tab.id ?? supportedPlatforms[0].id);
												}}
											/>
										);
									})}
								</div>
							</div>
						</div>
					</aside>

					{/* Right: selected provider config form */}
					<div className="min-w-0 flex-1">
						{selectedPluginId === "prometheus" && <PrometheusView />}
						{selectedPluginId === "otel" && <OtelView />}
						{selectedPluginId === "newrelic" && <NewrelicView />}
					</div>
				</div>
			</TooltipProvider>
		</div>
	);
}

function ObservabilityProviderTile({
	tab,
	isSelected,
	isEnabled,
	onSelect,
}: {
	tab: SupportedPlatform;
	isSelected: boolean;
	isEnabled: boolean;
	onSelect: () => void;
}) {
	const tile = (
		<button
			type="button"
			onClick={onSelect}
			disabled={!!tab.disabled}
			data-testid={`observability-provider-btn-${tab.id}`}
			aria-pressed={isSelected}
			aria-disabled={tab.disabled ? true : undefined}
			aria-current={isSelected ? "page" : undefined}
			aria-label={tab.name}
			className={cn(
				"group relative flex aspect-square w-full flex-col items-center justify-center gap-2 overflow-hidden rounded-xl border p-3 transition-all",
				isSelected
					? "border-primary/60 bg-primary/8 shadow-[0_0_0_1px_rgba(34,211,196,0.18)_inset,0_4px_14px_-6px_rgba(34,211,196,0.30)]"
					: "border-border/60 bg-card hover:border-border hover:shadow-[0_4px_12px_-6px_rgba(15,23,42,0.18)]",
				tab.disabled && "cursor-not-allowed opacity-60",
			)}
		>
			{/* Status dot top-right */}
			{isEnabled && (
				<span className="absolute right-1.5 top-1.5 inline-flex h-5 w-5 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
					<CheckCircle2 className="h-3.5 w-3.5" strokeWidth={2.25} />
				</span>
			)}

			{/* Icon dominates the tile */}
			<span className="inline-flex h-12 w-12 shrink-0 items-center justify-center transition-transform group-hover:scale-105 [&>svg]:h-10 [&>svg]:w-10 [&>img]:h-9 [&>img]:w-9">
				{tab.icon}
			</span>

			{/* Label */}
			<span className="line-clamp-1 max-w-full px-1 text-center text-[13px] font-semibold tracking-tight">{tab.name}</span>

			{tab.tag && (
				<Badge variant="secondary" className="absolute bottom-1 left-1 text-[9px] font-bold leading-tight">
					{tab.tag.toUpperCase()}
				</Badge>
			)}
			{tab.disabled && (
				<Badge variant="outline" className="absolute bottom-1 right-1 text-[9px] font-medium tracking-wider">
					SOON
				</Badge>
			)}
		</button>
	);

	return (
		<Tooltip>
			<TooltipTrigger asChild>{tile}</TooltipTrigger>
			<TooltipContent side="top">{tab.name}</TooltipContent>
		</Tooltip>
	);
}
