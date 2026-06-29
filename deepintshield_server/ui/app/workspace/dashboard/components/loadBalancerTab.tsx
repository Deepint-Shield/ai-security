"use client";

import LoadBalancerCharts from "@/app/workspace/adaptive-routing/views/loadBalancerCharts";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { RoutingEngineUsedLabels } from "@/lib/constants/logs";
import { useGetKeyHealthQuery, useGetVirtualKeysQuery, useLazyGetLogsCostHistogramQuery, useLazyGetLogsHistogramQuery, useLazyGetLogsLatencyHistogramQuery } from "@/lib/store";
import { useAppSelector } from "@/lib/store/hooks";
import { selectActiveWorkspaceId } from "@/lib/store/slices/activeScopeSlice";
import { dateUtils } from "@/lib/types/logs";
import type {
	CostHistogramResponse,
	LatencyHistogramResponse,
	LogFilters,
	LogsHistogramResponse,
	ProviderCostHistogramBucket,
	ProviderCostHistogramResponse,
	ProviderLatencyHistogramBucket,
	ProviderLatencyHistogramResponse,
} from "@/lib/types/logs";
import { useEffect, useMemo, useState } from "react";
import {
	CHART_HEADER_ACTIONS_CLASS,
	CHART_HEADER_CONTROLS_CLASS,
	CHART_HEADER_LEGEND_CLASS,
	COST_CHART_HEADER_ACTIONS_CLASS,
	COST_CHART_HEADER_FILTERS_CLASS,
	COST_CHART_HEADER_SUMMARY_ROW_CLASS,
	LATENCY_COLORS,
	getModelColor,
} from "../utils/chartUtils";
import { getProviderCostHistogramTotals } from "../utils/costTotals";
import { ChartCard } from "./charts/chartCard";
import { type ChartType, ChartTypeToggle } from "./charts/chartTypeToggle";
import { CostHeaderSummary } from "./charts/costHeaderSummary";
import { ProviderCostChart } from "./charts/providerCostChart";
import { ProviderLatencyChart } from "./charts/providerLatencyChart";
import { RoutingEngineFilterSelect } from "./charts/routingEngineFilterSelect";

// Engine identifiers match backend (see RoutingEngineUsedLabels in lib/constants/logs.ts)
const DEFAULT_ENGINES = ["routing-rule", "governance", "loadbalancing"];

function engineLabel(engine: string): string {
	return (RoutingEngineUsedLabels as Record<string, string>)[engine] ?? engine;
}

function mergeVolumeHistograms(engines: string[], responses: Array<LogsHistogramResponse | null>): ProviderCostHistogramResponse | null {
	const valid = responses
		.map((response, idx) => ({ response, engine: engines[idx] }))
		.filter((entry): entry is { response: LogsHistogramResponse; engine: string } => Boolean(entry.response?.buckets?.length));
	if (valid.length === 0) return null;

	const bucketSize = valid[0].response.bucket_size_seconds;
	const byTimestamp = new Map<string, ProviderCostHistogramBucket>();

	for (const { response, engine } of valid) {
		for (const bucket of response.buckets) {
			const existing = byTimestamp.get(bucket.timestamp) ?? {
				timestamp: bucket.timestamp,
				total_cost: 0,
				cache_savings: 0,
				by_provider: {},
				by_provider_cache_savings: {},
			};
			existing.by_provider[engine] = (existing.by_provider[engine] ?? 0) + (bucket.count ?? 0);
			existing.total_cost += bucket.count ?? 0;
			byTimestamp.set(bucket.timestamp, existing);
		}
	}

	const buckets = [...byTimestamp.values()].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
	return {
		buckets,
		bucket_size_seconds: bucketSize,
		providers: valid.map((entry) => entry.engine),
	};
}

function mergeCostHistograms(engines: string[], responses: Array<CostHistogramResponse | null>): ProviderCostHistogramResponse | null {
	const valid = responses
		.map((response, idx) => ({ response, engine: engines[idx] }))
		.filter((entry): entry is { response: CostHistogramResponse; engine: string } => Boolean(entry.response?.buckets?.length));
	if (valid.length === 0) return null;

	const bucketSize = valid[0].response.bucket_size_seconds;
	const byTimestamp = new Map<string, ProviderCostHistogramBucket>();

	for (const { response, engine } of valid) {
		for (const bucket of response.buckets) {
			const existing = byTimestamp.get(bucket.timestamp) ?? {
				timestamp: bucket.timestamp,
				total_cost: 0,
				cache_savings: 0,
				by_provider: {},
				by_provider_cache_savings: {},
			};
			const cost = bucket.total_cost ?? 0;
			const savings = bucket.cache_savings ?? 0;
			existing.by_provider[engine] = (existing.by_provider[engine] ?? 0) + cost;
			existing.by_provider_cache_savings[engine] = (existing.by_provider_cache_savings[engine] ?? 0) + savings;
			existing.total_cost += cost;
			existing.cache_savings += savings;
			byTimestamp.set(bucket.timestamp, existing);
		}
	}

	const buckets = [...byTimestamp.values()].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
	return {
		buckets,
		bucket_size_seconds: bucketSize,
		providers: valid.map((entry) => entry.engine),
	};
}

function mergeLatencyHistograms(
	engines: string[],
	responses: Array<LatencyHistogramResponse | null>,
): ProviderLatencyHistogramResponse | null {
	const valid = responses
		.map((response, idx) => ({ response, engine: engines[idx] }))
		.filter((entry): entry is { response: LatencyHistogramResponse; engine: string } => Boolean(entry.response?.buckets?.length));
	if (valid.length === 0) return null;

	const bucketSize = valid[0].response.bucket_size_seconds;
	const byTimestamp = new Map<string, ProviderLatencyHistogramBucket>();

	for (const { response, engine } of valid) {
		for (const bucket of response.buckets) {
			const existing = byTimestamp.get(bucket.timestamp) ?? {
				timestamp: bucket.timestamp,
				by_provider: {},
			};
			existing.by_provider[engine] = {
				avg_latency: bucket.avg_latency ?? 0,
				p90_latency: bucket.p90_latency ?? 0,
				p95_latency: bucket.p95_latency ?? 0,
				p99_latency: bucket.p99_latency ?? 0,
				total_requests: bucket.total_requests ?? 0,
			};
			byTimestamp.set(bucket.timestamp, existing);
		}
	}

	const buckets = [...byTimestamp.values()].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
	return {
		buckets,
		bucket_size_seconds: bucketSize,
		providers: valid.map((entry) => entry.engine),
	};
}

export interface LoadBalancerTabProps {
	filters: LogFilters;
	isActive: boolean;
	refreshKey: number;
	startTime: number;
	endTime: number;
	volumeChartType: ChartType;
	costChartType: ChartType;
	latencyChartType: ChartType;
	volumeEngine: string;
	costEngine: string;
	latencyEngine: string;
	onVolumeChartToggle: (type: ChartType) => void;
	onCostChartToggle: (type: ChartType) => void;
	onLatencyChartToggle: (type: ChartType) => void;
	onVolumeEngineChange: (engine: string) => void;
	onCostEngineChange: (engine: string) => void;
	onLatencyEngineChange: (engine: string) => void;
}

export function LoadBalancerTab({
	filters,
	isActive,
	refreshKey,
	startTime,
	endTime,
	volumeChartType,
	costChartType,
	latencyChartType,
	volumeEngine,
	costEngine,
	latencyEngine,
	onVolumeChartToggle,
	onCostChartToggle,
	onLatencyChartToggle,
	onVolumeEngineChange,
	onCostEngineChange,
	onLatencyEngineChange,
}: LoadBalancerTabProps) {
	const [triggerVolume] = useLazyGetLogsHistogramQuery({});
	const [triggerCost] = useLazyGetLogsCostHistogramQuery();
	const [triggerLatency] = useLazyGetLogsLatencyHistogramQuery();

	// Workspace-scoped live key-health + VK feeds for the new per-key charts
	// (Model Routing, Rate Limiting, Throttling, Circuit State). These poll
	// the same /governance/key-health endpoint that the operational page uses
	// and re-render in place every 10s.
	const activeWorkspaceId = useAppSelector(selectActiveWorkspaceId);
	const { data: lbVkData } = useGetVirtualKeysQuery(
		{ workspace_id: activeWorkspaceId || undefined },
		{ skip: !isActive },
	);
	const { data: lbHealthData } = useGetKeyHealthQuery(undefined, {
		skip: !isActive,
		pollingInterval: 10000,
	});
	const lbVirtualKeys = lbVkData?.virtual_keys ?? [];
	const lbWorkspaceKeyIds = useMemo(() => {
		const ids = new Set<string>();
		lbVirtualKeys.forEach((vk) =>
			vk.provider_configs?.forEach((pc) =>
				pc.keys?.forEach((k) => {
					if (k.key_id) ids.add(k.key_id);
				}),
			),
		);
		return ids;
	}, [lbVirtualKeys]);
	const lbKeyHealth = useMemo(
		() => (lbHealthData?.keys ?? []).filter((k) => lbWorkspaceKeyIds.has(k.key_id)),
		[lbHealthData?.keys, lbWorkspaceKeyIds],
	);

	const [volumeData, setVolumeData] = useState<ProviderCostHistogramResponse | null>(null);
	const [costData, setCostData] = useState<ProviderCostHistogramResponse | null>(null);
	const [latencyData, setLatencyData] = useState<ProviderLatencyHistogramResponse | null>(null);
	const [loading, setLoading] = useState(true);

	const engines = DEFAULT_ENGINES;

	useEffect(() => {
		if (!isActive) return;

		let cancelled = false;
		async function fetchLoadBalancerData() {
			setLoading(true);

			// Strip any existing engine filter - we're fetching one per engine here
			const baseFilters: LogFilters = {
				...filters,
				start_time: dateUtils.toISOString(startTime),
				end_time: dateUtils.toISOString(endTime),
			};
			delete baseFilters.routing_engine_used;

			const engineFetches = engines.map((engine) => ({
				engine,
				filters: { ...baseFilters, routing_engine_used: [engine] },
			}));

			const [volumeResults, costResults, latencyResults] = await Promise.all([
				Promise.all(engineFetches.map((entry) => triggerVolume({ filters: entry.filters }, false))),
				Promise.all(engineFetches.map((entry) => triggerCost({ filters: entry.filters }, false))),
				Promise.all(engineFetches.map((entry) => triggerLatency({ filters: entry.filters }, false))),
			]);

			if (cancelled) return;

			setVolumeData(
				mergeVolumeHistograms(
					engines,
					volumeResults.map((result) => result.data ?? null),
				),
			);
			setCostData(
				mergeCostHistograms(
					engines,
					costResults.map((result) => result.data ?? null),
				),
			);
			setLatencyData(
				mergeLatencyHistograms(
					engines,
					latencyResults.map((result) => result.data ?? null),
				),
			);
			setLoading(false);
		}

		void fetchLoadBalancerData();
		return () => {
			cancelled = true;
		};
	}, [isActive, refreshKey, filters, startTime, endTime, engines, triggerVolume, triggerCost, triggerLatency]);

	const availableEngines = useMemo(() => {
		const seen = new Set<string>();
		for (const list of [volumeData?.providers, costData?.providers, latencyData?.providers]) {
			for (const engine of list ?? []) {
				if (engine) seen.add(engine);
			}
		}
		return [...seen];
	}, [volumeData?.providers, costData?.providers, latencyData?.providers]);

	const volumeEngines = useMemo(() => volumeData?.providers ?? [], [volumeData?.providers]);
	const costEngines = useMemo(() => costData?.providers ?? [], [costData?.providers]);
	const latencyEngines = useMemo(() => latencyData?.providers ?? [], [latencyData?.providers]);

	// Per-engine routing view: savings are the provider-scoped cache_savings,
	// which already includes Response-Consistency (RCE is a per-row contribution
	// to cache_savings). The flat agentic-cache overlay has no routing engine, so
	// it's intentionally NOT layered here - that lives on the aggregate Overview /
	// Cost-Opt / Cache surfaces via usePlatformSavings.
	const costTotals = useMemo(() => getProviderCostHistogramTotals(costData, costEngine), [costData, costEngine]);

	return (
		<div className="flex flex-col gap-3">
			<div className="grid grid-cols-1 gap-2 lg:grid-cols-2 2xl:grid-cols-3">
			{/* Requests by Engine */}
			<ChartCard
				title="Requests by Engine"
				loading={loading}
				testId="chart-load-balancer-volume"
				headerActions={
					<div className={CHART_HEADER_ACTIONS_CLASS}>
						<div className={CHART_HEADER_LEGEND_CLASS}>
							{volumeEngine === "all" ? (
								volumeEngines.length > 0 && (
									<>
										<Tooltip>
											<TooltipTrigger asChild>
												<span data-testid="load-balancer-volume-legend-trigger" className="flex items-center gap-1">
													<span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: getModelColor(0) }} />
													<span className="text-muted-foreground max-w-[120px] truncate">{engineLabel(volumeEngines[0])}</span>
												</span>
											</TooltipTrigger>
											<TooltipContent>{engineLabel(volumeEngines[0])}</TooltipContent>
										</Tooltip>
										{volumeEngines.length > 1 && (
											<Tooltip>
												<TooltipTrigger asChild>
													<button
														type="button"
														data-testid="load-balancer-volume-legend-more-trigger"
														className="text-muted-foreground cursor-default"
													>
														+{volumeEngines.length - 1} more
													</button>
												</TooltipTrigger>
												<TooltipContent>
													<div className="flex flex-col gap-1">
														{volumeEngines.slice(1).map((engine, idx) => (
															<span key={engine} className="flex items-center gap-1">
																<span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: getModelColor(idx + 1) }} />
																{engineLabel(engine)}
															</span>
														))}
													</div>
												</TooltipContent>
											</Tooltip>
										)}
									</>
								)
							) : (
								<Tooltip>
									<TooltipTrigger asChild>
										<span className="flex items-center gap-1">
											<span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: getModelColor(0) }} />
											<span className="text-muted-foreground max-w-[120px] truncate">{engineLabel(volumeEngine)}</span>
										</span>
									</TooltipTrigger>
									<TooltipContent>{engineLabel(volumeEngine)}</TooltipContent>
								</Tooltip>
							)}
						</div>
						<div className={CHART_HEADER_CONTROLS_CLASS}>
							<RoutingEngineFilterSelect
								engines={availableEngines.length > 0 ? availableEngines : engines}
								selectedEngine={volumeEngine}
								onEngineChange={onVolumeEngineChange}
								data-testid="dashboard-load-balancer-volume-filter"
							/>
							<ChartTypeToggle
								chartType={volumeChartType}
								onToggle={onVolumeChartToggle}
								data-testid="dashboard-load-balancer-volume-chart-toggle"
							/>
						</div>
					</div>
				}
			>
				<ProviderCostChart
					data={volumeData}
					chartType={volumeChartType}
					startTime={startTime}
					endTime={endTime}
					selectedProvider={volumeEngine}
					valueMode="count"
				/>
			</ChartCard>

			{/* Cost by Engine */}
			<ChartCard
				title="Cost by Engine"
				loading={loading}
				testId="chart-load-balancer-cost"
				headerActions={
					<div className={COST_CHART_HEADER_ACTIONS_CLASS}>
						<div className={COST_CHART_HEADER_FILTERS_CLASS}>
							<RoutingEngineFilterSelect
								engines={availableEngines.length > 0 ? availableEngines : engines}
								selectedEngine={costEngine}
								onEngineChange={onCostEngineChange}
								data-testid="dashboard-load-balancer-cost-filter"
							/>
							<ChartTypeToggle
								chartType={costChartType}
								onToggle={onCostChartToggle}
								data-testid="dashboard-load-balancer-cost-chart-toggle"
							/>
						</div>
						<div className={COST_CHART_HEADER_SUMMARY_ROW_CLASS}>
							<div className={CHART_HEADER_LEGEND_CLASS}>
								{costEngine === "all" ? (
									costEngines.length > 0 && (
										<>
											<Tooltip>
												<TooltipTrigger asChild>
													<span data-testid="load-balancer-cost-legend-trigger" className="flex items-center gap-1">
														<span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: getModelColor(0) }} />
														<span className="text-muted-foreground max-w-[120px] truncate">{engineLabel(costEngines[0])}</span>
													</span>
												</TooltipTrigger>
												<TooltipContent>{engineLabel(costEngines[0])}</TooltipContent>
											</Tooltip>
											{costEngines.length > 1 && (
												<Tooltip>
													<TooltipTrigger asChild>
														<button
															type="button"
															data-testid="load-balancer-cost-legend-more-trigger"
															className="text-muted-foreground cursor-default"
														>
															+{costEngines.length - 1} more
														</button>
													</TooltipTrigger>
													<TooltipContent>
														<div className="flex flex-col gap-1">
															{costEngines.slice(1).map((engine, idx) => (
																<span key={engine} className="flex items-center gap-1">
																	<span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: getModelColor(idx + 1) }} />
																	{engineLabel(engine)}
																</span>
															))}
														</div>
													</TooltipContent>
												</Tooltip>
											)}
										</>
									)
								) : (
									<Tooltip>
										<TooltipTrigger asChild>
											<span className="flex items-center gap-1">
												<span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: getModelColor(0) }} />
												<span className="text-muted-foreground max-w-[120px] truncate">{engineLabel(costEngine)}</span>
											</span>
										</TooltipTrigger>
										<TooltipContent>{engineLabel(costEngine)}</TooltipContent>
									</Tooltip>
								)}
							</div>
							<CostHeaderSummary
								totalCost={costTotals.totalCost}
								totalSavings={costTotals.totalSavings}
								testIdPrefix="dashboard-load-balancer-cost-summary"
								className="ml-auto"
							/>
						</div>
					</div>
				}
			>
				<ProviderCostChart
					data={costData}
					chartType={costChartType}
					startTime={startTime}
					endTime={endTime}
					selectedProvider={costEngine}
				/>
			</ChartCard>

			{/* Latency by Engine */}
			<ChartCard
				title="Latency by Engine"
				loading={loading}
				testId="chart-load-balancer-latency"
				headerActions={
					<div className={CHART_HEADER_ACTIONS_CLASS}>
						<div className={CHART_HEADER_LEGEND_CLASS}>
							{latencyEngine === "all" ? (
								latencyEngines.length > 0 && (
									<>
										<Tooltip>
											<TooltipTrigger asChild>
												<span data-testid="load-balancer-latency-legend-trigger" className="flex items-center gap-1">
													<span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: getModelColor(0) }} />
													<span className="text-muted-foreground max-w-[120px] truncate">{engineLabel(latencyEngines[0])}</span>
												</span>
											</TooltipTrigger>
											<TooltipContent>{engineLabel(latencyEngines[0])}</TooltipContent>
										</Tooltip>
										{latencyEngines.length > 1 && (
											<Tooltip>
												<TooltipTrigger asChild>
													<button
														type="button"
														data-testid="load-balancer-latency-legend-more-trigger"
														className="text-muted-foreground cursor-default"
													>
														+{latencyEngines.length - 1} more
													</button>
												</TooltipTrigger>
												<TooltipContent>
													<div className="flex flex-col gap-1">
														{latencyEngines.slice(1).map((engine, idx) => (
															<span key={engine} className="flex items-center gap-1">
																<span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: getModelColor(idx + 1) }} />
																{engineLabel(engine)}
															</span>
														))}
													</div>
												</TooltipContent>
											</Tooltip>
										)}
									</>
								)
							) : (
								<>
									<span className="flex items-center gap-1">
										<span className="h-2 w-2 rounded-full" style={{ backgroundColor: LATENCY_COLORS.avg }} />
										<span className="text-muted-foreground">Avg</span>
									</span>
									<span className="flex items-center gap-1">
										<span className="h-2 w-2 rounded-full" style={{ backgroundColor: LATENCY_COLORS.p90 }} />
										<span className="text-muted-foreground">P90</span>
									</span>
									<span className="flex items-center gap-1">
										<span className="h-2 w-2 rounded-full" style={{ backgroundColor: LATENCY_COLORS.p95 }} />
										<span className="text-muted-foreground">P95</span>
									</span>
									<span className="flex items-center gap-1">
										<span className="h-2 w-2 rounded-full" style={{ backgroundColor: LATENCY_COLORS.p99 }} />
										<span className="text-muted-foreground">P99</span>
									</span>
								</>
							)}
						</div>
						<div className={CHART_HEADER_CONTROLS_CLASS}>
							<RoutingEngineFilterSelect
								engines={availableEngines.length > 0 ? availableEngines : engines}
								selectedEngine={latencyEngine}
								onEngineChange={onLatencyEngineChange}
								data-testid="dashboard-load-balancer-latency-filter"
							/>
							<ChartTypeToggle
								chartType={latencyChartType}
								onToggle={onLatencyChartToggle}
								data-testid="dashboard-load-balancer-latency-chart-toggle"
							/>
						</div>
					</div>
				}
			>
				<ProviderLatencyChart
					data={latencyData}
					chartType={latencyChartType}
					startTime={startTime}
					endTime={endTime}
					selectedProvider={latencyEngine}
				/>
			</ChartCard>
			</div>

			{/* Per-key real-time charts: Model Routing, Rate Limiting,
			    Throttling, Circuit State. Powered by /governance/key-health
			    (polls every 10s), scoped to the active workspace. */}
			<LoadBalancerCharts keyHealth={lbKeyHealth} virtualKeys={lbVirtualKeys} />
		</div>
	);
}
