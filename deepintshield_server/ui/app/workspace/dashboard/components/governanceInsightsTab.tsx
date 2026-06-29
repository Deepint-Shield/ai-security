"use client";

import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
	useGetTeamsQuery,
	useGetVirtualKeysQuery,
	useLazyGetLogsCacheHistogramQuery,
	useLazyGetLogsHistogramQuery,
	useLazyGetLogsProviderLatencyHistogramQuery,
} from "@/lib/store";
import type {
	CacheHistogramBucket,
	CacheHistogramResponse,
	HistogramBucket,
	LogFilters,
	LogsHistogramResponse,
	ProviderLatencyHistogramResponse,
} from "@/lib/types/logs";
import { useEffect, useMemo, useState } from "react";
import {
	CHART_COLORS,
	CHART_HEADER_ACTIONS_CLASS,
	CHART_HEADER_CONTROLS_CLASS,
	CHART_HEADER_LEGEND_CLASS,
	LATENCY_COLORS,
	formatTimestamp,
	getModelColor,
} from "../utils/chartUtils";
import { ChartCard } from "./charts/chartCard";
import { type ChartType, ChartTypeToggle } from "./charts/chartTypeToggle";
import {
	GovernanceTimeSeriesChart,
	type GovernanceTimeSeriesDatum,
	type GovernanceTimeSeriesSeries,
} from "./charts/governanceTimeSeriesChart";
import { ProviderFilterSelect } from "./charts/providerFilterSelect";
import { ProviderLatencyChart } from "./charts/providerLatencyChart";
import { TeamFilterSelect } from "./charts/teamFilterSelect";
import {
	ALL_TEAMS_VALUE,
	buildTeamComparisonRows,
	buildTeamComparisonScopes,
	buildTeamComparisonSeries,
	buildTeamScopedFilters,
	buildTeamVirtualKeyMap,
	mergeProviderLatencyResponses,
} from "./governanceChartUtils";

interface GovernanceInsightsTabProps {
	filters: LogFilters;
	isActive: boolean;
	refreshKey: number;
	startTime: number;
	endTime: number;
	teamId: string;
	providerLatencyChartType: ChartType;
	errorChartType: ChartType;
	cacheChartType: ChartType;
	providerLatencyProvider: string;
	onTeamChange: (teamId: string) => void;
	onProviderLatencyChartToggle: (type: ChartType) => void;
	onErrorChartToggle: (type: ChartType) => void;
	onCacheChartToggle: (type: ChartType) => void;
	onProviderLatencyProviderChange: (provider: string) => void;
}

interface TeamInsightsComparison {
	teamId: string;
	teamName: string;
	histogramData: LogsHistogramResponse | null;
	cacheData: CacheHistogramResponse | null;
	providerLatencyData: ProviderLatencyHistogramResponse | null;
}

function renderComparisonLegend(series: GovernanceTimeSeriesSeries[]) {
	if (series.length === 0) {
		return null;
	}

	return (
		<>
			{series.slice(0, 2).map((seriesItem) => (
				<Tooltip key={seriesItem.key}>
					<TooltipTrigger asChild>
						<span className="flex items-center gap-1">
							<span className="h-2 w-2 rounded-full" style={{ backgroundColor: seriesItem.color }} />
							<span className="text-muted-foreground max-w-[110px] truncate">{seriesItem.label}</span>
						</span>
					</TooltipTrigger>
					<TooltipContent>{seriesItem.label}</TooltipContent>
				</Tooltip>
			))}
			{series.length > 2 && (
				<Tooltip>
					<TooltipTrigger asChild>
						<span className="text-muted-foreground cursor-default">+{series.length - 2} more</span>
					</TooltipTrigger>
					<TooltipContent>
						<div className="flex flex-col gap-1">
							{series.slice(2).map((seriesItem) => (
								<span key={seriesItem.key} className="flex items-center gap-1">
									<span className="h-2 w-2 rounded-full" style={{ backgroundColor: seriesItem.color }} />
									{seriesItem.label}
								</span>
							))}
						</div>
					</TooltipContent>
				</Tooltip>
			)}
		</>
	);
}

function uniqueSortedValues(values: string[]): string[] {
	return [...new Set(values.filter((value) => value.length > 0))].sort((left, right) => left.localeCompare(right));
}

function getErrorRateValue(bucket: HistogramBucket): number {
	return bucket.count > 0 ? Number(((bucket.error / bucket.count) * 100).toFixed(2)) : 0;
}

function getCacheHitRateValue(bucket: CacheHistogramBucket): number {
	return bucket.cache_requests > 0 ? Number(((bucket.cache_hits / bucket.cache_requests) * 100).toFixed(2)) : 0;
}

export function GovernanceInsightsTab({
	filters,
	isActive,
	refreshKey,
	startTime,
	endTime,
	teamId,
	providerLatencyChartType,
	errorChartType,
	cacheChartType,
	providerLatencyProvider,
	onTeamChange,
	onProviderLatencyChartToggle,
	onErrorChartToggle,
	onCacheChartToggle,
	onProviderLatencyProviderChange,
}: GovernanceInsightsTabProps) {
	const { data: teamsData, isLoading: teamsLoading, refetch: refetchTeams } = useGetTeamsQuery(undefined, { skip: !isActive });
	const { data: virtualKeysData, isLoading: virtualKeysLoading, refetch: refetchVirtualKeys } = useGetVirtualKeysQuery(undefined, { skip: !isActive });

	const [triggerHistogram] = useLazyGetLogsHistogramQuery({});
	const [triggerCache] = useLazyGetLogsCacheHistogramQuery();
	const [triggerProviderLatency] = useLazyGetLogsProviderLatencyHistogramQuery();

	const [histogramData, setHistogramData] = useState<LogsHistogramResponse | null>(null);
	const [cacheData, setCacheData] = useState<CacheHistogramResponse | null>(null);
	const [providerLatencyData, setProviderLatencyData] = useState<ProviderLatencyHistogramResponse | null>(null);
	const [comparisonData, setComparisonData] = useState<TeamInsightsComparison[]>([]);
	const [loading, setLoading] = useState(false);

	const teams = useMemo(() => teamsData?.teams ?? [], [teamsData?.teams]);
	const virtualKeys = useMemo(() => virtualKeysData?.virtual_keys ?? [], [virtualKeysData?.virtual_keys]);

	const teamVirtualKeyMap = useMemo(() => buildTeamVirtualKeyMap(teams, virtualKeys), [teams, virtualKeys]);
	const teamOptions = useMemo(() => teams.map((team) => ({ value: team.id, label: team.name })), [teams]);
	const effectiveTeamId = useMemo(
		() => (teamId === ALL_TEAMS_VALUE || teamOptions.some((team) => team.value === teamId) ? teamId : ALL_TEAMS_VALUE),
		[teamId, teamOptions],
	);
	const isAllTeamsView = effectiveTeamId === ALL_TEAMS_VALUE;

	const teamScoped = useMemo(
		() => buildTeamScopedFilters(filters, effectiveTeamId, teamVirtualKeyMap),
		[filters, effectiveTeamId, teamVirtualKeyMap],
	);
	const comparisonScopes = useMemo(
		() => buildTeamComparisonScopes(filters, teams, teamVirtualKeyMap),
		[filters, teams, teamVirtualKeyMap],
	);
	const comparisonSeries = useMemo(() => buildTeamComparisonSeries(comparisonScopes), [comparisonScopes]);

	useEffect(() => {
		if (!isActive || refreshKey === 0) return;
		void refetchTeams();
		void refetchVirtualKeys();
	}, [isActive, refreshKey, refetchTeams, refetchVirtualKeys]);

	useEffect(() => {
		if (!isActive) return;

		let cancelled = false;

		const clearSingleTeamState = () => {
			setHistogramData(null);
			setCacheData(null);
			setProviderLatencyData(null);
		};

		const loadData = async () => {
			setLoading(true);

			try {
				if (isAllTeamsView) {
					if (comparisonScopes.length === 0) {
						clearSingleTeamState();
						setComparisonData([]);
						return;
					}

					const results = await Promise.all(
						comparisonScopes.map(async (scope) => {
							const request = { filters: scope.filters };
							const [histogramResult, cacheResult, providerLatencyResult] = await Promise.all([
								triggerHistogram(request, false),
								triggerCache(request, false),
								triggerProviderLatency(request, false),
							]);

							return {
								teamId: scope.teamId,
								teamName: scope.teamName,
								histogramData: histogramResult.data ?? null,
								cacheData: cacheResult.data ?? null,
								providerLatencyData: providerLatencyResult.data ?? null,
							};
						}),
					);

					if (cancelled) return;

					clearSingleTeamState();
					setComparisonData(results);
					return;
				}

				if (!teamScoped.hasData) {
					clearSingleTeamState();
					setComparisonData([]);
					return;
				}

				const request = { filters: teamScoped.filters };
				const [histogramResult, cacheResult, providerLatencyResult] = await Promise.all([
					triggerHistogram(request, false),
					triggerCache(request, false),
					triggerProviderLatency(request, false),
				]);

				if (cancelled) return;

				setComparisonData([]);
				setHistogramData(histogramResult.data ?? null);
				setCacheData(cacheResult.data ?? null);
				setProviderLatencyData(providerLatencyResult.data ?? null);
			} finally {
				if (!cancelled) {
					setLoading(false);
				}
			}
		};

		void loadData();

		return () => {
			cancelled = true;
		};
	}, [comparisonScopes, isActive, isAllTeamsView, refreshKey, teamScoped, triggerCache, triggerHistogram, triggerProviderLatency]);

	const providerLatencyProviders = useMemo(
		() =>
			isAllTeamsView
				? uniqueSortedValues(comparisonData.flatMap((item) => item.providerLatencyData?.providers ?? []))
				: providerLatencyData?.providers ?? [],
		[comparisonData, isAllTeamsView, providerLatencyData?.providers],
	);
	const effectiveProviderLatencyProvider = providerLatencyProviders.includes(providerLatencyProvider) ? providerLatencyProvider : "all";

	const mergedProviderLatency = useMemo(
		() => (isAllTeamsView ? mergeProviderLatencyResponses(comparisonData.map((d) => d.providerLatencyData)) : providerLatencyData),
		[comparisonData, isAllTeamsView, providerLatencyData],
	);

	const errorRateData = useMemo<GovernanceTimeSeriesDatum[]>(() => {
		if (isAllTeamsView) {
			return buildTeamComparisonRows(
				comparisonSeries.map((series) => ({ teamId: series.key })),
				comparisonData.map((item) => ({ teamId: item.teamId, buckets: item.histogramData?.buckets })),
				startTime,
				endTime,
				comparisonData.find((item) => item.histogramData?.bucket_size_seconds)?.histogramData?.bucket_size_seconds,
				getErrorRateValue,
			);
		}

		if (!histogramData?.buckets || !histogramData.bucket_size_seconds) {
			return [];
		}

		return histogramData.buckets.map((bucket, index) => ({
			timestamp: bucket.timestamp,
			index,
			formattedTime: formatTimestamp(bucket.timestamp, histogramData.bucket_size_seconds),
			error_rate: getErrorRateValue(bucket),
			error_requests: bucket.error,
			total_requests: bucket.count,
		}));
	}, [comparisonData, comparisonSeries, endTime, histogramData, isAllTeamsView, startTime]);

	const cacheHitRateData = useMemo<GovernanceTimeSeriesDatum[]>(() => {
		if (isAllTeamsView) {
			return buildTeamComparisonRows(
				comparisonSeries.map((series) => ({ teamId: series.key })),
				comparisonData.map((item) => ({ teamId: item.teamId, buckets: item.cacheData?.buckets })),
				startTime,
				endTime,
				comparisonData.find((item) => item.cacheData?.bucket_size_seconds)?.cacheData?.bucket_size_seconds,
				getCacheHitRateValue,
			);
		}

		if (!cacheData?.buckets || !cacheData.bucket_size_seconds) {
			return [];
		}

		return cacheData.buckets.map((bucket, index) => ({
			timestamp: bucket.timestamp,
			index,
			formattedTime: formatTimestamp(bucket.timestamp, cacheData.bucket_size_seconds),
			cache_hit_rate: getCacheHitRateValue(bucket),
			cache_hits: bucket.cache_hits,
			cache_requests: bucket.cache_requests,
		}));
	}, [cacheData, comparisonData, comparisonSeries, endTime, isAllTeamsView, startTime]);

	const errorRateSeries = useMemo<GovernanceTimeSeriesSeries[]>(
		() => (isAllTeamsView ? comparisonSeries : [{ key: "error_rate", label: "Error Rate", color: CHART_COLORS.error }]),
		[comparisonSeries, isAllTeamsView],
	);
	const cacheSeries = useMemo<GovernanceTimeSeriesSeries[]>(
		() => (isAllTeamsView ? comparisonSeries : [{ key: "cache_hit_rate", label: "Cache Hit Rate", color: CHART_COLORS.cachedReadTokens }]),
		[comparisonSeries, isAllTeamsView],
	);

	const renderTeamControl = (testId: string) => (
		<TeamFilterSelect
			teams={teamOptions}
			selectedTeamId={effectiveTeamId}
			onTeamChange={onTeamChange}
			data-testid={testId}
		/>
	);

	const teamChartLoading = teamsLoading || virtualKeysLoading || loading;

	const providerLatencyLegend = effectiveProviderLatencyProvider === "all" ? (
			providerLatencyProviders.length > 0 && (
				<>
					<Tooltip>
						<TooltipTrigger asChild>
							<span className="flex items-center gap-1">
								<span className="h-2 w-2 rounded-full" style={{ backgroundColor: getModelColor(0) }} />
								<span className="text-muted-foreground max-w-[100px] truncate">{providerLatencyProviders[0]}</span>
							</span>
						</TooltipTrigger>
						<TooltipContent>{providerLatencyProviders[0]}</TooltipContent>
					</Tooltip>
					{providerLatencyProviders.length > 1 && (
						<Tooltip>
							<TooltipTrigger asChild>
								<span className="text-muted-foreground cursor-default">+{providerLatencyProviders.length - 1} more</span>
							</TooltipTrigger>
							<TooltipContent>
								<div className="flex flex-col gap-1">
									{providerLatencyProviders.slice(1).map((provider, index) => (
										<span key={provider} className="flex items-center gap-1">
											<span className="h-2 w-2 rounded-full" style={{ backgroundColor: getModelColor(index + 1) }} />
											{provider}
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
	);

	const errorLegend = isAllTeamsView ? renderComparisonLegend(comparisonSeries) : (
		<span className="flex items-center gap-1">
			<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.error }} />
			<span className="text-muted-foreground">Error Rate</span>
		</span>
	);

	const cacheLegend = isAllTeamsView ? renderComparisonLegend(comparisonSeries) : (
		<span className="flex items-center gap-1">
			<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.cachedReadTokens }} />
			<span className="text-muted-foreground">Cache Hit Rate</span>
		</span>
	);

	return (
		<div className="grid grid-cols-1 gap-2 lg:grid-cols-2 2xl:grid-cols-3">
			<ChartCard
				title="Provider Latency"
				loading={teamChartLoading}
				testId="chart-governance-team-provider-latency"
				headerActions={
					<div className={CHART_HEADER_ACTIONS_CLASS}>
						<div className={CHART_HEADER_LEGEND_CLASS}>{providerLatencyLegend}</div>
						<div className={CHART_HEADER_CONTROLS_CLASS}>
							{renderTeamControl("dashboard-governance-provider-latency-team-filter")}
							<ProviderFilterSelect
								providers={providerLatencyProviders}
								selectedProvider={effectiveProviderLatencyProvider}
								onProviderChange={onProviderLatencyProviderChange}
								data-testid="dashboard-governance-provider-latency-filter"
							/>
							<ChartTypeToggle
								chartType={providerLatencyChartType}
								onToggle={onProviderLatencyChartToggle}
								data-testid="dashboard-governance-provider-latency-chart-toggle"
							/>
						</div>
					</div>
				}
			>
				<ProviderLatencyChart
					data={mergedProviderLatency}
					chartType={providerLatencyChartType}
					startTime={startTime}
					endTime={endTime}
					selectedProvider={effectiveProviderLatencyProvider}
				/>
			</ChartCard>

			<ChartCard
				title="Error Rate"
				loading={teamChartLoading}
				testId="chart-governance-team-errors"
				headerActions={
					<div className={CHART_HEADER_ACTIONS_CLASS}>
						<div className={CHART_HEADER_LEGEND_CLASS}>{errorLegend}</div>
						<div className={CHART_HEADER_CONTROLS_CLASS}>
							{renderTeamControl("dashboard-governance-error-team-filter")}
							<ChartTypeToggle chartType={errorChartType} onToggle={onErrorChartToggle} data-testid="dashboard-governance-error-chart-toggle" />
						</div>
					</div>
				}
			>
				<GovernanceTimeSeriesChart
					data={errorRateData}
					series={errorRateSeries}
					chartType={errorChartType}
					startTime={startTime}
					endTime={endTime}
					yAxisFormatter={(value) => `${value.toFixed(1)}%`}
					tooltipValueFormatter={(value) => `${value.toFixed(2)}%`}
					tooltipFooter={
						isAllTeamsView
							? undefined
							: (datum) => (
									<div className="border-border/70 flex items-center justify-between gap-4 border-t pt-2">
										<span className="dashboard-chart-tooltip-meta">Errors / Total</span>
										<span className="font-medium">
											{Number(datum.error_requests || 0).toLocaleString()} / {Number(datum.total_requests || 0).toLocaleString()}
										</span>
									</div>
								)
					}
					yAxisWidth={58}
				/>
			</ChartCard>

			<ChartCard
				title="Cache Hit Rate"
				loading={teamChartLoading}
				testId="chart-governance-team-cache"
				headerActions={
					<div className={CHART_HEADER_ACTIONS_CLASS}>
						<div className={CHART_HEADER_LEGEND_CLASS}>{cacheLegend}</div>
						<div className={CHART_HEADER_CONTROLS_CLASS}>
							{renderTeamControl("dashboard-governance-cache-team-filter")}
							<ChartTypeToggle chartType={cacheChartType} onToggle={onCacheChartToggle} data-testid="dashboard-governance-cache-chart-toggle" />
						</div>
					</div>
				}
			>
				<GovernanceTimeSeriesChart
					data={cacheHitRateData}
					series={cacheSeries}
					chartType={cacheChartType}
					startTime={startTime}
					endTime={endTime}
					yAxisFormatter={(value) => `${value.toFixed(1)}%`}
					tooltipValueFormatter={(value) => `${value.toFixed(2)}%`}
					tooltipFooter={
						isAllTeamsView
							? undefined
							: (datum) => (
									<div className="border-border/70 flex items-center justify-between gap-4 border-t pt-2">
										<span className="dashboard-chart-tooltip-meta">Hits / Requests</span>
										<span className="font-medium">
											{Number(datum.cache_hits || 0).toLocaleString()} / {Number(datum.cache_requests || 0).toLocaleString()}
										</span>
									</div>
								)
					}
					yAxisWidth={58}
				/>
			</ChartCard>
		</div>
	);
}
