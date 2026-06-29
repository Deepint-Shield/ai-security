"use client";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
	useGetTeamsQuery,
	useGetVirtualKeysQuery,
	useLazyGetLogsCostHistogramQuery,
	useLazyGetLogsHistogramQuery,
	useLazyGetLogsLatencyHistogramQuery,
	useLazyGetLogsProviderCostHistogramQuery,
	useLazyGetLogsProviderTokenHistogramQuery,
	useLazyGetLogsTokenHistogramQuery,
} from "@/lib/store";
import type {
	CostHistogramBucket,
	CostHistogramResponse,
	LatencyHistogramBucket,
	LatencyHistogramResponse,
	LogFilters,
	LogsHistogramResponse,
	ProviderCostHistogramResponse,
	ProviderTokenHistogramResponse,
	TokenHistogramBucket,
	TokenHistogramResponse,
} from "@/lib/types/logs";
import { useEffect, useMemo, useState } from "react";
import {
	CHART_COLORS,
	CHART_HEADER_ACTIONS_CLASS,
	CHART_HEADER_CONTROLS_CLASS,
	CHART_HEADER_LEGEND_CLASS,
	COST_CHART_HEADER_ACTIONS_CLASS,
	COST_CHART_HEADER_FILTERS_CLASS,
	COST_CHART_HEADER_SUMMARY_ROW_CLASS,
	COST_CHART_Y_AXIS_WIDTH,
	LATENCY_COLORS,
	formatCost,
	formatCostAxis,
	formatLatency,
	formatTokens,
	getModelColor,
} from "../utils/chartUtils";
import {
	getCostHistogramTotals,
	getCostHistogramTotalsFromResponses,
	getProviderCostHistogramTotals,
	getProviderCostHistogramTotalsFromResponses,
} from "../utils/costTotals";
import { ChartCard } from "./charts/chartCard";
import { type ChartType, ChartTypeToggle } from "./charts/chartTypeToggle";
import { CostChart } from "./charts/costChart";
import { CostHeaderSummary } from "./charts/costHeaderSummary";
import {
	GovernanceTimeSeriesChart,
	type GovernanceTimeSeriesSeries,
} from "./charts/governanceTimeSeriesChart";
import { LatencyChart } from "./charts/latencyChart";
import { LogVolumeChart } from "./charts/logVolumeChart";
import { ModelFilterSelect } from "./charts/modelFilterSelect";
import { ProviderCostChart } from "./charts/providerCostChart";
import { ProviderFilterSelect } from "./charts/providerFilterSelect";
import { ProviderTokenChart } from "./charts/providerTokenChart";
import { TeamFilterSelect } from "./charts/teamFilterSelect";
import { TokenUsageChart } from "./charts/tokenUsageChart";
import { GovernanceInsightsTab } from "./governanceInsightsTab";
import {
	ALL_TEAMS_VALUE,
	buildTeamComparisonRows,
	buildTeamComparisonScopes,
	buildTeamComparisonSeries,
	buildTeamScopedFilters,
	buildTeamVirtualKeyMap,
	mergeProviderCostResponses,
	mergeProviderTokenResponses,
} from "./governanceChartUtils";

interface GovernanceTabProps {
	filters: LogFilters;
	isActive: boolean;
	refreshKey: number;
	startTime: number;
	endTime: number;
	teamId: string;
	requestChartType: ChartType;
	tokenChartType: ChartType;
	costChartType: ChartType;
	latencyChartType: ChartType;
	providerCostChartType: ChartType;
	providerTokenChartType: ChartType;
	providerLatencyChartType: ChartType;
	errorChartType: ChartType;
	cacheChartType: ChartType;
	costModel: string;
	providerCostProvider: string;
	providerTokenProvider: string;
	providerLatencyProvider: string;
	onTeamChange: (teamId: string) => void;
	onRequestChartToggle: (type: ChartType) => void;
	onTokenChartToggle: (type: ChartType) => void;
	onCostChartToggle: (type: ChartType) => void;
	onLatencyChartToggle: (type: ChartType) => void;
	onProviderCostChartToggle: (type: ChartType) => void;
	onProviderTokenChartToggle: (type: ChartType) => void;
	onProviderLatencyChartToggle: (type: ChartType) => void;
	onErrorChartToggle: (type: ChartType) => void;
	onCacheChartToggle: (type: ChartType) => void;
	onCostModelChange: (model: string) => void;
	onProviderCostProviderChange: (provider: string) => void;
	onProviderTokenProviderChange: (provider: string) => void;
	onProviderLatencyProviderChange: (provider: string) => void;
}

interface TeamMetricsComparison {
	teamId: string;
	teamName: string;
	histogramData: LogsHistogramResponse | null;
	tokenData: TokenHistogramResponse | null;
	costData: CostHistogramResponse | null;
	latencyData: LatencyHistogramResponse | null;
	providerCostData: ProviderCostHistogramResponse | null;
	providerTokenData: ProviderTokenHistogramResponse | null;
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

export function GovernanceTab({
	filters,
	isActive,
	refreshKey,
	startTime,
	endTime,
	teamId,
	requestChartType,
	tokenChartType,
	costChartType,
	latencyChartType,
	providerCostChartType,
	providerTokenChartType,
	providerLatencyChartType,
	errorChartType,
	cacheChartType,
	costModel,
	providerCostProvider,
	providerTokenProvider,
	providerLatencyProvider,
	onTeamChange,
	onRequestChartToggle,
	onTokenChartToggle,
	onCostChartToggle,
	onLatencyChartToggle,
	onProviderCostChartToggle,
	onProviderTokenChartToggle,
	onProviderLatencyChartToggle,
	onErrorChartToggle,
	onCacheChartToggle,
	onCostModelChange,
	onProviderCostProviderChange,
	onProviderTokenProviderChange,
	onProviderLatencyProviderChange,
}: GovernanceTabProps) {
	const { data: teamsData, isLoading: teamsLoading, refetch: refetchTeams } = useGetTeamsQuery(undefined, { skip: !isActive });
	const { data: virtualKeysData, isLoading: virtualKeysLoading, refetch: refetchVirtualKeys } = useGetVirtualKeysQuery(undefined, { skip: !isActive });

	const [triggerHistogram] = useLazyGetLogsHistogramQuery({});
	const [triggerTokens] = useLazyGetLogsTokenHistogramQuery();
	const [triggerCost] = useLazyGetLogsCostHistogramQuery();
	const [triggerLatency] = useLazyGetLogsLatencyHistogramQuery();
	const [triggerProviderCost] = useLazyGetLogsProviderCostHistogramQuery();
	const [triggerProviderTokens] = useLazyGetLogsProviderTokenHistogramQuery();

	const [histogramData, setHistogramData] = useState<LogsHistogramResponse | null>(null);
	const [tokenData, setTokenData] = useState<TokenHistogramResponse | null>(null);
	const [costData, setCostData] = useState<CostHistogramResponse | null>(null);
	const [latencyData, setLatencyData] = useState<LatencyHistogramResponse | null>(null);
	const [providerCostData, setProviderCostData] = useState<ProviderCostHistogramResponse | null>(null);
	const [providerTokenData, setProviderTokenData] = useState<ProviderTokenHistogramResponse | null>(null);
	const [comparisonData, setComparisonData] = useState<TeamMetricsComparison[]>([]);
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
			setTokenData(null);
			setCostData(null);
			setLatencyData(null);
			setProviderCostData(null);
			setProviderTokenData(null);
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
							const [
								histogramResult,
								tokenResult,
								costResult,
								latencyResult,
								providerCostResult,
								providerTokenResult,
							] = await Promise.all([
								triggerHistogram(request, false),
								triggerTokens(request, false),
								triggerCost(request, false),
								triggerLatency(request, false),
								triggerProviderCost(request, false),
								triggerProviderTokens(request, false),
							]);

								const result: TeamMetricsComparison = {
									teamId: scope.teamId,
									teamName: scope.teamName,
									histogramData: histogramResult.data ?? null,
									tokenData: tokenResult.data ?? null,
									costData: costResult.data ?? null,
									latencyData: latencyResult.data ?? null,
									providerCostData: providerCostResult.data ?? null,
									providerTokenData: providerTokenResult.data ?? null,
								};

								return result;
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
				const [
					histogramResult,
					tokenResult,
					costResult,
					latencyResult,
					providerCostResult,
					providerTokenResult,
				] = await Promise.all([
					triggerHistogram(request, false),
					triggerTokens(request, false),
					triggerCost(request, false),
					triggerLatency(request, false),
					triggerProviderCost(request, false),
					triggerProviderTokens(request, false),
				]);

				if (cancelled) return;

				setComparisonData([]);
				setHistogramData(histogramResult.data ?? null);
				setTokenData(tokenResult.data ?? null);
				setCostData(costResult.data ?? null);
				setLatencyData(latencyResult.data ?? null);
				setProviderCostData(providerCostResult.data ?? null);
				setProviderTokenData(providerTokenResult.data ?? null);
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
	}, [
		comparisonScopes,
		isActive,
		isAllTeamsView,
		refreshKey,
		teamScoped,
		triggerCost,
		triggerHistogram,
		triggerLatency,
		triggerProviderCost,
		triggerProviderTokens,
		triggerTokens,
	]);

	const availableCostModels = useMemo(
		() =>
			isAllTeamsView
				? uniqueSortedValues(comparisonData.flatMap((item) => item.costData?.models ?? []))
				: costData?.models ?? [],
		[comparisonData, costData?.models, isAllTeamsView],
	);
	const effectiveCostModel = availableCostModels.includes(costModel) ? costModel : "all";

	const providerCostProviders = useMemo(
		() =>
			isAllTeamsView
				? uniqueSortedValues(comparisonData.flatMap((item) => item.providerCostData?.providers ?? []))
				: providerCostData?.providers ?? [],
		[comparisonData, isAllTeamsView, providerCostData?.providers],
	);
	const effectiveProviderCostProvider = providerCostProviders.includes(providerCostProvider) ? providerCostProvider : "all";

	const providerTokenProviders = useMemo(
		() =>
			isAllTeamsView
				? uniqueSortedValues(comparisonData.flatMap((item) => item.providerTokenData?.providers ?? []))
				: providerTokenData?.providers ?? [],
		[comparisonData, isAllTeamsView, providerTokenData?.providers],
	);
	const effectiveProviderTokenProvider = providerTokenProviders.includes(providerTokenProvider) ? providerTokenProvider : "all";

	const requestComparisonData = useMemo(
		() =>
			buildTeamComparisonRows(
				comparisonSeries.map((series) => ({ teamId: series.key })),
				comparisonData.map((item) => ({ teamId: item.teamId, buckets: item.histogramData?.buckets })),
				startTime,
				endTime,
				comparisonData.find((item) => item.histogramData?.bucket_size_seconds)?.histogramData?.bucket_size_seconds,
				(bucket: LogsHistogramResponse["buckets"][number]) => bucket.count,
			),
		[comparisonData, comparisonSeries, endTime, startTime],
	);

	const tokenComparisonData = useMemo(
		() =>
			buildTeamComparisonRows(
				comparisonSeries.map((series) => ({ teamId: series.key })),
				comparisonData.map((item) => ({ teamId: item.teamId, buckets: item.tokenData?.buckets })),
				startTime,
				endTime,
				comparisonData.find((item) => item.tokenData?.bucket_size_seconds)?.tokenData?.bucket_size_seconds,
				(bucket: TokenHistogramBucket) => bucket.total_tokens,
			),
		[comparisonData, comparisonSeries, endTime, startTime],
	);

	const costComparisonData = useMemo(
		() =>
			buildTeamComparisonRows(
				comparisonSeries.map((series) => ({ teamId: series.key })),
				comparisonData.map((item) => ({ teamId: item.teamId, buckets: item.costData?.buckets })),
				startTime,
				endTime,
				comparisonData.find((item) => item.costData?.bucket_size_seconds)?.costData?.bucket_size_seconds,
				(bucket: CostHistogramBucket) => (effectiveCostModel === "all" ? bucket.total_cost : (bucket.by_model?.[effectiveCostModel] ?? 0)),
			),
		[comparisonData, comparisonSeries, effectiveCostModel, endTime, startTime],
	);

	const latencyComparisonData = useMemo(
		() =>
			buildTeamComparisonRows(
				comparisonSeries.map((series) => ({ teamId: series.key })),
				comparisonData.map((item) => ({ teamId: item.teamId, buckets: item.latencyData?.buckets })),
				startTime,
				endTime,
				comparisonData.find((item) => item.latencyData?.bucket_size_seconds)?.latencyData?.bucket_size_seconds,
				(bucket: LatencyHistogramBucket) => bucket.avg_latency,
			),
		[comparisonData, comparisonSeries, endTime, startTime],
	);

	// Merge all teams' provider data so the standard per-provider chart
	// components can render a per-provider color breakdown in All Teams view.
	const mergedProviderCost = useMemo(
		() => (isAllTeamsView ? mergeProviderCostResponses(comparisonData.map((d) => d.providerCostData)) : providerCostData),
		[comparisonData, isAllTeamsView, providerCostData],
	);
	const mergedProviderTokens = useMemo(
		() => (isAllTeamsView ? mergeProviderTokenResponses(comparisonData.map((d) => d.providerTokenData)) : providerTokenData),
		[comparisonData, isAllTeamsView, providerTokenData],
	);

	const teamCostTotals = useMemo(
		() =>
			isAllTeamsView
				? getCostHistogramTotalsFromResponses(
						comparisonData.map((item) => item.costData),
						effectiveCostModel,
					)
				: getCostHistogramTotals(costData, effectiveCostModel),
		[comparisonData, costData, effectiveCostModel, isAllTeamsView],
	);

	const teamProviderCostTotals = useMemo(
		() => getProviderCostHistogramTotals(mergedProviderCost, effectiveProviderCostProvider),
		[mergedProviderCost, effectiveProviderCostProvider],
	);

	const renderTeamControl = (testId: string) => (
		<TeamFilterSelect
			teams={teamOptions}
			selectedTeamId={effectiveTeamId}
			onTeamChange={onTeamChange}
			data-testid={testId}
		/>
	);

	const requestLegend = isAllTeamsView ? renderComparisonLegend(comparisonSeries) : (
		<>
			<span className="flex items-center gap-1">
				<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.success }} />
				<span className="text-muted-foreground">Success</span>
			</span>
			<span className="flex items-center gap-1">
				<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.error }} />
				<span className="text-muted-foreground">Error</span>
			</span>
		</>
	);

	const tokenLegend = isAllTeamsView ? renderComparisonLegend(comparisonSeries) : (
		<>
			<span className="flex items-center gap-1">
				<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.promptTokens }} />
				<span className="text-muted-foreground">Input</span>
			</span>
			<span className="flex items-center gap-1">
				<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.completionTokens }} />
				<span className="text-muted-foreground">Output</span>
			</span>
			<span className="flex items-center gap-1">
				<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.cachedReadTokens }} />
				<span className="text-muted-foreground">Cached</span>
			</span>
		</>
	);

	const costLegend = isAllTeamsView ? renderComparisonLegend(comparisonSeries) : (
		<>
			<span className="flex items-center gap-1">
				<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.cacheSavings }} />
				<span className="text-muted-foreground">Cache savings</span>
			</span>
			{effectiveCostModel === "all" ? (
				availableCostModels.length > 0 && (
					<>
						<Tooltip>
							<TooltipTrigger asChild>
								<span className="flex items-center gap-1">
									<span className="h-2 w-2 rounded-full" style={{ backgroundColor: getModelColor(0) }} />
									<span className="text-muted-foreground max-w-[100px] truncate">{availableCostModels[0]}</span>
								</span>
							</TooltipTrigger>
							<TooltipContent>{availableCostModels[0]}</TooltipContent>
						</Tooltip>
						{availableCostModels.length > 1 && (
							<Tooltip>
								<TooltipTrigger asChild>
									<span className="text-muted-foreground cursor-default">+{availableCostModels.length - 1} more</span>
								</TooltipTrigger>
								<TooltipContent>
									<div className="flex flex-col gap-1">
										{availableCostModels.slice(1).map((model, index) => (
											<span key={model} className="flex items-center gap-1">
												<span className="h-2 w-2 rounded-full" style={{ backgroundColor: getModelColor(index + 1) }} />
												{model}
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
							<span className="h-2 w-2 rounded-full" style={{ backgroundColor: getModelColor(0) }} />
							<span className="text-muted-foreground max-w-[100px] truncate">{effectiveCostModel}</span>
						</span>
					</TooltipTrigger>
					<TooltipContent>{effectiveCostModel}</TooltipContent>
				</Tooltip>
			)}
		</>
	);

	const latencyLegend = isAllTeamsView ? renderComparisonLegend(comparisonSeries) : (
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

	const providerCostLegend = effectiveProviderCostProvider === "all" ? (
		providerCostProviders.length > 0 && (
			<>
				<Tooltip>
					<TooltipTrigger asChild>
						<span className="flex items-center gap-1">
							<span className="h-2 w-2 rounded-full" style={{ backgroundColor: getModelColor(0) }} />
							<span className="text-muted-foreground max-w-[100px] truncate">{providerCostProviders[0]}</span>
						</span>
					</TooltipTrigger>
					<TooltipContent>{providerCostProviders[0]}</TooltipContent>
				</Tooltip>
				{providerCostProviders.length > 1 && (
					<Tooltip>
						<TooltipTrigger asChild>
							<span className="text-muted-foreground cursor-default">+{providerCostProviders.length - 1} more</span>
						</TooltipTrigger>
						<TooltipContent>
							<div className="flex flex-col gap-1">
								{providerCostProviders.slice(1).map((provider, index) => (
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
		<Tooltip>
			<TooltipTrigger asChild>
				<span className="flex items-center gap-1">
					<span className="h-2 w-2 rounded-full" style={{ backgroundColor: getModelColor(0) }} />
					<span className="text-muted-foreground max-w-[100px] truncate">{effectiveProviderCostProvider}</span>
				</span>
			</TooltipTrigger>
			<TooltipContent>{effectiveProviderCostProvider}</TooltipContent>
		</Tooltip>
	);

	const providerTokenLegend = effectiveProviderTokenProvider === "all" ? (
		providerTokenProviders.length > 0 && (
			<>
				<Tooltip>
					<TooltipTrigger asChild>
						<span className="flex items-center gap-1">
							<span className="h-2 w-2 rounded-full" style={{ backgroundColor: getModelColor(0) }} />
							<span className="text-muted-foreground max-w-[100px] truncate">{providerTokenProviders[0]}</span>
						</span>
					</TooltipTrigger>
					<TooltipContent>{providerTokenProviders[0]}</TooltipContent>
				</Tooltip>
				{providerTokenProviders.length > 1 && (
					<Tooltip>
						<TooltipTrigger asChild>
							<span className="text-muted-foreground cursor-default">+{providerTokenProviders.length - 1} more</span>
						</TooltipTrigger>
						<TooltipContent>
							<div className="flex flex-col gap-1">
								{providerTokenProviders.slice(1).map((provider, index) => (
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
				<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.promptTokens }} />
				<span className="text-muted-foreground">Input</span>
			</span>
			<span className="flex items-center gap-1">
				<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.completionTokens }} />
				<span className="text-muted-foreground">Output</span>
			</span>
		</>
	);

	const isChartLoading = teamsLoading || virtualKeysLoading || loading;

	const teamMappingReady = !teamsLoading && !virtualKeysLoading;
	const hasMappedVirtualKeys = useMemo(
		() => Array.from(teamVirtualKeyMap.values()).some((ids) => ids.length > 0),
		[teamVirtualKeyMap],
	);
	const showTeamMappingNotice = teamMappingReady && (teams.length === 0 || !hasMappedVirtualKeys);
	const teamMappingNoticeMessage = teams.length === 0
		? "No teams exist yet. Create a team in Governance → Teams and attach virtual keys to it to populate these charts."
		: virtualKeys.length === 0
			? "No virtual keys exist yet. Create a virtual key under Governance → Virtual Keys and attach it to a team."
			: "Virtual keys exist but none are attached to a team. Open Governance → Virtual Keys, edit a key, and set its team to populate team usage.";

	return (
		<div className="flex flex-col gap-2">
			{showTeamMappingNotice ? (
				<Alert variant="info" data-testid="dashboard-governance-team-mapping-notice">
					<AlertTitle>Team usage charts have no data to render</AlertTitle>
					<AlertDescription>{teamMappingNoticeMessage}</AlertDescription>
				</Alert>
			) : null}
			<div className="grid grid-cols-1 gap-2 lg:grid-cols-2 2xl:grid-cols-3">
				<ChartCard
					title="Requests"
					loading={isChartLoading}
					testId="chart-governance-team-requests"
					headerActions={
						<div className={CHART_HEADER_ACTIONS_CLASS}>
							<div className={CHART_HEADER_LEGEND_CLASS}>{requestLegend}</div>
							<div className={CHART_HEADER_CONTROLS_CLASS}>
								{renderTeamControl("dashboard-governance-request-team-filter")}
								<ChartTypeToggle chartType={requestChartType} onToggle={onRequestChartToggle} data-testid="dashboard-governance-request-chart-toggle" />
							</div>
						</div>
					}
				>
					{isAllTeamsView ? (
						<GovernanceTimeSeriesChart
							data={requestComparisonData}
							series={comparisonSeries}
							chartType={requestChartType}
							startTime={startTime}
							endTime={endTime}
						/>
					) : (
						<LogVolumeChart data={histogramData} chartType={requestChartType} startTime={startTime} endTime={endTime} />
					)}
				</ChartCard>

				<ChartCard
					title="Tokens"
					loading={isChartLoading}
					testId="chart-governance-team-tokens"
					headerActions={
						<div className={CHART_HEADER_ACTIONS_CLASS}>
							<div className={CHART_HEADER_LEGEND_CLASS}>{tokenLegend}</div>
							<div className={CHART_HEADER_CONTROLS_CLASS}>
								{renderTeamControl("dashboard-governance-token-team-filter")}
								<ChartTypeToggle chartType={tokenChartType} onToggle={onTokenChartToggle} data-testid="dashboard-governance-token-chart-toggle" />
							</div>
						</div>
					}
				>
					{isAllTeamsView ? (
						<GovernanceTimeSeriesChart
							data={tokenComparisonData}
							series={comparisonSeries}
							chartType={tokenChartType}
							startTime={startTime}
							endTime={endTime}
							yAxisFormatter={formatTokens}
							tooltipValueFormatter={(value) => formatTokens(value)}
						/>
					) : (
						<TokenUsageChart data={tokenData} chartType={tokenChartType} startTime={startTime} endTime={endTime} />
					)}
				</ChartCard>

				<ChartCard
					title="Cost"
					loading={isChartLoading}
					testId="chart-governance-team-cost"
					headerActions={
						<div className={COST_CHART_HEADER_ACTIONS_CLASS}>
							<div className={COST_CHART_HEADER_FILTERS_CLASS}>
								{renderTeamControl("dashboard-governance-cost-team-filter")}
								<ModelFilterSelect
									models={availableCostModels}
									selectedModel={effectiveCostModel}
									onModelChange={onCostModelChange}
									data-testid="dashboard-governance-cost-model-filter"
								/>
								<ChartTypeToggle chartType={costChartType} onToggle={onCostChartToggle} data-testid="dashboard-governance-cost-chart-toggle" />
							</div>
							<div className={COST_CHART_HEADER_SUMMARY_ROW_CLASS}>
								<div className={CHART_HEADER_LEGEND_CLASS}>{costLegend}</div>
								<CostHeaderSummary
									totalCost={teamCostTotals.totalCost}
									totalSavings={teamCostTotals.totalSavings}
									testIdPrefix="dashboard-governance-team-cost-summary"
									className="ml-auto"
								/>
							</div>
						</div>
					}
				>
					{isAllTeamsView ? (
						<GovernanceTimeSeriesChart
							data={costComparisonData}
							series={comparisonSeries}
							chartType={costChartType}
							startTime={startTime}
							endTime={endTime}
							yAxisFormatter={formatCostAxis}
							tooltipValueFormatter={(value) => formatCost(value)}
							yAxisWidth={COST_CHART_Y_AXIS_WIDTH}
						/>
					) : (
						<CostChart data={costData} chartType={costChartType} startTime={startTime} endTime={endTime} selectedModel={effectiveCostModel} />
					)}
				</ChartCard>

				<ChartCard
					title="Latency"
					loading={isChartLoading}
					testId="chart-governance-team-latency"
					headerActions={
						<div className={CHART_HEADER_ACTIONS_CLASS}>
							<div className={CHART_HEADER_LEGEND_CLASS}>{latencyLegend}</div>
							<div className={CHART_HEADER_CONTROLS_CLASS}>
								{renderTeamControl("dashboard-governance-latency-team-filter")}
								<ChartTypeToggle chartType={latencyChartType} onToggle={onLatencyChartToggle} data-testid="dashboard-governance-latency-chart-toggle" />
							</div>
						</div>
					}
				>
					{isAllTeamsView ? (
						<GovernanceTimeSeriesChart
							data={latencyComparisonData}
							series={comparisonSeries}
							chartType={latencyChartType}
							startTime={startTime}
							endTime={endTime}
							yAxisFormatter={formatLatency}
							tooltipValueFormatter={(value) => formatLatency(value)}
							yAxisWidth={55}
						/>
					) : (
						<LatencyChart data={latencyData} chartType={latencyChartType} startTime={startTime} endTime={endTime} />
					)}
				</ChartCard>

				<ChartCard
					title="Provider Cost"
					loading={isChartLoading}
					testId="chart-governance-team-provider-cost"
					headerActions={
						<div className={COST_CHART_HEADER_ACTIONS_CLASS}>
							<div className={COST_CHART_HEADER_FILTERS_CLASS}>
								{renderTeamControl("dashboard-governance-provider-cost-team-filter")}
								<ProviderFilterSelect
									providers={providerCostProviders}
									selectedProvider={effectiveProviderCostProvider}
									onProviderChange={onProviderCostProviderChange}
									data-testid="dashboard-governance-provider-cost-filter"
								/>
								<ChartTypeToggle
									chartType={providerCostChartType}
									onToggle={onProviderCostChartToggle}
									data-testid="dashboard-governance-provider-cost-chart-toggle"
								/>
							</div>
							<div className={COST_CHART_HEADER_SUMMARY_ROW_CLASS}>
								<div className={CHART_HEADER_LEGEND_CLASS}>{providerCostLegend}</div>
								<CostHeaderSummary
									totalCost={teamProviderCostTotals.totalCost}
									totalSavings={teamProviderCostTotals.totalSavings}
									testIdPrefix="dashboard-governance-team-provider-cost-summary"
									className="ml-auto"
								/>
							</div>
						</div>
					}
				>
					<ProviderCostChart
						data={mergedProviderCost}
						chartType={providerCostChartType}
						startTime={startTime}
						endTime={endTime}
						selectedProvider={effectiveProviderCostProvider}
					/>
				</ChartCard>

				<ChartCard
					title="Provider Tokens"
					loading={isChartLoading}
					testId="chart-governance-team-provider-tokens"
					headerActions={
						<div className={CHART_HEADER_ACTIONS_CLASS}>
							<div className={CHART_HEADER_LEGEND_CLASS}>{providerTokenLegend}</div>
							<div className={CHART_HEADER_CONTROLS_CLASS}>
								{renderTeamControl("dashboard-governance-provider-token-team-filter")}
								<ProviderFilterSelect
									providers={providerTokenProviders}
									selectedProvider={effectiveProviderTokenProvider}
									onProviderChange={onProviderTokenProviderChange}
									data-testid="dashboard-governance-provider-token-filter"
								/>
								<ChartTypeToggle
									chartType={providerTokenChartType}
									onToggle={onProviderTokenChartToggle}
									data-testid="dashboard-governance-provider-token-chart-toggle"
								/>
							</div>
						</div>
					}
				>
					<ProviderTokenChart
						data={mergedProviderTokens}
						chartType={providerTokenChartType}
						startTime={startTime}
						endTime={endTime}
						selectedProvider={effectiveProviderTokenProvider}
					/>
				</ChartCard>
			</div>

			<GovernanceInsightsTab
				filters={filters}
				isActive={isActive}
				refreshKey={refreshKey}
				startTime={startTime}
				endTime={endTime}
				teamId={teamId}
				providerLatencyChartType={providerLatencyChartType}
				errorChartType={errorChartType}
				cacheChartType={cacheChartType}
				providerLatencyProvider={providerLatencyProvider}
				onTeamChange={onTeamChange}
				onProviderLatencyChartToggle={onProviderLatencyChartToggle}
				onErrorChartToggle={onErrorChartToggle}
				onCacheChartToggle={onCacheChartToggle}
				onProviderLatencyProviderChange={onProviderLatencyProviderChange}
			/>
		</div>
	);
}
