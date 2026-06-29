"use client";

import type { CacheHistogramResponse, CostHistogramResponse, TokenHistogramResponse } from "@/lib/types/logs";

import {
	CHART_COLORS,
	CHART_HEADER_ACTIONS_CLASS,
	CHART_HEADER_CONTROLS_CLASS,
	CHART_HEADER_LEGEND_CLASS,
	COST_CHART_HEADER_ACTIONS_CLASS,
	COST_CHART_HEADER_FILTERS_CLASS,
	COST_CHART_HEADER_SUMMARY_ROW_CLASS,
} from "../utils/chartUtils";
import { usePlatformSavings } from "../hooks/usePlatformSavings";
import { CacheHitTypeChart } from "./charts/cacheHitTypeChart";
import { CacheHitRateChart } from "./charts/cacheHitRateChart";
import { CacheRequestsChart } from "./charts/cacheRequestsChart";
import { CacheSavingsChart } from "./charts/cacheSavingsChart";
import CacheTokenMeterChart from "./charts/cacheTokenMeterChart";
import { ChartCard } from "./charts/chartCard";
import { CostHeaderSummary } from "./charts/costHeaderSummary";
import { type ChartType, ChartTypeToggle } from "./charts/chartTypeToggle";

export interface CacheTabProps {
	cacheData: CacheHistogramResponse | null;
	tokenData: TokenHistogramResponse | null;
	costData: CostHistogramResponse | null;
	loadingCache: boolean;
	loadingTokens: boolean;
	loadingCost: boolean;
	startTime: number;
	endTime: number;
	cacheRequestsChartType: ChartType;
	cacheSavingsChartType: ChartType;
	cacheHitRateChartType: ChartType;
	cacheHitTypesChartType: ChartType;
	onCacheRequestsChartToggle: (type: ChartType) => void;
	onCacheSavingsChartToggle: (type: ChartType) => void;
	onCacheHitRateChartToggle: (type: ChartType) => void;
	onCacheHitTypesChartToggle: (type: ChartType) => void;
}

export function CacheTab({
	cacheData,
	tokenData,
	costData,
	loadingCache,
	loadingTokens,
	loadingCost,
	startTime,
	endTime,
	cacheRequestsChartType,
	cacheSavingsChartType,
	cacheHitRateChartType,
	cacheHitTypesChartType,
	onCacheRequestsChartToggle,
	onCacheSavingsChartToggle,
	onCacheHitRateChartToggle,
	onCacheHitTypesChartToggle,
}: CacheTabProps) {
	const totalSemanticSuppressions = (cacheData?.buckets || []).reduce((sum, bucket) => sum + (bucket.semantic_suppressions || 0), 0);

	// Canonical platform savings - one reconciling source shared with the Cost
	// Optimization + Overview tabs. Response-Consistency savings already arrive
	// inside gateway cache_savings (the 7th source), and the agentic-cache
	// overlay is layered on by the hook, so this tab's "Total saved" matches the
	// rest of the console without any manual additive math here.
	const { totalCost, totalSavings } = usePlatformSavings({ costData, startTime, endTime });

	return (
		<div className="grid grid-cols-1 gap-2 lg:grid-cols-2 2xl:grid-cols-3">
			<ChartCard title="Prompt Coverage" loading={loadingTokens} testId="chart-cache-meter">
				<CacheTokenMeterChart data={tokenData} />
			</ChartCard>

			<ChartCard
				title="Savings ($)"
				loading={loadingCost}
				testId="chart-cache-savings"
				headerActions={
					<div className={COST_CHART_HEADER_ACTIONS_CLASS}>
						<div className={COST_CHART_HEADER_FILTERS_CLASS}>
							<ChartTypeToggle
								chartType={cacheSavingsChartType}
								onToggle={onCacheSavingsChartToggle}
								data-testid="dashboard-cache-savings-chart-toggle"
							/>
						</div>
						<div className={COST_CHART_HEADER_SUMMARY_ROW_CLASS}>
							<div className={CHART_HEADER_LEGEND_CLASS}>
							<span className="flex items-center gap-1">
								<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.cost }} />
								<span className="text-muted-foreground">Avoided provider spend</span>
							</span>
							</div>
							<CostHeaderSummary
								totalCost={totalCost}
								totalSavings={totalSavings}
								testIdPrefix="dashboard-cache-savings-summary"
								className="ml-auto"
							/>
						</div>
					</div>
				}
			>
				<CacheSavingsChart costData={costData} chartType={cacheSavingsChartType} startTime={startTime} endTime={endTime} />
			</ChartCard>

			<ChartCard
				title="Requests"
				loading={loadingCache}
				testId="chart-cache-requests"
				headerActions={
					<div className={CHART_HEADER_ACTIONS_CLASS}>
						<div className={CHART_HEADER_LEGEND_CLASS}>
							<span className="flex items-center gap-1">
								<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.cacheHit }} />
								<span className="text-muted-foreground">Hits</span>
							</span>
							<span className="flex items-center gap-1">
								<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.cacheMiss }} />
								<span className="text-muted-foreground">Misses</span>
							</span>
						</div>
						<div className={CHART_HEADER_CONTROLS_CLASS}>
							<ChartTypeToggle
								chartType={cacheRequestsChartType}
								onToggle={onCacheRequestsChartToggle}
								data-testid="dashboard-cache-requests-chart-toggle"
							/>
						</div>
					</div>
				}
			>
				<CacheRequestsChart data={cacheData} chartType={cacheRequestsChartType} startTime={startTime} endTime={endTime} />
			</ChartCard>

			<ChartCard
				title="Hit Rate"
				loading={loadingCache}
				testId="chart-cache-hit-rate"
				headerActions={
					<div className={CHART_HEADER_ACTIONS_CLASS}>
						<div className={CHART_HEADER_LEGEND_CLASS}>
							<span className="flex items-center gap-1">
								<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.cacheHit }} />
								<span className="text-muted-foreground">Hits / Requests</span>
							</span>
						</div>
						<div className={CHART_HEADER_CONTROLS_CLASS}>
							<ChartTypeToggle
								chartType={cacheHitRateChartType}
								onToggle={onCacheHitRateChartToggle}
								data-testid="dashboard-cache-hit-rate-chart-toggle"
							/>
						</div>
					</div>
				}
			>
				<CacheHitRateChart data={cacheData} chartType={cacheHitRateChartType} startTime={startTime} endTime={endTime} />
			</ChartCard>

			<ChartCard
				title="Hit Types"
				loading={loadingCache}
				testId="chart-cache-hit-types"
				headerActions={
					<div className={CHART_HEADER_ACTIONS_CLASS}>
						<div className={CHART_HEADER_LEGEND_CLASS}>
							<span className="flex items-center gap-1">
								<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.cacheDirectHit }} />
								<span className="text-muted-foreground">Direct</span>
							</span>
							<span className="flex items-center gap-1">
								<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.cacheSemanticHit }} />
								<span className="text-muted-foreground">Semantic</span>
							</span>
						</div>
						<div className={CHART_HEADER_CONTROLS_CLASS}>
							<ChartTypeToggle
								chartType={cacheHitTypesChartType}
								onToggle={onCacheHitTypesChartToggle}
								data-testid="dashboard-cache-hit-types-chart-toggle"
							/>
						</div>
					</div>
				}
			>
				<CacheHitTypeChart data={cacheData} chartType={cacheHitTypesChartType} startTime={startTime} endTime={endTime} />
			</ChartCard>

			<ChartCard title="Lookups Skipped" loading={loadingCache} testId="chart-cache-semantic-suppressions">
				<div className="flex h-full flex-col items-center justify-center gap-3 text-center">
					<div className="text-4xl font-semibold tracking-tight">{totalSemanticSuppressions.toLocaleString()}</div>
					<div className="text-muted-foreground max-w-sm text-sm">
						Requests where DeepIntShield skipped semantic reuse because traffic was unscoped or the active cache policy blocked semantic sharing.
					</div>
				</div>
			</ChartCard>
		</div>
	);
}
