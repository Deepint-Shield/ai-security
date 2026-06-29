"use client";

import type {
	CacheHistogramResponse,
	CostHistogramResponse,
	LatencyHistogramResponse,
	OptimizationHistogramBucket,
	TokenHistogramResponse,
} from "@/lib/types/logs";
import { useGetLogsOptimizationHistogramQuery } from "@/lib/store";
import { BrainCircuit, Boxes, GitBranch, Gauge, Layers, MessagesSquare, Minimize2, Rocket, Scissors, Sparkles, Split, TrendingDown, Zap } from "lucide-react";
import { useMemo } from "react";

import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { usePlatformSavings } from "../hooks/usePlatformSavings";
import {
	CHART_CURSOR,
	CHART_GRID_STROKE,
	CHART_TICK_STYLE,
	CHART_TICK_STYLE_DY,
	CHART_TOOLTIP_CLASS,
	CHART_TOOLTIP_META_CLASS,
	CHART_TOOLTIP_TIMESTAMP_CLASS,
	CHART_TOOLTIP_VALUE_CLASS,
	COST_CHART_Y_AXIS_WIDTH,
	formatCostAxis,
	formatFullTimestamp,
	formatTimestamp,
} from "../utils/chartUtils";
import { ChartCard } from "./charts/chartCard";
import { ChartErrorBoundary } from "./charts/chartErrorBoundary";

// CostOptimizationTab focuses on the savings-specific story: stat tiles
// rolled up from cost / cache / token / latency / optimization histograms,
// plus the four RAG-specific charts. Savings / Cost / Requests / Hit rate /
// Cache coverage / Latency live on the Summary + Cache tabs and are not
// duplicated here.
export interface CostOptimizationTabProps {
	cacheData: CacheHistogramResponse | null;
	costData: CostHistogramResponse | null;
	tokenData: TokenHistogramResponse | null;
	latencyData: LatencyHistogramResponse | null;

	loadingTokens: boolean;

	startTime: number;
	endTime: number;
}

export function CostOptimizationTab({
	cacheData,
	costData,
	tokenData,
	latencyData,
	loadingTokens,
	startTime,
	endTime,
}: CostOptimizationTabProps) {
	// Optimization histogram - same filter shape as the cost histogram so the
	// numbers align with the workspace scope the rest of the dashboard uses.
	// Returns real measured RAG / compression / reasoning aggregates (no more
	// projected constants).
	const { data: optimizationData } = useGetLogsOptimizationHistogramQuery({
		filters: {
			start_time: new Date(startTime * 1000).toISOString(),
			end_time: new Date(endTime * 1000).toISOString(),
		},
	});

	const parallelToolsRollup = useMemo(() => {
		const buckets = optimizationData?.buckets || [];
		let applied = 0;
		let totalTools = 0;
		let parallelCount = 0;
		let sequentialCount = 0;
		let wallClockMs = 0;
		let serialEstimateMs = 0;
		let latencySavedMs = 0;
		for (const b of buckets) {
			applied += b.parallel_tools_applied || 0;
			totalTools += b.parallel_tools_total || 0;
			parallelCount += b.parallel_tools_parallel_count || 0;
			sequentialCount += b.parallel_tools_sequential_count || 0;
			wallClockMs += b.parallel_tools_wall_clock_ms || 0;
			serialEstimateMs += b.parallel_tools_serial_estimate_ms || 0;
			latencySavedMs += b.parallel_tools_latency_saved_ms || 0;
		}
		const parallelPct = totalTools > 0 ? (parallelCount / totalTools) * 100 : 0;
		const avgSavedPerStep = applied > 0 ? latencySavedMs / applied : 0;
		const speedupRatio = wallClockMs > 0 ? serialEstimateMs / wallClockMs : 0;
		return {
			applied,
			totalTools,
			parallelCount,
			sequentialCount,
			wallClockMs,
			serialEstimateMs,
			latencySavedMs,
			parallelPct,
			avgSavedPerStep,
			speedupRatio,
		};
	}, [optimizationData]);

	// Reasoning-throttling rollup - savings + applied/sampled counts from the
	// optimization histogram. Tracked per-bucket by reasoning.go's stamper.
	const reasoningRollup = useMemo(() => {
		const buckets = optimizationData?.buckets || [];
		let savings = 0;
		let applied = 0;
		let sampled = 0;
		for (const b of buckets) {
			savings += b.reasoning_savings || 0;
			applied += b.reasoning_applied || 0;
			sampled += b.reasoning_sampled || 0;
		}
		return { savings, applied, sampled };
	}, [optimizationData]);

	// Prompt-compression rollup - savings, cache hits, and original→compressed
	// token deltas from promptcompression.go's per-bucket stamper.
	const compressionRollup = useMemo(() => {
		const buckets = optimizationData?.buckets || [];
		let savings = 0;
		let applied = 0;
		let cacheHits = 0;
		let originalTokens = 0;
		let compressedTokens = 0;
		for (const b of buckets) {
			savings += b.compression_savings || 0;
			applied += b.compression_applied || 0;
			cacheHits += b.compression_cache_hits || 0;
			originalTokens += b.compression_original_tokens || 0;
			compressedTokens += b.compression_compressed_tokens || 0;
		}
		const compressionPct = originalTokens > 0 ? Math.max(0, (1 - compressedTokens / originalTokens) * 100) : 0;
		return { savings, applied, cacheHits, originalTokens, compressedTokens, compressionPct };
	}, [optimizationData]);

	// Cascade routing rollup - avg confidence score (weighted across buckets)
	// + total escalations stamped by cascade.go.
	const cascadeRollup = useMemo(() => {
		const buckets = optimizationData?.buckets || [];
		let scoreAcc = 0;
		let scoreN = 0;
		let escalations = 0;
		for (const b of buckets) {
			if (b.cascade_avg_score) {
				scoreAcc += b.cascade_avg_score;
				scoreN++;
			}
			escalations += b.cascade_escalations || 0;
		}
		const avgScore = scoreN > 0 ? scoreAcc / scoreN : 0;
		return { avgScore, escalations, scoreSamples: scoreN };
	}, [optimizationData]);

	// Batch-routing rollup - count of requests stamped batch-eligible by
	// batch.go. Actual batch dispatch happens client-side.
	const batchRollup = useMemo(() => {
		const buckets = optimizationData?.buckets || [];
		let eligible = 0;
		for (const b of buckets) {
			eligible += b.batch_eligible || 0;
		}
		return { eligible };
	}, [optimizationData]);

	const ttftRollup = useMemo(() => {
		const buckets = optimizationData?.buckets || [];
		let applied = 0;
		let messagesReordered = 0;
		let stablePrefixTokens = 0;
		for (const b of buckets) {
			applied += b.ttft_applied || 0;
			messagesReordered += b.ttft_messages_reordered || 0;
			stablePrefixTokens += b.ttft_stable_prefix_tokens || 0;
		}
		const avgPrefixTokens = applied > 0 ? Math.round(stablePrefixTokens / applied) : 0;
		const avgMessagesMoved = applied > 0 ? messagesReordered / applied : 0;
		return { applied, messagesReordered, stablePrefixTokens, avgPrefixTokens, avgMessagesMoved };
	}, [optimizationData]);

	const summarizationRollup = useMemo(() => {
		const buckets = optimizationData?.buckets || [];
		let savings = 0;
		let applied = 0;
		let cacheHits = 0;
		let asyncKickoffs = 0;
		let turnsSummarized = 0;
		let originalTokens = 0;
		let summaryTokens = 0;
		let savedTokens = 0;
		for (const b of buckets) {
			savings += b.summarization_savings || 0;
			applied += b.summarization_applied || 0;
			cacheHits += b.summarization_cache_hits || 0;
			asyncKickoffs += b.summarization_async_kickoffs || 0;
			turnsSummarized += b.summarization_turns_summarized || 0;
			originalTokens += b.summarization_original_tokens || 0;
			summaryTokens += b.summarization_summary_tokens || 0;
			savedTokens += b.summarization_saved_tokens || 0;
		}
		const compressionPct = originalTokens > 0 ? Math.max(0, (1 - summaryTokens / originalTokens) * 100) : 0;
		const avgTurnsPerApply = applied > 0 ? turnsSummarized / applied : 0;
		return {
			savings,
			applied,
			cacheHits,
			asyncKickoffs,
			turnsSummarized,
			originalTokens,
			summaryTokens,
			savedTokens,
			compressionPct,
			avgTurnsPerApply,
		};
	}, [optimizationData]);

	const ragRollup = useMemo(() => {
		const buckets = optimizationData?.buckets || [];
		let savings = 0;
		let chunksDetected = 0;
		let chunksKept = 0;
		let trimmedTokens = 0;
		let originalTokens = 0;
		let appliedRows = 0;
		let rerankLatencyAcc = 0;
		let rerankLatencyN = 0;
		for (const b of buckets) {
			savings += b.rag_savings || 0;
			chunksDetected += b.rag_chunks_detected || 0;
			chunksKept += b.rag_chunks_kept || 0;
			trimmedTokens += b.rag_trimmed_tokens || 0;
			originalTokens += b.rag_original_tokens || 0;
			appliedRows += b.rag_applied || 0;
			if (b.rag_avg_rerank_latency_ms) {
				rerankLatencyAcc += b.rag_avg_rerank_latency_ms;
				rerankLatencyN++;
			}
		}
		const avgChunksRetrieved = appliedRows > 0 ? Math.round(chunksDetected / appliedRows) : 0;
		const avgChunksKept = appliedRows > 0 ? Math.round(chunksKept / appliedRows) : 0;
		const avgChunksDropped = avgChunksRetrieved - avgChunksKept;
		const dropRatePct =
			avgChunksRetrieved > 0 ? ((avgChunksRetrieved - avgChunksKept) / avgChunksRetrieved) * 100 : 0;
		const avgRerankMs = rerankLatencyN > 0 ? rerankLatencyAcc / rerankLatencyN : 0;
		return {
			savings,
			chunksDetected,
			chunksKept,
			trimmedTokens,
			originalTokens,
			appliedRows,
			avgChunksRetrieved,
			avgChunksKept,
			avgChunksDropped,
			dropRatePct,
			avgRerankMs,
		};
	}, [optimizationData]);

	// Derived metrics - pure-CPU reductions over the in-memory buckets that
	// the dashboard already has. No extra API call needed.
	const cacheRollup = useMemo(() => {
		const buckets = cacheData?.buckets || [];
		let hits = 0;
		let misses = 0;
		for (const b of buckets) {
			hits += b.cache_hits || 0;
			misses += b.cache_misses || 0;
		}
		const total = hits + misses;
		return {
			hits,
			misses,
			total,
			hitRatePct: total > 0 ? (hits / total) * 100 : 0,
		};
	}, [cacheData]);

	// Canonical platform savings - the single reconciling source shared by every
	// cost surface. Gateway savings (cache_savings) already folds in all seven
	// log-pipeline sources including Response Consistency; the hook layers the
	// agentic-cache overlay on top so "Total saved" and "Savings rate" below use
	// one identical numerator/denominator (they can no longer disagree).
	const platformSavings = usePlatformSavings({ costData, startTime, endTime });
	const { totalSavings, wouldHaveSpent, savingsRatePct, agenticCacheSaved } = platformSavings;

	// Cached input tokens / total input tokens - the share of input we
	// serve from cache (semantic + provider prompt cache combined).
	const tokenRollup = useMemo(() => {
		const buckets = tokenData?.buckets || [];
		let promptTokens = 0;
		let cachedTokens = 0;
		for (const b of buckets) {
			promptTokens += b.prompt_tokens || 0;
			cachedTokens += b.cached_read_tokens || 0;
		}
		return {
			promptTokens,
			cachedTokens,
			// Clamp to 100%: on a gateway cache hit the full prompt is credited as
			// "served from cache" (matview COALESCE(NULLIF(cached_read_tokens,0),
			// prompt_tokens)), while the denominator SUM(prompt_tokens) excludes
			// those cache-served rows - so the raw ratio can exceed 100%. Coverage
			// can never exceed 100%; clamp to match cacheTokenMeterChart's gauge.
			coveragePct: promptTokens > 0 ? Math.min(100, (cachedTokens / promptTokens) * 100) : 0,
		};
	}, [tokenData]);

	// Latency view: every chart in the dashboard is "all traffic"; we don't
	// have a paired cached-vs-uncached split today. The story we surface is
	// the realized average - cached responses cluster near zero ms and pull
	// the p50/p90 down, so the chart-over-time reads as the improvement
	// curve as cache adoption grows.
	const avgLatencyMs = useMemo(() => {
		const buckets = latencyData?.buckets || [];
		if (!buckets.length) return 0;
		let sum = 0;
		let n = 0;
		for (const b of buckets) {
			if (typeof b.avg_latency === "number") {
				sum += b.avg_latency;
				n++;
			}
		}
		return n > 0 ? sum / n : 0;
	}, [latencyData]);

	return (
		<div className="flex flex-col gap-3">
			{/* Hero metric tiles - first row: realised cost-opt totals. Second
			    row: RAG-specific numbers (measured by the ragoptimizer plugin
			    once it's enabled and processing chunks). Same visual rhythm
			    as governance + provider tabs. */}
			<div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-4">
				<StatTile
					icon={<TrendingDown className="h-4 w-4" />}
					accent="emerald"
					label="Total saved"
					value={formatCurrency(totalSavings)}
					subline={
						agenticCacheSaved > 0
							? `vs ${formatCurrency(wouldHaveSpent)} would-have-spent · incl. ${formatCurrency(agenticCacheSaved)} from Agentic Cache`
							: `vs ${formatCurrency(wouldHaveSpent)} would-have-spent`
					}
					testId="costopt-tile-saved"
				/>
				<StatTile
					icon={<Sparkles className="h-4 w-4" />}
					accent="primary"
					label="Savings rate"
					value={`${savingsRatePct.toFixed(1)}%`}
					subline="Of estimated unoptimised spend"
					testId="costopt-tile-rate"
				/>
				<StatTile
					icon={<Zap className="h-4 w-4" />}
					accent="sky"
					label="Cache hit rate"
					value={`${cacheRollup.hitRatePct.toFixed(1)}%`}
					subline={`${cacheRollup.hits.toLocaleString()} hits / ${cacheRollup.total.toLocaleString()} requests`}
					testId="costopt-tile-hit-rate"
				/>
				<StatTile
					icon={<Gauge className="h-4 w-4" />}
					accent="violet"
					label="Avg latency"
					value={formatMs(avgLatencyMs)}
					subline="Cached responses pull this down"
					testId="costopt-tile-latency"
				/>
			</div>

			{/* Charts - RAG-specific views + the one stat card that isn't already
			    covered by the tile row above. Savings/Cost/Coverage/Requests/Hit
			    rate/Latency live on the Summary + Cache tabs and aren't repeated
			    here. */}
			<div className="grid grid-cols-1 gap-2 lg:grid-cols-2 2xl:grid-cols-3">
				<ChartCard title="Cached tokens" loading={loadingTokens} testId="costopt-chart-cached-tokens">
					<div className="flex h-full flex-col items-center justify-center gap-2 text-center">
						<div className="text-4xl font-semibold tracking-tight">{tokenRollup.cachedTokens.toLocaleString()}</div>
						<div className="text-muted-foreground text-xs">
							{tokenRollup.promptTokens.toLocaleString()} prompt tokens total · {tokenRollup.coveragePct.toFixed(1)}% served from cache
						</div>
					</div>
				</ChartCard>
			</div>

		</div>
	);
}

// RagTokenSplitVisual mirrors the proportional bar from the original RAG
// tab, but uses real (measured) trimmed tokens from the optimization
// histogram instead of the projected constants the preview used.
function RagTokenSplitVisual({ originalTokens, trimmedTokens }: { originalTokens: number; trimmedTokens: number }) {
	const trimmedPct = originalTokens > 0 ? (trimmedTokens / originalTokens) * 100 : 0;
	const keptPct = 100 - trimmedPct;
	const keptTokens = Math.max(0, originalTokens - trimmedTokens);
	return (
		<div className="flex h-full flex-col justify-center gap-3">
			<div className="flex items-baseline justify-between gap-2">
				<span className="text-foreground text-2xl font-semibold tabular-nums">{formatTokens(trimmedTokens)}</span>
				<span className="text-muted-foreground text-[11px]">trimmed of {formatTokens(originalTokens)}</span>
			</div>
			<div className="border-border/40 relative h-3 overflow-hidden rounded-full border bg-background/40">
				<div className="absolute inset-y-0 left-0 bg-gradient-to-r from-emerald-500/70 to-emerald-400/80" style={{ width: `${keptPct}%` }} />
				<div className="absolute inset-y-0 right-0 bg-gradient-to-l from-amber-500/70 to-amber-400/80" style={{ width: `${trimmedPct}%` }} />
			</div>
			<div className="text-muted-foreground flex items-center justify-between text-[11px]">
				<span>Kept · {formatTokens(keptTokens)} ({keptPct.toFixed(0)}%)</span>
				<span>Trimmed · {formatTokens(trimmedTokens)} ({trimmedPct.toFixed(0)}%)</span>
			</div>
		</div>
	);
}

// RagChunksVisual shows the average chunks-retrieved-vs-kept per applied
// request. Empty state when nothing has been processed yet.
function RagChunksVisual({ retrieved, kept, appliedRows }: { retrieved: number; kept: number; appliedRows: number }) {
	if (retrieved <= 0 || appliedRows <= 0) {
		return (
			<div className="text-muted-foreground flex h-full items-center justify-center text-xs">
				No RAG-shaped traffic in the selected window.
			</div>
		);
	}
	const dropped = Math.max(0, retrieved - kept);
	return (
		<div className="flex h-full flex-col items-center justify-center gap-2">
			<div className="flex items-center gap-1.5">
				{Array.from({ length: retrieved }).map((_, idx) => (
					<span
						key={idx}
						className={`inline-block h-6 w-2.5 rounded-sm ${idx < kept ? "bg-emerald-500/85" : "bg-amber-500/45"}`}
					/>
				))}
			</div>
			<div className="text-muted-foreground flex items-baseline gap-3 text-[11px]">
				<span>
					<span className="text-foreground tabular-nums text-base font-semibold">{kept}</span> kept
				</span>
				<span>·</span>
				<span>
					<span className="text-foreground tabular-nums text-base font-semibold">{dropped}</span> dropped
				</span>
				<span>·</span>
				<span>{retrieved} retrieved</span>
			</div>
			<div className="text-muted-foreground text-[10px]">avg over {appliedRows.toLocaleString()} requests</div>
		</div>
	);
}

// RagLatencyTrend renders per-bucket avg rerank latency as a recharts BarChart
// with the same axis treatment as the Top Models / Cache Savings charts on
// the other dashboard tabs (CartesianGrid, formatted XAxis/YAxis ticks,
// shared tooltip styles). Replaces the hand-rolled div-bar sparkline that
// had no real axis labels - the previous "0 ms / peak X ms" footer kept
// getting clipped at the card's bottom edge.
function RagLatencyTrend({
	buckets,
	bucketSizeSeconds,
}: {
	buckets: OptimizationHistogramBucket[];
	bucketSizeSeconds: number;
}) {
	const chartData = useMemo(
		() =>
			buckets.map((b) => ({
				timestamp: b.timestamp,
				formattedTime: formatTimestamp(b.timestamp, bucketSizeSeconds),
				value: b.rag_avg_rerank_latency_ms || 0,
			})),
		[buckets, bucketSizeSeconds],
	);
	const hasData = chartData.some((d) => d.value > 0);
	if (!hasData) {
		return (
			<div className="text-muted-foreground flex h-full items-center justify-center text-xs">
				Rerank latency will appear once the reranker processes traffic.
			</div>
		);
	}
	return (
		<ChartErrorBoundary resetKey={`rag-latency-${chartData.length}`}>
			<ResponsiveContainer width="100%" height="100%">
				<BarChart data={chartData} margin={{ top: 6, right: 4, left: 4, bottom: 0 }} barCategoryGap={1}>
					<CartesianGrid strokeDasharray="3 3" vertical={false} stroke={CHART_GRID_STROKE} />
					<XAxis
						dataKey="formattedTime"
						tick={CHART_TICK_STYLE_DY}
						tickLine={false}
						axisLine={false}
						interval="preserveStartEnd"
						minTickGap={24}
					/>
					<YAxis
						tick={CHART_TICK_STYLE}
						tickLine={false}
						axisLine={false}
						width={48}
						tickFormatter={(v: number) => (v >= 1000 ? `${(v / 1000).toFixed(1)}s` : `${Math.round(v)}ms`)}
						domain={[0, (dataMax: number) => Math.max(dataMax, 1)]}
					/>
					<Tooltip content={<RerankTooltip />} cursor={CHART_CURSOR} />
					<Bar
						dataKey="value"
						fill="#8c8bff"
						fillOpacity={0.85}
						radius={[2, 2, 0, 0]}
						isAnimationActive={false}
						barSize={20}
					/>
				</BarChart>
			</ResponsiveContainer>
		</ChartErrorBoundary>
	);
}

function SavingsTooltip({
	active,
	payload,
}: {
	active?: boolean;
	payload?: Array<{ payload?: { timestamp?: string; value?: number } }>;
}) {
	if (!active || !payload?.length || !payload[0]?.payload) return null;
	const datum = payload[0].payload;
	const ts = datum.timestamp ? formatFullTimestamp(datum.timestamp) : "";
	const value = datum.value ?? 0;
	return (
		<div className={CHART_TOOLTIP_CLASS}>
			<div className={CHART_TOOLTIP_TIMESTAMP_CLASS}>{ts}</div>
			<div className="flex items-center justify-between gap-4 text-sm">
				<span className={CHART_TOOLTIP_META_CLASS}>RAG savings</span>
				<span className={CHART_TOOLTIP_VALUE_CLASS}>{formatCurrency(value)}</span>
			</div>
		</div>
	);
}

function RerankTooltip({
	active,
	payload,
}: {
	active?: boolean;
	payload?: Array<{ payload?: { timestamp?: string; value?: number } }>;
}) {
	if (!active || !payload?.length || !payload[0]?.payload) return null;
	const datum = payload[0].payload;
	const ts = datum.timestamp ? formatFullTimestamp(datum.timestamp) : "";
	const value = datum.value ?? 0;
	return (
		<div className={CHART_TOOLTIP_CLASS}>
			<div className={CHART_TOOLTIP_TIMESTAMP_CLASS}>{ts}</div>
			<div className="flex items-center justify-between gap-4 text-sm">
				<span className={CHART_TOOLTIP_META_CLASS}>Avg rerank latency</span>
				<span className={CHART_TOOLTIP_VALUE_CLASS}>
					{value >= 1000 ? `${(value / 1000).toFixed(2)}s` : `${Math.round(value)}ms`}
				</span>
			</div>
		</div>
	);
}

// RagSavingsTrend mirrors the Cache Savings chart shape from the Cache tab
// but plots only the RAG slice. Recharts BarChart with the same axis
// treatment as other dashboard tabs so the $ y-axis ticks and time x-axis
// ticks are always visible - the previous hand-rolled div bars dropped
// their footer text below the card edge.
function RagSavingsTrend({
	buckets,
	bucketSizeSeconds,
}: {
	buckets: OptimizationHistogramBucket[];
	bucketSizeSeconds: number;
}) {
	const chartData = useMemo(
		() =>
			buckets.map((b) => ({
				timestamp: b.timestamp,
				formattedTime: formatTimestamp(b.timestamp, bucketSizeSeconds),
				value: b.rag_savings || 0,
			})),
		[buckets, bucketSizeSeconds],
	);
	const total = useMemo(() => chartData.reduce((acc, d) => acc + d.value, 0), [chartData]);
	const hasData = total > 0;
	if (!hasData) {
		return (
			<div className="text-muted-foreground flex h-full items-center justify-center text-xs">
				No RAG savings recorded yet. Enable the toggle and send traffic with retrieved chunks.
			</div>
		);
	}
	return (
		<div className="flex h-full flex-col gap-2">
			<div className="flex shrink-0 items-baseline justify-between">
				<span className="text-foreground text-lg font-semibold tabular-nums">{formatCurrency(total)}</span>
				<span className="text-muted-foreground text-[11px]">measured savings · trimmed tokens × input rate</span>
			</div>
			<div className="min-h-0 flex-1">
				<ChartErrorBoundary resetKey={`rag-savings-${chartData.length}`}>
					<ResponsiveContainer width="100%" height="100%">
						<BarChart data={chartData} margin={{ top: 6, right: 4, left: 4, bottom: 0 }} barCategoryGap={1}>
							<CartesianGrid strokeDasharray="3 3" vertical={false} stroke={CHART_GRID_STROKE} />
							<XAxis
								dataKey="formattedTime"
								tick={CHART_TICK_STYLE_DY}
								tickLine={false}
								axisLine={false}
								interval="preserveStartEnd"
								minTickGap={24}
							/>
							<YAxis
								tick={CHART_TICK_STYLE}
								tickLine={false}
								axisLine={false}
								width={COST_CHART_Y_AXIS_WIDTH}
								tickFormatter={formatCostAxis}
								domain={[0, (dataMax: number) => Math.max(dataMax, 0.0001)]}
							/>
							<Tooltip content={<SavingsTooltip />} cursor={CHART_CURSOR} />
							<Bar
								dataKey="value"
								fill="#21d3c4"
								fillOpacity={0.85}
								radius={[2, 2, 0, 0]}
								isAnimationActive={false}
								barSize={20}
							/>
						</BarChart>
					</ResponsiveContainer>
				</ChartErrorBoundary>
			</div>
		</div>
	);
}

// StatTile - small numeric centerpiece card. Mirrors the visual rhythm used
// across governance / provider tabs (rounded card, accent icon, numeric
// value, supporting subline).
function StatTile({
	icon,
	accent,
	label,
	value,
	subline,
	testId,
}: {
	icon: React.ReactNode;
	accent: "emerald" | "primary" | "sky" | "violet";
	label: string;
	value: string;
	subline: string;
	testId?: string;
}) {
	const accentClass = {
		emerald: "bg-emerald-500/12 text-emerald-600 dark:text-emerald-400",
		primary: "bg-primary/12 text-primary",
		sky: "bg-sky-500/12 text-sky-600 dark:text-sky-400",
		violet: "bg-violet-500/12 text-violet-600 dark:text-violet-400",
	}[accent];
	return (
		<div
			data-testid={testId}
			className="border-border/60 bg-card/80 flex items-center gap-3 rounded-2xl border px-4 py-3 shadow-[0_18px_36px_-32px_rgba(7,24,30,0.4),inset_0_1px_0_rgba(255,255,255,0.1)] backdrop-blur-xl"
		>
			<span
				className={`inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.18)] ${accentClass}`}
			>
				{icon}
			</span>
			<div className="min-w-0">
				<p className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">{label}</p>
				<p className="text-foreground mt-1 text-xl font-semibold tabular-nums leading-none">{value}</p>
				<p className="text-muted-foreground mt-1 text-[11px]">{subline}</p>
			</div>
		</div>
	);
}

function formatTokens(value: number): string {
	if (!isFinite(value) || value <= 0) return "0";
	if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M`;
	if (value >= 1_000) return `${(value / 1_000).toFixed(1)}K`;
	return Math.round(value).toLocaleString();
}

function formatCurrency(value: number): string {
	if (!isFinite(value) || value === 0) return "$0.00";
	if (Math.abs(value) < 0.01) {
		// A real but tiny saving (e.g. 105 RAG tokens trimmed ≈ $0.0000157)
		// rounds away to "$0.0000" at four decimals, which reads as a flat
		// zero and makes a working optimizer look broken. Label anything that
		// would vanish at 4dp as a "less-than" floor so it stays visibly
		// non-zero.
		if (Math.abs(value) < 0.00005) return `${value < 0 ? "−" : ""}<$0.0001`;
		return `$${value.toFixed(4)}`;
	}
	return `$${value.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

function formatMs(value: number): string {
	if (!isFinite(value) || value <= 0) return "-";
	if (value >= 1000) return `${(value / 1000).toFixed(2)} s`;
	return `${Math.round(value)} ms`;
}
