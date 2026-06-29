"use client";

import { useGetLogsOptimizationHistogramQuery } from "@/lib/store";
import type { OptimizationHistogramBucket } from "@/lib/types/logs";
import { Gauge, ScanSearch, Sparkles } from "lucide-react";
import { useMemo } from "react";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ChartCard } from "./charts/chartCard";
import { ChartErrorBoundary } from "./charts/chartErrorBoundary";

// Hallucination Metrics - quality + control telemetry aggregated at the
// workspace level. Every series is sourced from the optimization-histogram
// endpoint (the same data the Cost Optimization tab uses) so totals stay
// consistent. The OSS backend already aggregates the hallucination_* columns
// per bucket (framework/logstore/rdb.go GetOptimizationHistogram).
//
// Metric semantics:
//   * Faithfulness, Answer Relevance, Coherence, Helpfulness, Citation
//     Precision - 0..1, higher = better
//   * Hallucination Score - 0..1, higher = MORE hallucinated (lower is better)
//   * Improvement - 0..1 heuristic on how strongly the proactive control
//     techniques showed up in the response (higher = better)
//
// Cloud-only surfaces (ML scoring/eval config, ground-truth datasets) are
// intentionally NOT part of this OSS tab. The eval columns are populated by
// the optional async scorer; when nothing has scored traffic in the window
// the charts show a friendly empty state rather than a flat zero line.

export interface HallucinationTabProps {
	startTime: number;
	endTime: number;
}

export function HallucinationTab({ startTime, endTime }: HallucinationTabProps) {
	const { data } = useGetLogsOptimizationHistogramQuery({
		filters: {
			start_time: new Date(startTime * 1000).toISOString(),
			end_time: new Date(endTime * 1000).toISOString(),
		},
	});

	const rollup = useMemo(() => {
		const buckets = data?.buckets || [];
		let scored = 0;
		let controlApplied = 0;
		// Per-metric sum + count: each detector only contributes from buckets
		// where it actually produced a value. Without this, buckets that scored
		// but skipped a detector (value coerced to 0 by Go's float64 JSON
		// marshalling) would drag the displayed average down.
		const m = {
			faith: { sum: 0, n: 0 },
			relevance: { sum: 0, n: 0 },
			coherence: { sum: 0, n: 0 },
			helpful: { sum: 0, n: 0 },
			citation: { sum: 0, n: 0 },
			score: { sum: 0, n: 0 },
			improvement: { sum: 0, n: 0 },
		};
		const add = (slot: { sum: number; n: number }, v: number | undefined) => {
			if (typeof v !== "number" || !isFinite(v) || v <= 0) return;
			slot.sum += v;
			slot.n++;
		};
		for (const b of buckets) {
			scored += b.hallucination_scored || 0;
			controlApplied += b.hallucination_control_applied || 0;
			if ((b.hallucination_scored || 0) > 0) {
				add(m.faith, b.hallucination_avg_faithfulness);
				add(m.relevance, b.hallucination_avg_answer_relevance);
				add(m.coherence, b.hallucination_avg_coherence);
				add(m.helpful, b.hallucination_avg_helpfulness);
				add(m.citation, b.hallucination_avg_citation_precision);
				add(m.score, b.hallucination_avg_score);
			}
			if ((b.hallucination_control_applied || 0) > 0) {
				add(m.improvement, b.hallucination_control_avg_improvement);
			}
		}
		const avg = (slot: { sum: number; n: number }) => (slot.n > 0 ? slot.sum / slot.n : 0);
		return {
			scored,
			controlApplied,
			faith: avg(m.faith),
			relevance: avg(m.relevance),
			coherence: avg(m.coherence),
			helpful: avg(m.helpful),
			citation: avg(m.citation),
			score: avg(m.score),
			improvement: avg(m.improvement),
		};
	}, [data]);

	const buckets = data?.buckets || [];

	return (
		<div className="flex flex-col gap-3">
			{/* Hero tile row - workspace-aggregated averages. */}
			<div className="grid grid-cols-1 gap-2 md:grid-cols-2">
				<StatTile
					icon={<ScanSearch className="h-4 w-4" />}
					accent="primary"
					label="Control applied"
					value={rollup.controlApplied.toLocaleString()}
					subline="Requests with proactive mitigations"
				/>
				<StatTile
					icon={<Sparkles className="h-4 w-4" />}
					accent="emerald"
					label="Avg improvement"
					value={fmt(rollup.improvement)}
					subline="Heuristic · higher is better"
				/>
			</div>

			{/* OSS scope: only the deterministic control's Improvement heuristic is
			    plotted. ML quality scoring (faithfulness, relevance, coherence,
			    helpfulness, citation precision, hallucination score) is a
			    Cloud/Enterprise feature and is intentionally not shown here. */}
			<div className="grid grid-cols-1 gap-2">
				<MetricCard
					title="Improvement over time"
					testId="halluc-chart-improvement"
					buckets={buckets}
					pick={(b) => b.hallucination_control_avg_improvement}
					good="up"
					average={rollup.improvement}
					useControl
					pendingLabel="Turn on techniques in Hallucination Control to see improvement here."
				/>
			</div>
			<p className="text-muted-foreground text-xs">
				ML quality scoring - faithfulness, answer relevance, coherence, citation precision, and the composite hallucination score - is
				available on DeepintShield Cloud / Enterprise.
			</p>
		</div>
	);
}

function StatTile({
	icon,
	accent,
	label,
	value,
	subline,
}: {
	icon: React.ReactNode;
	accent: "primary" | "emerald" | "sky" | "violet";
	label: string;
	value: string;
	subline: string;
}) {
	const accentClass = {
		emerald: "bg-emerald-500/12 text-emerald-600 dark:text-emerald-400",
		primary: "bg-primary/12 text-primary",
		sky: "bg-sky-500/12 text-sky-600 dark:text-sky-400",
		violet: "bg-violet-500/12 text-violet-600 dark:text-violet-400",
	}[accent];
	return (
		<div className="border-border/60 bg-card/80 flex items-center gap-3 rounded-2xl border px-4 py-3 shadow-[0_18px_36px_-32px_rgba(7,24,30,0.4),inset_0_1px_0_rgba(255,255,255,0.1)] backdrop-blur-xl">
			<span
				className={`inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.18)] ${accentClass}`}
			>
				{icon}
			</span>
			<div className="min-w-0">
				<p className="text-muted-foreground text-[10px] font-semibold tracking-[0.16em] uppercase">{label}</p>
				<p className="text-foreground mt-1 text-xl leading-none font-semibold tabular-nums">{value}</p>
				<p className="text-muted-foreground mt-1 text-[11px]">{subline}</p>
			</div>
		</div>
	);
}

type MetricPick = (b: OptimizationHistogramBucket) => number | undefined;

// MetricCard wraps a single metric trend in a ChartCard. The card's title row
// carries the average + direction hint; the body is ONLY the chart so it can
// follow the OSS chart-rendering rule (ResponsiveContainer rendered directly
// inside ChartCard, wrapped only by ChartErrorBoundary - no extra flex-1 div
// that would collapse the chart height to 0).
function MetricCard({
	title,
	testId,
	buckets,
	pick,
	good,
	average,
	pendingLabel,
	useControl,
}: {
	title: string;
	testId: string;
	buckets: OptimizationHistogramBucket[];
	pick: MetricPick;
	good: "up" | "down";
	average: number;
	pendingLabel?: string;
	useControl?: boolean;
}) {
	return (
		<ChartCard
			title={title}
			loading={false}
			testId={testId}
			icon={<Gauge className="h-3.5 w-3.5" />}
			headerActions={
				<span className="text-muted-foreground text-[11px] tabular-nums">
					avg <span className="text-foreground font-semibold">{fmt(average)}</span> · {good === "up" ? "higher better" : "lower better"}
				</span>
			}
		>
			<MetricTrend buckets={buckets} pick={pick} good={good} average={average} pendingLabel={pendingLabel} useControl={useControl} />
		</ChartCard>
	);
}

// MetricTrend renders a per-bucket bar chart with the same Recharts chrome the
// rest of the dashboard uses. Bars are color-coded by direction: green when on
// the good side of the average, amber otherwise. `good="down"` inverts the
// comparison for the Hallucination Score chart (lower = better).
function MetricTrend({
	buckets,
	pick,
	good,
	average,
	pendingLabel,
	useControl,
}: {
	buckets: OptimizationHistogramBucket[];
	pick: MetricPick;
	good: "up" | "down";
	average: number;
	pendingLabel?: string;
	// useControl swaps the "did this bucket have data?" predicate from
	// hallucination_scored (eval side) to hallucination_control_applied
	// (control side). Needed for the Improvement chart, where eval may not
	// have run but control still has data to plot.
	useControl?: boolean;
}) {
	const chartData = useMemo(
		() =>
			buckets.map((b, idx) => {
				const sentinel = useControl ? b.hallucination_control_applied || 0 : b.hallucination_scored || 0;
				const v = sentinel > 0 ? pick(b) || 0 : 0;
				const ts = b.timestamp ? new Date(b.timestamp) : null;
				const label = ts ? ts.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : `#${idx + 1}`;
				return { idx, value: v, label, scored: sentinel };
			}),
		[buckets, pick, useControl],
	);
	const hasData = chartData.some((d) => d.value > 0);
	if (!hasData) {
		return (
			<div className="text-muted-foreground flex h-full items-center justify-center px-3 text-center text-xs">
				{pendingLabel ?? "No responses checked in this time range."}
			</div>
		);
	}
	return (
		<ChartErrorBoundary resetKey={`${chartData.length}-${good}`}>
			<ResponsiveContainer width="100%" height="100%">
				<BarChart data={chartData} margin={{ top: 6, right: 4, left: 4, bottom: 0 }} barCategoryGap={1}>
					<CartesianGrid strokeDasharray="3 3" vertical={false} className="stroke-zinc-200 dark:stroke-zinc-700" />
					<XAxis
						dataKey="label"
						tick={{ fontSize: 10, className: "fill-zinc-500", dy: 4 }}
						tickLine={false}
						axisLine={false}
						interval="preserveStartEnd"
						minTickGap={24}
					/>
					<YAxis
						domain={[0, 1]}
						tick={{ fontSize: 10, className: "fill-zinc-500" }}
						tickLine={false}
						axisLine={false}
						width={32}
						tickFormatter={(v) => v.toFixed(1)}
					/>
					<Tooltip
						cursor={{ fill: "#8c8c8f", fillOpacity: 0.12 }}
						content={({ active, payload }) => {
							if (!active || !payload?.length) return null;
							const row = payload[0]?.payload as { label: string; value: number; scored: number } | undefined;
							if (!row) return null;
							return (
								<div className="dashboard-chart-tooltip">
									<div className="dashboard-chart-tooltip-title mb-1 text-xs">{row.label}</div>
									<div className="text-sm">
										<div className="flex items-center justify-between gap-4">
											<span className="dashboard-chart-tooltip-meta">Score</span>
											<span className="font-medium">{row.value > 0 ? row.value.toFixed(3) : "-"}</span>
										</div>
									</div>
								</div>
							);
						}}
					/>
					<Bar dataKey="value" radius={[2, 2, 0, 0]} isAnimationActive={false}>
						{chartData.map((d, i) => {
							const isGood = good === "up" ? d.value >= average : d.value <= average;
							const fill = d.value > 0 ? (isGood ? "#10b981" : "#f59e0b") : "#52525b40";
							return <Cell key={i} fill={fill} fillOpacity={d.value > 0 ? 0.85 : 0.25} />;
						})}
					</Bar>
				</BarChart>
			</ResponsiveContainer>
		</ChartErrorBoundary>
	);
}

function fmt(v: number): string {
	if (!isFinite(v) || v <= 0) return "-";
	return v.toFixed(3);
}
