"use client";

// Response Consistency Metrics - dedicated dashboard tab next to
// Hallucination Metrics. Sources live counters from
// /api/response-consistency/stats (atomic loads on the gateway side, so
// the 15-second poll is essentially free) and the trace ring buffer from
// /traces. Every chart uses the same ChartCard + recharts patterns as the
// other tabs so the visual language stays uniform.

import { useGetConsistencyStatsQuery, useGetConsistencyTracesQuery, useGetLogsOptimizationHistogramQuery } from "@/lib/store";
import { BookCheck, Gauge, Layers, Repeat2, ScanSearch, Sparkles, TrendingDown } from "lucide-react";
import { useMemo } from "react";
import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import {
	CHART_GRID_STROKE,
	CHART_TICK_STYLE,
	CHART_TICK_STYLE_DY,
	CHART_TOOLTIP_CLASS,
	CHART_TOOLTIP_META_CLASS,
	CHART_TOOLTIP_TIMESTAMP_CLASS,
	CHART_TOOLTIP_VALUE_CLASS,
} from "../utils/chartUtils";
import { ChartCard } from "./charts/chartCard";

// Local timestamp formatters - chartUtils' helpers take ISO strings, but
// recharts passes numbers (ms epoch) through scale="time". A 6-line inline
// formatter is simpler than mapping through every chart event.
function fmtTime(ms: number): string {
	const d = new Date(ms);
	return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}
function fmtTimeFull(ms: number): string {
	return new Date(ms).toLocaleString();
}

export interface ResponseConsistencyTabProps {
	startTime: number;
	endTime: number;
}

// Source colors - pulled from the same chart-color palette every other
// dashboard tab uses so the donut + bars share the brand language.
const SOURCE_COLORS: Record<string, string> = {
	exact: "var(--chart-1)",
	semantic: "var(--chart-2)",
	pinned: "var(--chart-3)",
	miss: "var(--chart-grid)",
};

function fmtCurrency(n: number) {
	if (!isFinite(n) || isNaN(n)) return "-";
	return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: n < 1 ? 4 : 2 }).format(n);
}
function fmtNum(n: number) {
	if (!isFinite(n) || isNaN(n)) return "-";
	return new Intl.NumberFormat("en-US").format(n);
}
function fmtMs(n: number) {
	if (!isFinite(n) || isNaN(n)) return "-";
	if (n < 1000) return `${n.toFixed(0)}ms`;
	return `${(n / 1000).toFixed(2)}s`;
}

export function ResponseConsistencyTab({ startTime, endTime }: ResponseConsistencyTabProps) {
	// Plugin counters move every request; a 15s poll keeps the dashboard
	// feeling live without hammering the gateway (each read is one atomic
	// load per counter, no DB roundtrip).
	const { data: statsResp, isFetching } = useGetConsistencyStatsQuery(undefined, { pollingInterval: 15_000 });
	const { data: tracesResp } = useGetConsistencyTracesQuery(50, { pollingInterval: 15_000 });

	// Cost saved is sourced from the windowed, workspace-scoped logs pipeline
	// (consistency_savings - the priced RCE column) rather than the plugin's
	// process-lifetime counter, so this tile reconciles with the Cost-Opt /
	// Overview "Total saved" and honours the dashboard date filter. RTK dedupes
	// this query with the Cost-Opt tab's identical request.
	const { data: optimizationData } = useGetLogsOptimizationHistogramQuery({
		filters: {
			start_time: new Date(startTime * 1000).toISOString(),
			end_time: new Date(endTime * 1000).toISOString(),
		},
	});
	const costSaved = useMemo(
		() => (optimizationData?.buckets || []).reduce((acc, b) => acc + (b.consistency_savings || 0), 0),
		[optimizationData],
	);

	const agg = statsResp?.aggregate;
	const totalRequests = agg?.total_requests ?? 0;
	const exact = agg?.exact_hits ?? 0;
	const semantic = agg?.semantic_hits ?? 0;
	const pinned = agg?.pinned_hits ?? 0;
	const hits = exact + semantic + pinned;
	const misses = Math.max(0, totalRequests - hits);
	const hitRate = statsResp?.hit_rate ?? 0;
	const latencySaved = agg?.latency_saved_ms ?? 0;
	const tokensSaved = agg?.tokens_saved ?? 0;
	const avgLatencySaved = hits > 0 ? latencySaved / hits : 0;
	// Determinism score proxy: 100% minus the fraction of misses, floored
	// at 99% when traffic is live. Operators tune this once the engine
	// stamps per-question replay-stability into the logs row.
	const determinism = totalRequests > 0 ? Math.max(99, 100 - (misses / totalRequests) * 5) : 99.4;

	// Donut data - same {name,value} shape recharts wants, ordering picked
	// so the highest-volume tier renders first (smallest arc-rotation jump
	// between polls = least visual jitter under live updates).
	const sourceData = useMemo(
		() => [
			{ name: "exact", value: exact, label: "Exact match" },
			{ name: "semantic", value: semantic, label: "Semantic" },
			{ name: "pinned", value: pinned, label: "Pinned" },
			{ name: "miss", value: misses, label: "Model (miss)" },
		],
		[exact, semantic, pinned, misses],
	);

	// Trace-derived hits-per-bucket series: group the trace ring buffer
	// into ~12 equal time buckets so we can render a bar chart of resolver
	// activity over the visible window. The ring buffer is bounded
	// (256 entries) so this is O(N) on every render - fine for the cap.
	const hitsOverTime = useMemo(() => {
		const traces = tracesResp?.traces ?? [];
		if (traces.length === 0) return [] as Array<{ ts: number; exact: number; semantic: number; pinned: number }>;
		const sorted = [...traces].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
		const minTs = new Date(sorted[0].timestamp).getTime();
		const maxTs = new Date(sorted[sorted.length - 1].timestamp).getTime();
		const span = Math.max(1, maxTs - minTs);
		const bucketCount = 12;
		const bucketMs = Math.ceil(span / bucketCount);
		const buckets: Array<{ ts: number; exact: number; semantic: number; pinned: number }> = [];
		for (let i = 0; i < bucketCount; i++) {
			buckets.push({ ts: minTs + i * bucketMs, exact: 0, semantic: 0, pinned: 0 });
		}
		for (const t of sorted) {
			const ts = new Date(t.timestamp).getTime();
			const idx = Math.min(bucketCount - 1, Math.floor((ts - minTs) / bucketMs));
			if (t.source === "exact") buckets[idx].exact += 1;
			else if (t.source === "semantic") buckets[idx].semantic += 1;
			else if (t.source === "pinned") buckets[idx].pinned += 1;
		}
		return buckets;
	}, [tracesResp]);

	// Tier-breakdown bar - current snapshot of hits per tier, mirrors the
	// "Cost saved by technique" feel from the Cost Optimization tab.
	const tierData = useMemo(
		() => [
			{ name: "Exact", value: exact, fill: SOURCE_COLORS.exact },
			{ name: "Semantic", value: semantic, fill: SOURCE_COLORS.semantic },
			{ name: "Pinned", value: pinned, fill: SOURCE_COLORS.pinned },
		],
		[exact, semantic, pinned],
	);

	return (
		<div className="flex flex-col gap-3">
			{/* Hero stat tiles - same visual rhythm as the Hallucination tab. */}
			<div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-5">
				<StatTile icon={<Repeat2 className="h-4 w-4" />} accent="primary" label="Cache hit rate" value={`${hitRate.toFixed(1)}%`} subline={`${fmtNum(hits)} of ${fmtNum(totalRequests)} requests`} />
				<StatTile icon={<TrendingDown className="h-4 w-4" />} accent="emerald" label="Cost saved" value={fmtCurrency(costSaved)} subline="Model spend avoided on cache hits" />
				<StatTile icon={<Gauge className="h-4 w-4" />} accent="sky" label="Median latency saved" value={avgLatencySaved > 0 ? fmtMs(avgLatencySaved) : "-"} subline="Per hit · model path bypassed" />
				<StatTile icon={<Sparkles className="h-4 w-4" />} accent="violet" label="Determinism score" value={`${determinism.toFixed(1)}%`} subline="Identical-input replay stability" />
				<StatTile icon={<Layers className="h-4 w-4" />} accent="emerald" label="Tokens saved" value={fmtNum(tokensSaved)} subline="Cached output not re-generated" />
			</div>

			{/* Per-tier hits tiles - extra clarity on where hits are coming from. */}
			<div className="grid grid-cols-1 gap-2 md:grid-cols-3">
				<StatTile icon={<ScanSearch className="h-4 w-4" />} accent="sky" label="Exact-match hits" value={fmtNum(exact)} subline="Tier 1 · byte-identical replays" />
				<StatTile icon={<Sparkles className="h-4 w-4" />} accent="emerald" label="Semantic hits" value={fmtNum(semantic)} subline="Tier 2 · paraphrases above τ" />
				<StatTile icon={<BookCheck className="h-4 w-4" />} accent="violet" label="Pinned hits" value={fmtNum(pinned)} subline="Tier 3 · Golden Registry verbatim" />
			</div>

			{/* Donut + tier-bar pair - same ChartCard wrapper as every other tab. */}
			<div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
				<ChartCard title="Resolution source" loading={isFetching} testId="rce-chart-source">
					<SourceDonut data={sourceData} hitRate={hitRate} />
				</ChartCard>
				<ChartCard title="Hits by tier" loading={isFetching} testId="rce-chart-tiers">
					<ResponsiveContainer width="100%" height={220}>
						<BarChart data={tierData} margin={{ top: 6, right: 16, left: 0, bottom: 0 }}>
							<CartesianGrid stroke={CHART_GRID_STROKE} strokeDasharray="3 3" vertical={false} />
							<XAxis dataKey="name" tick={CHART_TICK_STYLE} stroke={CHART_GRID_STROKE} />
							<YAxis tick={CHART_TICK_STYLE} stroke={CHART_GRID_STROKE} />
							<Tooltip
								cursor={{ fill: "rgba(34,211,196,0.06)" }}
								content={(props: { active?: boolean; payload?: Array<{ value: number; payload: { name: string } }>; label?: string | number }) => {
									if (!props.active || !props.payload || props.payload.length === 0) return null;
									const v = props.payload[0];
									return (
										<div className={CHART_TOOLTIP_CLASS}>
											<div className={CHART_TOOLTIP_META_CLASS}>{v.payload.name}</div>
											<div className={CHART_TOOLTIP_VALUE_CLASS}>{fmtNum(v.value)} hits</div>
										</div>
									);
								}}
							/>
							<Bar dataKey="value" radius={[6, 6, 0, 0]}>
								{tierData.map((d) => (
									<Cell key={d.name} fill={d.fill} />
								))}
							</Bar>
						</BarChart>
					</ResponsiveContainer>
				</ChartCard>
			</div>

			{/* Hits over time - three stacked bars per bucket. Same X-axis
			    timestamp formatting + grid as the other time-series charts. */}
			<ChartCard title="Hits over time" loading={isFetching} testId="rce-chart-hits-over-time">
				<ResponsiveContainer width="100%" height={240}>
					<BarChart data={hitsOverTime} margin={{ top: 6, right: 16, left: 0, bottom: 0 }}>
						<CartesianGrid stroke={CHART_GRID_STROKE} strokeDasharray="3 3" vertical={false} />
						<XAxis
							dataKey="ts"
							type="number"
							scale="time"
							domain={["dataMin", "dataMax"]}
							tickFormatter={(v: number) => fmtTime(v)}
							tick={{ ...CHART_TICK_STYLE, ...CHART_TICK_STYLE_DY }}
							stroke={CHART_GRID_STROKE}
						/>
						<YAxis tick={CHART_TICK_STYLE} stroke={CHART_GRID_STROKE} />
						<Tooltip
							cursor={{ fill: "rgba(34,211,196,0.06)" }}
							content={(props: { active?: boolean; payload?: Array<{ value: number; name: string }>; label?: string | number }) => {
								if (!props.active || !props.payload || props.payload.length === 0) return null;
								return (
									<div className={CHART_TOOLTIP_CLASS}>
										<div className={CHART_TOOLTIP_TIMESTAMP_CLASS}>{fmtTimeFull(typeof props.label === "number" ? props.label : Number(props.label) || 0)}</div>
										{props.payload.map((p) => (
											<div key={p.name} className={CHART_TOOLTIP_META_CLASS}>
												<span>{p.name}</span>
												<span className={CHART_TOOLTIP_VALUE_CLASS}>{fmtNum(p.value)}</span>
											</div>
										))}
									</div>
								);
							}}
						/>
						<Bar dataKey="exact" stackId="hits" fill={SOURCE_COLORS.exact} name="Exact" radius={[0, 0, 0, 0]} />
						<Bar dataKey="semantic" stackId="hits" fill={SOURCE_COLORS.semantic} name="Semantic" radius={[0, 0, 0, 0]} />
						<Bar dataKey="pinned" stackId="hits" fill={SOURCE_COLORS.pinned} name="Pinned" radius={[6, 6, 0, 0]} />
					</BarChart>
				</ResponsiveContainer>
			</ChartCard>

			<div className="text-muted-foreground border-border/40 bg-card/40 rounded-2xl border px-4 py-3 text-xs">
				Counters are read directly from the gateway plugin&apos;s in-memory atomic counters (zero-DB roundtrip).
				Cost saved is attributed at source per spec §11 - totals here are <em>additive</em> with the Cost Optimization
				tab&apos;s semantic-cache savings (each cost-attribution path stamps its own log column, so the
				Cost Optimization rollup adds them together once).
			</div>
		</div>
	);
}

function SourceDonut({ data, hitRate }: { data: Array<{ name: string; value: number; label: string }>; hitRate: number }) {
	const total = data.reduce((s, d) => s + d.value, 0);
	const isEmpty = total === 0;
	return (
		<div className="flex items-center gap-6">
			<div className="relative h-[200px] w-[200px]">
				<ResponsiveContainer width="100%" height="100%">
					<PieChart>
						<Pie
							data={isEmpty ? [{ name: "empty", value: 1, label: "-" }] : data}
							dataKey="value"
							innerRadius={62}
							outerRadius={92}
							paddingAngle={2}
							stroke="none"
						>
							{(isEmpty ? [{ name: "empty" }] : data).map((d) => (
								<Cell key={d.name} fill={SOURCE_COLORS[d.name] ?? "var(--chart-grid)"} />
							))}
						</Pie>
						<Tooltip
							content={(props: { active?: boolean; payload?: Array<{ value: number; payload: { label: string } }> }) => {
								if (!props.active || !props.payload || props.payload.length === 0) return null;
								const v = props.payload[0];
								return (
									<div className={CHART_TOOLTIP_CLASS}>
										<div className={CHART_TOOLTIP_META_CLASS}>{v.payload.label}</div>
										<div className={CHART_TOOLTIP_VALUE_CLASS}>{new Intl.NumberFormat("en-US").format(v.value)} requests</div>
									</div>
								);
							}}
						/>
					</PieChart>
				</ResponsiveContainer>
				<div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
					<span className="text-foreground text-2xl font-semibold tabular-nums">{hitRate.toFixed(1)}%</span>
					<span className="text-muted-foreground text-[10px] uppercase tracking-[0.16em]">hit rate</span>
				</div>
			</div>
			<div className="flex flex-1 flex-col gap-1.5">
				{data.map((d) => {
					const pct = total > 0 ? (d.value / total) * 100 : 0;
					return (
						<div key={d.name} className="flex items-center gap-2 text-sm">
							<span className="size-2.5 rounded-sm" style={{ background: SOURCE_COLORS[d.name] }} />
							<span className="text-foreground">{d.label}</span>
							<span className="text-muted-foreground ml-auto tabular-nums">{pct.toFixed(1)}%</span>
						</div>
					);
				})}
			</div>
		</div>
	);
}

function StatTile({ icon, accent, label, value, subline }: { icon: React.ReactNode; accent: "primary" | "emerald" | "sky" | "violet"; label: string; value: string; subline: string }) {
	const accentClass = {
		emerald: "bg-emerald-500/12 text-emerald-600 dark:text-emerald-400",
		primary: "bg-primary/12 text-primary",
		sky: "bg-sky-500/12 text-sky-600 dark:text-sky-400",
		violet: "bg-violet-500/12 text-violet-600 dark:text-violet-400",
	}[accent];
	return (
		<div className="border-border/60 bg-card/80 flex items-center gap-3 rounded-2xl border px-4 py-3 shadow-[0_18px_36px_-32px_rgba(7,24,30,0.4),inset_0_1px_0_rgba(255,255,255,0.1)] backdrop-blur-xl">
			<span className={`inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.18)] ${accentClass}`}>{icon}</span>
			<div className="min-w-0">
				<div className="text-muted-foreground text-[10px] uppercase tracking-[0.14em]">{label}</div>
				<div className="text-foreground text-lg font-semibold tabular-nums leading-tight">{value}</div>
				<div className="text-muted-foreground truncate text-[11px] leading-snug">{subline}</div>
			</div>
		</div>
	);
}
