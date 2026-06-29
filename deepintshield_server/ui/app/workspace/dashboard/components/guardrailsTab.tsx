"use client";

import { useGetGuardrailMetricsStatsQuery } from "@/lib/store";
import { AlertTriangle, ListChecks, ShieldAlert, ShieldCheck } from "lucide-react";
import { useMemo } from "react";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ChartCard } from "./charts/chartCard";
import { ChartErrorBoundary } from "./charts/chartErrorBoundary";

// Guardrails analytics - basic OSS glimpse tab. Sources every figure from the
// server-aggregated /api/guardrails/metrics-stats endpoint (true counts +
// distributions over the full window), mirroring the HallucinationTab shape:
// a row of stat tiles plus a decisions-breakdown bar chart and a
// decisions-over-time bar chart. Renders a friendly empty state when there is
// no guardrail activity in the window.

export interface GuardrailsTabProps {
	startTime: number;
	endTime: number;
}

// Decision colors - allow (green), deny (red), mask/redact (amber), other (zinc).
const DECISION_COLORS: Record<string, string> = {
	allow: "#10b981",
	deny: "#ef4444",
	mask: "#f59e0b",
	redact: "#f59e0b",
};
const decisionColor = (name: string) => DECISION_COLORS[name.toLowerCase()] ?? "#60a5fa";

export function GuardrailsTab({ startTime, endTime }: GuardrailsTabProps) {
	const { data, isLoading } = useGetGuardrailMetricsStatsQuery({
		start_time: new Date(startTime * 1000).toISOString(),
		end_time: new Date(endTime * 1000).toISOString(),
	});

	// Roll the decision_timeline up into (a) a per-decision total breakdown and
	// (b) an ordered per-bucket series for the over-time chart.
	const { breakdown, timeline, totalDecisions } = useMemo(() => {
		const points = data?.decision_timeline || [];
		const byDecision = new Map<string, number>();
		const byBucket = new Map<string, { label: string; total: number }>();
		let total = 0;
		for (const p of points) {
			const decision = (p.decision || "allow").toLowerCase();
			byDecision.set(decision, (byDecision.get(decision) || 0) + p.count);
			total += p.count;
			const ts = p.bucket ? new Date(p.bucket) : null;
			const key = p.bucket || "";
			const label = ts ? ts.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : key;
			const existing = byBucket.get(key);
			if (existing) existing.total += p.count;
			else byBucket.set(key, { label, total: p.count });
		}
		const breakdown = Array.from(byDecision.entries())
			.map(([name, value]) => ({ name, value }))
			.sort((a, b) => b.value - a.value);
		const timeline = Array.from(byBucket.entries())
			.sort((a, b) => a[0].localeCompare(b[0]))
			.map(([, v], idx) => ({ idx, label: v.label, value: v.total }));
		return { breakdown, timeline, totalDecisions: total };
	}, [data]);

	const tracesTotal = data?.traces_total ?? 0;
	const findingsTotal = data?.findings_total ?? 0;
	const findingsBlocking = data?.findings_blocking ?? 0;
	const hasActivity = tracesTotal > 0 || findingsTotal > 0 || totalDecisions > 0;

	if (!isLoading && !hasActivity) {
		return (
			<div className="border-border/60 bg-card/80 flex flex-col items-center justify-center gap-2 rounded-2xl border px-6 py-16 text-center">
				<ShieldCheck className="text-muted-foreground h-8 w-8" />
				<p className="text-foreground text-sm font-medium">No guardrail activity yet</p>
				<p className="text-muted-foreground max-w-sm text-xs">
					Enable guardrails in Config → Guardrails and send traffic to see decision breakdowns and findings here.
				</p>
			</div>
		);
	}

	return (
		<div className="flex flex-col gap-3">
			<div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-4">
				<StatTile
					icon={<ListChecks className="h-4 w-4" />}
					accent="primary"
					label="Evaluations"
					value={tracesTotal.toLocaleString()}
					subline="Guardrail traces in range"
				/>
				<StatTile
					icon={<ShieldAlert className="h-4 w-4" />}
					accent="violet"
					label="Findings"
					value={findingsTotal.toLocaleString()}
					subline="Detector hits across stages"
				/>
				<StatTile
					icon={<AlertTriangle className="h-4 w-4" />}
					accent="amber"
					label="Blocking findings"
					value={findingsBlocking.toLocaleString()}
					subline="Findings that blocked a request"
				/>
				<StatTile
					icon={<ShieldCheck className="h-4 w-4" />}
					accent="emerald"
					label="Decisions"
					value={totalDecisions.toLocaleString()}
					subline="Allow / deny / mask total"
				/>
			</div>

			<div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
				<ChartCard title="Decisions Breakdown" loading={isLoading} testId="guardrails-chart-breakdown">
					<CategoryBars data={breakdown} colorFor={decisionColor} emptyLabel="No decisions in this time range." />
				</ChartCard>
				<ChartCard title="Decisions Over Time" loading={isLoading} testId="guardrails-chart-timeline">
					<TimelineBars data={timeline} />
				</ChartCard>
			</div>
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
	accent: "primary" | "emerald" | "amber" | "violet";
	label: string;
	value: string;
	subline: string;
}) {
	const accentClass = {
		emerald: "bg-emerald-500/12 text-emerald-600 dark:text-emerald-400",
		primary: "bg-primary/12 text-primary",
		amber: "bg-amber-500/12 text-amber-600 dark:text-amber-400",
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

// CategoryBars renders a labelled bar per category (decision type), color-coded.
function CategoryBars({
	data,
	colorFor,
	emptyLabel,
}: {
	data: Array<{ name: string; value: number }>;
	colorFor: (name: string) => string;
	emptyLabel: string;
}) {
	if (data.length === 0) {
		return <div className="text-muted-foreground flex h-full items-center justify-center px-3 text-center text-xs">{emptyLabel}</div>;
	}
	return (
			<ChartErrorBoundary resetKey={`${data.length}`}>
				<ResponsiveContainer width="100%" height="100%">
					<BarChart data={data} margin={{ top: 6, right: 4, left: 4, bottom: 0 }} barCategoryGap={12}>
						<CartesianGrid strokeDasharray="3 3" vertical={false} className="stroke-zinc-200 dark:stroke-zinc-700" />
						<XAxis dataKey="name" tick={{ fontSize: 10, className: "fill-zinc-500", dy: 4 }} tickLine={false} axisLine={false} />
						<YAxis tick={{ fontSize: 10, className: "fill-zinc-500" }} tickLine={false} axisLine={false} width={32} allowDecimals={false} />
						<Tooltip
							cursor={{ fill: "#8c8c8f", fillOpacity: 0.12 }}
							content={({ active, payload }) => {
								if (!active || !payload?.length) return null;
								const row = payload[0]?.payload as { name: string; value: number } | undefined;
								if (!row) return null;
								return (
									<div className="dashboard-chart-tooltip">
										<div className="dashboard-chart-tooltip-title mb-1 text-xs capitalize">{row.name}</div>
										<div className="text-sm font-medium">{row.value.toLocaleString()}</div>
									</div>
								);
							}}
						/>
						<Bar dataKey="value" radius={[2, 2, 0, 0]} isAnimationActive={false}>
							{data.map((d, i) => (
								<Cell key={i} fill={colorFor(d.name)} fillOpacity={0.85} />
							))}
						</Bar>
					</BarChart>
				</ResponsiveContainer>
			</ChartErrorBoundary>
	);
}

// TimelineBars renders one bar per time bucket - total decisions.
function TimelineBars({ data }: { data: Array<{ idx: number; label: string; value: number }> }) {
	const hasData = data.some((d) => d.value > 0);
	if (!hasData) {
		return (
			<div className="text-muted-foreground flex h-full items-center justify-center px-3 text-center text-xs">
				No decisions in this time range.
			</div>
		);
	}
	return (
			<ChartErrorBoundary resetKey={`${data.length}`}>
				<ResponsiveContainer width="100%" height="100%">
					<BarChart data={data} margin={{ top: 6, right: 4, left: 4, bottom: 0 }} barCategoryGap={1}>
						<CartesianGrid strokeDasharray="3 3" vertical={false} className="stroke-zinc-200 dark:stroke-zinc-700" />
						<XAxis
							dataKey="label"
							tick={{ fontSize: 10, className: "fill-zinc-500", dy: 4 }}
							tickLine={false}
							axisLine={false}
							interval="preserveStartEnd"
							minTickGap={24}
						/>
						<YAxis tick={{ fontSize: 10, className: "fill-zinc-500" }} tickLine={false} axisLine={false} width={32} allowDecimals={false} />
						<Tooltip
							cursor={{ fill: "#8c8c8f", fillOpacity: 0.12 }}
							content={({ active, payload }) => {
								if (!active || !payload?.length) return null;
								const row = payload[0]?.payload as { label: string; value: number } | undefined;
								if (!row) return null;
								return (
									<div className="dashboard-chart-tooltip">
										<div className="dashboard-chart-tooltip-title mb-1 text-xs">{row.label}</div>
										<div className="text-sm font-medium">{row.value.toLocaleString()} decisions</div>
									</div>
								);
							}}
						/>
						<Bar dataKey="value" radius={[2, 2, 0, 0]} isAnimationActive={false} fill="#22d3c4" fillOpacity={0.85} />
					</BarChart>
				</ResponsiveContainer>
			</ChartErrorBoundary>
	);
}
