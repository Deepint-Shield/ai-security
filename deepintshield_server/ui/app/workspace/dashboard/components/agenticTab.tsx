"use client";

import { useGetAgenticBasicStatsQuery } from "@/lib/store";
import { Bot, CheckCircle2, ShieldX, UserCheck } from "lucide-react";
import { useMemo } from "react";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ChartCard } from "./charts/chartCard";
import { ChartErrorBoundary } from "./charts/chartErrorBoundary";

// Agentic analytics - basic OSS glimpse tab. Sources from the minimal
// /api/agentic-security/stats endpoint (allow/deny/approval/mask counts + an
// hourly timeline computed from the decision audit store). Mirrors the
// GuardrailsTab/HallucinationTab shape: stat tiles + a verdict-breakdown bar
// chart + a decisions-over-time bar chart. Friendly empty state when the PDP
// has made no decisions in the window.

export interface AgenticTabProps {
	startTime: number;
	endTime: number;
}

const VERDICT_COLORS: Record<string, string> = {
	allow: "#10b981",
	deny: "#ef4444",
	approval: "#f59e0b",
	mask: "#60a5fa",
};

export function AgenticTab({ startTime, endTime }: AgenticTabProps) {
	const { data, isLoading } = useGetAgenticBasicStatsQuery({
		since: new Date(startTime * 1000).toISOString(),
		until: new Date(endTime * 1000).toISOString(),
	});

	const breakdown = useMemo(() => {
		if (!data) return [] as Array<{ name: string; value: number }>;
		return [
			{ name: "allow", value: data.allow },
			{ name: "deny", value: data.deny },
			{ name: "approval", value: data.approval },
			{ name: "mask", value: data.mask },
		].filter((d) => d.value > 0);
	}, [data]);

	const timeline = useMemo(() => {
		const points = data?.timeline || [];
		return points.map((p, idx) => {
			const ts = p.bucket ? new Date(p.bucket) : null;
			const label = ts ? ts.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : `#${idx + 1}`;
			return { idx, label, value: p.allow + p.deny + p.approval + p.mask };
		});
	}, [data]);

	const total = data?.total ?? 0;

	if (!isLoading && total === 0) {
		return (
			<div className="border-border/60 bg-card/80 flex flex-col items-center justify-center gap-2 rounded-2xl border px-6 py-16 text-center">
				<Bot className="text-muted-foreground h-8 w-8" />
				<p className="text-foreground text-sm font-medium">No agentic decisions yet</p>
				<p className="text-muted-foreground max-w-sm text-xs">
					Enable agentic policy decisions in Config → Agentic Policy and call <code className="font-mono">/decide</code> to see verdict
					breakdowns here.
				</p>
			</div>
		);
	}

	return (
		<div className="flex flex-col gap-3">
			<div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-4">
				<StatTile
					icon={<CheckCircle2 className="h-4 w-4" />}
					accent="emerald"
					label="Allowed"
					value={(data?.allow ?? 0).toLocaleString()}
					subline="Calls permitted"
				/>
				<StatTile
					icon={<ShieldX className="h-4 w-4" />}
					accent="rose"
					label="Denied"
					value={(data?.deny ?? 0).toLocaleString()}
					subline="Calls blocked"
				/>
				<StatTile
					icon={<UserCheck className="h-4 w-4" />}
					accent="amber"
					label="Approval"
					value={(data?.approval ?? 0).toLocaleString()}
					subline="Require human approval"
				/>
				<StatTile
					icon={<Bot className="h-4 w-4" />}
					accent="primary"
					label="Total decisions"
					value={total.toLocaleString()}
					subline="PDP decisions in range"
				/>
			</div>

			<div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
				<ChartCard title="Verdicts Breakdown" loading={isLoading} testId="agentic-chart-breakdown">
					<CategoryBars data={breakdown} emptyLabel="No decisions in this time range." />
				</ChartCard>
				<ChartCard title="Decisions Over Time" loading={isLoading} testId="agentic-chart-timeline">
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
	accent: "primary" | "emerald" | "amber" | "rose";
	label: string;
	value: string;
	subline: string;
}) {
	const accentClass = {
		emerald: "bg-emerald-500/12 text-emerald-600 dark:text-emerald-400",
		primary: "bg-primary/12 text-primary",
		amber: "bg-amber-500/12 text-amber-600 dark:text-amber-400",
		rose: "bg-rose-500/12 text-rose-600 dark:text-rose-400",
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

function CategoryBars({ data, emptyLabel }: { data: Array<{ name: string; value: number }>; emptyLabel: string }) {
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
								<Cell key={i} fill={VERDICT_COLORS[d.name] ?? "#60a5fa"} fillOpacity={0.85} />
							))}
						</Bar>
					</BarChart>
				</ResponsiveContainer>
			</ChartErrorBoundary>
	);
}

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
