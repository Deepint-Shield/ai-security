"use client";

import { ChartCard } from "@/app/workspace/dashboard/components/charts/chartCard";
import { ChartErrorBoundary } from "@/app/workspace/dashboard/components/charts/chartErrorBoundary";
import {
	CHART_COLORS,
	CHART_GRID_STROKE,
	CHART_TICK_STYLE_DY,
	getModelColor,
} from "@/app/workspace/dashboard/utils/chartUtils";
import type { KeyHealthStatus, VirtualKey } from "@/lib/types/governance";
import { Activity, AlertTriangle, Gauge, ShieldHalf } from "lucide-react";
import { useMemo } from "react";
import {
	Bar,
	BarChart,
	Cell,
	Legend,
	Pie,
	PieChart,
	ResponsiveContainer,
	Tooltip,
	XAxis,
	YAxis,
} from "recharts";

// Truncate the key id so the X-axis stays readable on small cards. Real key
// ids are uuids; we show the first 8 chars + ellipsis, with the full id in the
// tooltip so operators can still copy-paste it.
function shortKeyId(keyId: string): string {
	return keyId.length > 10 ? `${keyId.slice(0, 8)}…` : keyId;
}

// Build a friendly label for each key when we can - falls back to the short
// uuid. The VK + provider context is useful when an operator is staring at the
// chart trying to identify which physical key is hot.
function keyLabel(keyId: string, lookup: Record<string, { vk: string; provider: string }>): string {
	const meta = lookup[keyId];
	if (!meta) return shortKeyId(keyId);
	return `${meta.vk} · ${meta.provider}`;
}

// Recharts tooltip skeleton - matches the rest of the dashboard's tooltip
// chrome (rounded, blurred surface, two-row k/v layout) so charts feel
// consistent across the app.
function BarTooltip({ active, payload, valueLabel, valueFormatter }: any) {
	if (!active || !payload?.length) return null;
	const row = payload[0]?.payload;
	if (!row) return null;
	return (
		<div className="dashboard-chart-tooltip">
			<div className="dashboard-chart-tooltip-title mb-1 text-xs">{row.label}</div>
			<div className="space-y-1 text-sm">
				<div className="flex items-center justify-between gap-4">
					<span className="dashboard-chart-tooltip-meta">{valueLabel}</span>
					<span className="font-medium">{valueFormatter(row.value)}</span>
				</div>
				{row.keyId && (
					<div className="flex items-center justify-between gap-4">
						<span className="dashboard-chart-tooltip-meta">Key</span>
						<span className="font-mono text-xs">{row.keyId}</span>
					</div>
				)}
			</div>
		</div>
	);
}

function PieTooltip({ active, payload }: any) {
	if (!active || !payload?.length) return null;
	const slice = payload[0];
	if (!slice) return null;
	return (
		<div className="dashboard-chart-tooltip">
			<div className="dashboard-chart-tooltip-title mb-1 text-xs">{slice.name}</div>
			<div className="text-sm">
				<div className="flex items-center justify-between gap-4">
					<span className="dashboard-chart-tooltip-meta">Keys</span>
					<span className="font-medium">{slice.value?.toLocaleString?.() ?? slice.value}</span>
				</div>
			</div>
		</div>
	);
}

interface LoadBalancerChartsProps {
	keyHealth: KeyHealthStatus[];
	virtualKeys: VirtualKey[];
}

// LoadBalancerCharts surfaces routing / rate-limit / throttling signals
// derived from the in-memory key-load tracker that the gateway exposes on
// /governance/key-health. Four small charts in a 2x2 grid:
//   1. Request distribution per key (Model Routing)
//   2. Active in-flight per key      (Rate Limiting headroom)
//   3. Errors per key                 (Throttling - circuit-breaker trips)
//   4. Circuit state breakdown        (overall fleet health donut)
// All four refresh whenever the parent re-fetches /governance/key-health.
export default function LoadBalancerCharts({ keyHealth, virtualKeys }: LoadBalancerChartsProps) {
	// Build a lookup so each key id can be tagged with VK name + provider in
	// tooltips. Useful when several VKs share similar uuids.
	const keyLookup = useMemo(() => {
		const out: Record<string, { vk: string; provider: string }> = {};
		virtualKeys.forEach((vk) => {
			vk.provider_configs?.forEach((pc) => {
				pc.keys?.forEach((k) => {
					if (k.key_id) out[k.key_id] = { vk: vk.name, provider: pc.provider };
				});
			});
		});
		return out;
	}, [virtualKeys]);

	const requestRows = useMemo(
		() =>
			keyHealth
				.map((k) => ({
					label: keyLabel(k.key_id, keyLookup),
					keyId: k.key_id,
					value: k.total_requests,
				}))
				.sort((a, b) => b.value - a.value),
		[keyHealth, keyLookup],
	);

	const activeRows = useMemo(
		() =>
			keyHealth
				.map((k) => ({
					label: keyLabel(k.key_id, keyLookup),
					keyId: k.key_id,
					value: k.active_requests,
				}))
				.sort((a, b) => b.value - a.value),
		[keyHealth, keyLookup],
	);

	const errorRows = useMemo(
		() =>
			keyHealth
				.map((k) => ({
					label: keyLabel(k.key_id, keyLookup),
					keyId: k.key_id,
					value: k.error_count,
				}))
				.sort((a, b) => b.value - a.value),
		[keyHealth, keyLookup],
	);

	const circuitRows = useMemo(() => {
		const counts = { closed: 0, half_open: 0, open: 0 };
		keyHealth.forEach((k) => {
			counts[k.circuit_state] = (counts[k.circuit_state] ?? 0) + 1;
		});
		return [
			{ name: "Healthy", value: counts.closed, fill: CHART_COLORS.success },
			{ name: "Recovering", value: counts.half_open, fill: CHART_COLORS.cost },
			{ name: "Circuit Open", value: counts.open, fill: CHART_COLORS.error },
		].filter((row) => row.value > 0);
	}, [keyHealth]);

	const totalRequests = requestRows.reduce((s, r) => s + r.value, 0);
	const totalActive = activeRows.reduce((s, r) => s + r.value, 0);
	const totalErrors = errorRows.reduce((s, r) => s + r.value, 0);

	return (
		<div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
			<ChartCard
				title="Model Routing"
				icon={<Gauge className="h-3.5 w-3.5" />}
				headerActions={
					<span className="text-muted-foreground text-[11px] tabular-nums">
						Total {totalRequests.toLocaleString()}
					</span>
				}
				testId="lb-chart-routing"
			>
				<KeyBarChart rows={requestRows} valueLabel="Requests" valueFormatter={(v) => v.toLocaleString()} barColor={CHART_COLORS.promptTokens} />
			</ChartCard>

			<ChartCard
				title="Rate Limiting"
				icon={<Activity className="h-3.5 w-3.5" />}
				headerActions={
					<span className="text-muted-foreground text-[11px] tabular-nums">
						In flight {totalActive.toLocaleString()}
					</span>
				}
				testId="lb-chart-active"
			>
				<KeyBarChart
					rows={activeRows}
					valueLabel="Active"
					valueFormatter={(v) => v.toLocaleString()}
					barColor={CHART_COLORS.totalTokens}
					zeroMessage="All keys idle - no requests in flight."
				/>
			</ChartCard>

			<ChartCard
				title="Throttling"
				icon={<AlertTriangle className="h-3.5 w-3.5" />}
				headerActions={
					<span className={`text-[11px] tabular-nums ${totalErrors > 0 ? "text-red-500" : "text-muted-foreground"}`}>
						Errors {totalErrors.toLocaleString()}
					</span>
				}
				testId="lb-chart-errors"
			>
				<KeyBarChart
					rows={errorRows}
					valueLabel="Errors"
					valueFormatter={(v) => v.toLocaleString()}
					barColor={CHART_COLORS.error}
					zeroMessage="No errors recorded - all keys healthy."
				/>
			</ChartCard>

			<ChartCard
				title="Circuit Breaker"
				icon={<ShieldHalf className="h-3.5 w-3.5" />}
				headerActions={
					<span className="text-muted-foreground text-[11px] tabular-nums">
						{keyHealth.length} key{keyHealth.length === 1 ? "" : "s"}
					</span>
				}
				testId="lb-chart-circuit"
			>
				<CircuitStateDonut rows={circuitRows} />
			</ChartCard>
		</div>
	);
}

// KeyBarChart renders a horizontal-style bar (label below, value above) with
// the same axis chrome as the dashboard's other small charts.
function KeyBarChart({
	rows,
	valueLabel,
	valueFormatter,
	barColor,
	emptyMessage = "No data yet - send some traffic.",
	zeroMessage,
}: {
	rows: { label: string; keyId: string; value: number }[];
	valueLabel: string;
	valueFormatter: (n: number) => string;
	barColor: string;
	emptyMessage?: string;
	zeroMessage?: string;
}) {
	if (rows.length === 0) {
		return <div className="text-muted-foreground flex h-full items-center justify-center text-xs">{emptyMessage}</div>;
	}
	if (rows.every((r) => r.value === 0)) {
		return <div className="text-muted-foreground flex h-full items-center justify-center text-xs">{zeroMessage ?? emptyMessage}</div>;
	}
	return (
		<ChartErrorBoundary resetKey={`${rows.length}-${valueLabel}`}>
			<ResponsiveContainer width="100%" height="100%">
				<BarChart data={rows} margin={{ top: 6, right: 4, left: 4, bottom: 0 }} barCategoryGap={4}>
					<XAxis
						dataKey="label"
						tick={CHART_TICK_STYLE_DY}
						tickLine={false}
						axisLine={false}
						interval={0}
						height={32}
						tickFormatter={(v: string) => (v.length > 18 ? `${v.slice(0, 16)}…` : v)}
					/>
					<YAxis
						tick={{ fontSize: 11, fill: "var(--chart-axis)" }}
						tickLine={false}
						axisLine={false}
						width={36}
						tickFormatter={(v) => v.toLocaleString()}
						stroke={CHART_GRID_STROKE}
					/>
					<Tooltip content={<BarTooltip valueLabel={valueLabel} valueFormatter={valueFormatter} />} cursor={{ fill: "var(--chart-cursor)" }} />
					<Bar dataKey="value" radius={[6, 6, 0, 0]} isAnimationActive={false}>
						{rows.map((row, idx) => (
							<Cell key={row.keyId} fill={rows.length > 1 ? getModelColor(idx) : barColor} />
						))}
					</Bar>
				</BarChart>
			</ResponsiveContainer>
		</ChartErrorBoundary>
	);
}

function CircuitStateDonut({ rows }: { rows: { name: string; value: number; fill: string }[] }) {
	if (rows.length === 0) {
		return <div className="text-muted-foreground flex h-full items-center justify-center text-xs">No data yet - send some traffic.</div>;
	}
	return (
		<ChartErrorBoundary resetKey={`circuit-${rows.length}`}>
			<ResponsiveContainer width="100%" height="100%">
				<PieChart>
					<Tooltip content={<PieTooltip />} cursor={false} />
					<Legend
						verticalAlign="bottom"
						height={28}
						iconType="circle"
						iconSize={8}
						formatter={(value: string) => <span className="text-muted-foreground text-[11px]">{value}</span>}
					/>
					<Pie
						data={rows}
						dataKey="value"
						nameKey="name"
						innerRadius="58%"
						outerRadius="86%"
						paddingAngle={2}
						stroke="var(--chart-bg, transparent)"
						isAnimationActive={false}
					>
						{rows.map((row) => (
							<Cell key={row.name} fill={row.fill} />
						))}
					</Pie>
				</PieChart>
			</ResponsiveContainer>
		</ChartErrorBoundary>
	);
}
