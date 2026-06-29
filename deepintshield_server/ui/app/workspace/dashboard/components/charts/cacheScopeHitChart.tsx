"use client";

import type { CacheHistogramResponse } from "@/lib/types/logs";
import { useMemo } from "react";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { CHART_COLORS, formatTokens } from "../../utils/chartUtils";

interface CacheScopeHitChartProps {
	data: CacheHistogramResponse | null;
}

const scopeColorMap = {
	User: CHART_COLORS.cacheScopeUser,
	"Use Case": CHART_COLORS.cacheScopeUseCase,
	Session: CHART_COLORS.cacheScopeSession,
	"Virtual Key": CHART_COLORS.cacheScopeVirtualKey,
	"Custom Metadata": CHART_COLORS.cacheScopeCustomMetadata,
	Tenant: CHART_COLORS.cacheScopeTenant,
} as const;

function CustomTooltip({ active, payload }: any) {
	if (!active || !payload || !payload.length) return null;

	const data = payload[0]?.payload;
	if (!data) return null;

	return (
		<div className="dashboard-chart-tooltip">
			<div className="dashboard-chart-tooltip-title mb-1 text-xs">{data.name}</div>
			<div className="flex items-center justify-between gap-4 text-sm">
				<span className="dashboard-chart-tooltip-meta">Hits</span>
				<span className="dashboard-chart-tooltip-value">{formatTokens(data.value)}</span>
			</div>
		</div>
	);
}

export function CacheScopeHitChart({ data }: CacheScopeHitChartProps) {
	const chartData = useMemo(() => {
		if (!data?.buckets?.length) {
			return [];
		}

		const totals = data.buckets.reduce(
			(acc, bucket) => {
				acc.user += bucket.user_scope_hits || 0;
				acc.useCase += bucket.use_case_scope_hits || 0;
				acc.session += bucket.session_scope_hits || 0;
				acc.virtualKey += bucket.virtual_key_scope_hits || 0;
				acc.customMetadata += bucket.custom_metadata_scope_hits || 0;
				acc.tenant += bucket.tenant_scope_hits || 0;
				return acc;
			},
			{ user: 0, useCase: 0, session: 0, virtualKey: 0, customMetadata: 0, tenant: 0 },
		);

		return [
			{ name: "User", value: totals.user },
			{ name: "Use Case", value: totals.useCase },
			{ name: "Session", value: totals.session },
			{ name: "Virtual Key", value: totals.virtualKey },
			{ name: "Custom Metadata", value: totals.customMetadata },
			{ name: "Tenant", value: totals.tenant },
		].filter((item) => item.value > 0);
	}, [data]);

	if (chartData.length === 0) {
		return <div className="text-muted-foreground flex h-full items-center justify-center text-sm">No scope hits available</div>;
	}

	return (
		<ResponsiveContainer width="100%" height="100%">
			<BarChart data={chartData} layout="vertical" margin={{ top: 6, right: 16, left: 8, bottom: 0 }}>
				<XAxis type="number" tick={{ fontSize: 11, fill: "var(--chart-axis)" }} tickLine={false} axisLine={false} tickFormatter={formatTokens} />
				<YAxis dataKey="name" type="category" tick={{ fontSize: 11, fill: "var(--chart-axis)" }} tickLine={false} axisLine={false} width={104} />
				<Tooltip content={<CustomTooltip />} cursor={false} />
				<Bar dataKey="value" radius={[0, 6, 6, 0]} isAnimationActive={false}>
					{chartData.map((entry) => (
						<Cell key={entry.name} fill={scopeColorMap[entry.name as keyof typeof scopeColorMap]} />
					))}
				</Bar>
			</BarChart>
		</ResponsiveContainer>
	);
}
