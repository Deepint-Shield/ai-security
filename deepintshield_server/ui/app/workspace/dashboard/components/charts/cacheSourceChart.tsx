"use client";

import type { CacheHistogramResponse } from "@/lib/types/logs";
import { useMemo } from "react";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { CHART_COLORS, formatTokens } from "../../utils/chartUtils";

interface CacheSourceChartProps {
	data: CacheHistogramResponse | null;
}

const sourceColorMap = {
	"Auto Derived": CHART_COLORS.cacheSourceAuto,
	"Explicit Override": CHART_COLORS.cacheSourceExplicit,
	"Default Key": CHART_COLORS.cacheSourceDefault,
	"Request Fallback": CHART_COLORS.cacheSourceRequestFallback,
} as const;

export function CacheSourceChart({ data }: CacheSourceChartProps) {
	const chartData = useMemo(() => {
		if (!data?.buckets?.length) {
			return [];
		}

		const totals = data.buckets.reduce(
			(acc, bucket) => {
				acc.auto += bucket.auto_scoped_hits || 0;
				acc.explicit += bucket.explicit_override_hits || 0;
				acc.defaultKey += bucket.default_scope_hits || 0;
				acc.requestFallback += bucket.request_fallback_hits || 0;
				return acc;
			},
			{ auto: 0, explicit: 0, defaultKey: 0, requestFallback: 0 },
		);

		return [
			{ name: "Auto Derived", value: totals.auto },
			{ name: "Explicit Override", value: totals.explicit },
			{ name: "Default Key", value: totals.defaultKey },
			{ name: "Request Fallback", value: totals.requestFallback },
		].filter((item) => item.value > 0);
	}, [data]);

	if (chartData.length === 0) {
		return <div className="text-muted-foreground flex h-full items-center justify-center text-sm">No cache-source hits available</div>;
	}

	return (
		<ResponsiveContainer width="100%" height="100%">
			<BarChart data={chartData} layout="vertical" margin={{ top: 6, right: 16, left: 8, bottom: 0 }}>
				<XAxis type="number" tick={{ fontSize: 11, fill: "var(--chart-axis)" }} tickLine={false} axisLine={false} tickFormatter={formatTokens} />
				<YAxis dataKey="name" type="category" tick={{ fontSize: 11, fill: "var(--chart-axis)" }} tickLine={false} axisLine={false} width={112} />
				<Tooltip
					formatter={(value: number) => value.toLocaleString()}
					contentStyle={{ borderRadius: "1rem", borderColor: "var(--chart-tooltip-border)" }}
				/>
				<Bar dataKey="value" radius={[0, 6, 6, 0]} isAnimationActive={false}>
					{chartData.map((entry) => (
						<Cell key={entry.name} fill={sourceColorMap[entry.name as keyof typeof sourceColorMap]} />
					))}
				</Bar>
			</BarChart>
		</ResponsiveContainer>
	);
}
