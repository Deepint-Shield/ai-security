"use client";

import type { CacheHistogramResponse } from "@/lib/types/logs";
import { useMemo } from "react";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { CHART_COLORS, formatFullTimestamp, formatTimestamp } from "../../utils/chartUtils";
import { ChartErrorBoundary } from "./chartErrorBoundary";
import type { ChartType } from "./chartTypeToggle";

interface CacheHitTypeChartProps {
	data: CacheHistogramResponse | null;
	chartType: ChartType;
	startTime: number;
	endTime: number;
}

function CustomTooltip({ active, payload }: any) {
	if (!active || !payload || !payload.length) return null;

	const data = payload[0]?.payload;
	if (!data) return null;

	return (
		<div className="dashboard-chart-tooltip">
			<div className="dashboard-chart-tooltip-title mb-1 text-xs">{formatFullTimestamp(data.timestamp)}</div>
			<div className="space-y-1 text-sm">
				<div className="flex items-center justify-between gap-4">
					<span className="flex items-center gap-1.5">
						<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.cacheDirectHit }} />
						<span className="dashboard-chart-tooltip-meta">Direct hits</span>
					</span>
					<span className="dashboard-chart-tooltip-value">{data.direct_hits.toLocaleString()}</span>
				</div>
				<div className="flex items-center justify-between gap-4">
					<span className="flex items-center gap-1.5">
						<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.cacheSemanticHit }} />
						<span className="dashboard-chart-tooltip-meta">Semantic hits</span>
					</span>
					<span className="dashboard-chart-tooltip-value">{data.semantic_hits.toLocaleString()}</span>
				</div>
				<div className="border-border/70 flex items-center justify-between gap-4 border-t pt-2">
					<span className="dashboard-chart-tooltip-meta">Total hits</span>
					<span className="dashboard-chart-tooltip-value">{data.cache_hits.toLocaleString()}</span>
				</div>
			</div>
		</div>
	);
}

export function CacheHitTypeChart({ data, chartType, startTime, endTime }: CacheHitTypeChartProps) {
	const chartData = useMemo(() => {
		if (!data?.buckets || !data.bucket_size_seconds) {
			return [];
		}

		return data.buckets.map((bucket, index) => ({
			...bucket,
			index,
			formattedTime: formatTimestamp(bucket.timestamp, data.bucket_size_seconds),
		}));
	}, [data]);

	if (!data?.buckets || chartData.length === 0) {
		return <div className="text-muted-foreground flex h-full items-center justify-center text-sm">No data available</div>;
	}

	const commonProps = {
		data: chartData,
		margin: { top: 6, right: 4, left: 12, bottom: 0 },
	};

	return (
		<ChartErrorBoundary resetKey={`${startTime}-${endTime}-${chartData.length}-cache-hit-types`}>
			<ResponsiveContainer width="100%" height="100%">
				{chartType === "bar" ? (
					<BarChart {...commonProps} barCategoryGap={1}>
						<CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--chart-grid)" />
						<XAxis
							dataKey="index"
							type="number"
							domain={[-0.5, chartData.length - 0.5]}
							tick={{ fontSize: 11, fill: "var(--chart-axis)", dy: 5 }}
							tickLine={false}
							axisLine={false}
							tickFormatter={(idx) => chartData[Math.round(idx)]?.formattedTime || ""}
							interval="preserveStartEnd"
						/>
						<YAxis
							tick={{ fontSize: 11, fill: "var(--chart-axis)" }}
							tickLine={false}
							axisLine={false}
							width={56}
							tickFormatter={(v) => v.toLocaleString()}
							domain={[0, (dataMax: number) => Math.max(dataMax, 1)]}
							allowDataOverflow={false}
						/>
						<Tooltip content={<CustomTooltip />} cursor={{ fill: "var(--chart-cursor)" }} />
						<Bar
							isAnimationActive={false}
							dataKey="direct_hits"
							stackId="cache_hit_types"
							fill={CHART_COLORS.cacheDirectHit}
							fillOpacity={0.9}
							radius={[0, 0, 0, 0]}
							barSize={30}
						/>
						<Bar
							isAnimationActive={false}
							dataKey="semantic_hits"
							stackId="cache_hit_types"
							fill={CHART_COLORS.cacheSemanticHit}
							fillOpacity={0.9}
							radius={[2, 2, 0, 0]}
							barSize={30}
						/>
					</BarChart>
				) : (
					<AreaChart {...commonProps}>
						<CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--chart-grid)" />
						<XAxis
							dataKey="index"
							type="number"
							domain={[-0.5, chartData.length - 0.5]}
							tick={{ fontSize: 11, fill: "var(--chart-axis)" }}
							tickLine={false}
							axisLine={false}
							tickFormatter={(idx) => chartData[Math.round(idx)]?.formattedTime || ""}
							interval="preserveStartEnd"
						/>
						<YAxis
							tick={{ fontSize: 11, fill: "var(--chart-axis)" }}
							tickLine={false}
							axisLine={false}
							width={56}
							tickFormatter={(v) => v.toLocaleString()}
							domain={[0, (dataMax: number) => Math.max(dataMax, 1)]}
							allowDataOverflow={false}
						/>
						<Tooltip content={<CustomTooltip />} />
						<Area
							isAnimationActive={false}
							type="monotone"
							dataKey="direct_hits"
							stackId="1"
							stroke={CHART_COLORS.cacheDirectHit}
							fill={CHART_COLORS.cacheDirectHit}
							fillOpacity={0.7}
						/>
						<Area
							isAnimationActive={false}
							type="monotone"
							dataKey="semantic_hits"
							stackId="1"
							stroke={CHART_COLORS.cacheSemanticHit}
							fill={CHART_COLORS.cacheSemanticHit}
							fillOpacity={0.7}
						/>
					</AreaChart>
				)}
			</ResponsiveContainer>
		</ChartErrorBoundary>
	);
}
