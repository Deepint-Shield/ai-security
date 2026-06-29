"use client";

import type { ProviderCostHistogramBucket, ProviderCostHistogramResponse } from "@/lib/types/logs";
import { useMemo } from "react";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import {
	CHART_COLORS,
	COST_CHART_Y_AXIS_WIDTH,
	formatCost,
	formatCostAxis,
	formatFullTimestamp,
	formatTimestamp,
	formatTokens,
	getModelColor,
} from "../../utils/chartUtils";
import { ChartErrorBoundary } from "./chartErrorBoundary";
import type { ChartType } from "./chartTypeToggle";

type ValueMode = "cost" | "count";

interface ProviderCostChartProps {
	data: ProviderCostHistogramResponse | null;
	chartType: ChartType;
	startTime: number;
	endTime: number;
	selectedProvider: string;
	valueMode?: ValueMode;
}

function CustomTooltip({ active, payload, selectedProvider, providers, valueMode }: any) {
	if (!active || !payload || !payload.length) return null;

	const data = payload[0]?.payload;
	if (!data) return null;
	const isCount = valueMode === "count";
	const formatValue = (value: number) => (isCount ? formatTokens(value) : formatCost(value));
	const cacheSavings = isCount ? 0 : Math.max(data.cacheSavingsSeries || 0, 0);
	const netCost = Math.max(data.netCostSeries || 0, 0);
	const grossCost = netCost + cacheSavings;

	return (
		<div className="dashboard-chart-tooltip">
			<div className="dashboard-chart-tooltip-title mb-1 text-xs">{formatFullTimestamp(data.timestamp)}</div>
			<div className="space-y-1 text-sm">
				{selectedProvider === "all" ? (
					<>
						{providers.map((provider: string, idx: number) => {
							const value = data.by_provider?.[provider] || 0;
							if (value === 0) return null;
							return (
								<div key={provider} className="flex items-center justify-between gap-4">
									<span className="flex items-center gap-1.5">
										<span className="h-2 w-2 rounded-full" style={{ backgroundColor: getModelColor(idx) }} />
										<span className="dashboard-chart-tooltip-meta max-w-[120px] truncate">{provider}</span>
									</span>
									<span className="font-medium">{formatValue(value)}</span>
								</div>
							);
						})}
						{cacheSavings > 0 && (
							<div className="flex items-center justify-between gap-4">
								<span className="flex items-center gap-1.5">
									<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.cacheSavings }} />
									<span className="dashboard-chart-tooltip-meta">Cache savings</span>
								</span>
								<span className="font-medium">{formatValue(cacheSavings)}</span>
							</div>
						)}
						<div className="border-border/70 flex items-center justify-between gap-4 border-t pt-2">
							<span className="dashboard-chart-tooltip-meta">{isCount ? "Total" : "Gross cost"}</span>
							<span className="font-medium">{formatValue(grossCost)}</span>
						</div>
						{!isCount && (
							<div className="flex items-center justify-between gap-4">
								<span className="dashboard-chart-tooltip-meta">Net cost</span>
								<span className="font-medium">{formatValue(netCost)}</span>
							</div>
						)}
					</>
				) : (
					<>
						<div className="flex items-center justify-between gap-4">
							<span className="flex items-center gap-1.5">
								<span className="h-2 w-2 rounded-full" style={{ backgroundColor: getModelColor(0) }} />
								<span className="dashboard-chart-tooltip-meta">{selectedProvider}</span>
							</span>
							<span className="font-medium">{formatValue(data.by_provider?.[selectedProvider] || 0)}</span>
						</div>
						{cacheSavings > 0 && (
							<div className="flex items-center justify-between gap-4">
								<span className="flex items-center gap-1.5">
									<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.cacheSavings }} />
									<span className="dashboard-chart-tooltip-meta">Cache savings</span>
								</span>
								<span className="font-medium">{formatValue(cacheSavings)}</span>
							</div>
						)}
						{!isCount && (
							<>
								<div className="border-border/70 flex items-center justify-between gap-4 border-t pt-2">
									<span className="dashboard-chart-tooltip-meta">Gross cost</span>
									<span className="font-medium">{formatValue(grossCost)}</span>
								</div>
								<div className="flex items-center justify-between gap-4">
									<span className="dashboard-chart-tooltip-meta">Net cost</span>
									<span className="font-medium">{formatValue(netCost)}</span>
								</div>
							</>
						)}
					</>
				)}
			</div>
		</div>
	);
}

export function ProviderCostChart({ data, chartType, startTime, endTime, selectedProvider, valueMode = "cost" }: ProviderCostChartProps) {
	const isCount = valueMode === "count";
	const yAxisFormatter = isCount ? (value: number) => formatTokens(value) : (value: number) => formatCostAxis(value);
	const yAxisWidth = isCount ? 44 : COST_CHART_Y_AXIS_WIDTH;
	const getBucketProviderCacheSavings = (bucket: ProviderCostHistogramBucket, provider: string) =>
		bucket.by_provider_cache_savings?.[provider] || 0;

	const { chartData, displayProviders } = useMemo(() => {
		if (!data?.buckets || !data.bucket_size_seconds) {
			return { chartData: [], displayProviders: [] };
		}

		const providers = selectedProvider === "all" ? data.providers : [selectedProvider];

		const processed = data.buckets.map((bucket, index) => {
			const item: any = {
				...bucket,
				index,
				formattedTime: formatTimestamp(bucket.timestamp, data.bucket_size_seconds),
				netCostSeries: selectedProvider === "all" ? Math.max(bucket.total_cost || 0, 0) : Math.max(bucket.by_provider?.[selectedProvider] || 0, 0),
				cacheSavingsSeries:
					selectedProvider === "all"
						? Math.max(bucket.cache_savings || 0, 0)
						: Math.max(getBucketProviderCacheSavings(bucket, selectedProvider) || 0, 0),
			};
			providers.forEach((provider, idx) => {
				item[`provider_${idx}`] = bucket.by_provider?.[provider] || 0;
			});
			return item;
		});

		return { chartData: processed, displayProviders: providers };
	}, [data, selectedProvider]);

	if (!data?.buckets || chartData.length === 0) {
		return <div className="text-muted-foreground flex h-full items-center justify-center text-sm">No data available</div>;
	}

	const commonProps = {
		data: chartData,
		margin: { top: 6, right: 4, left: 4, bottom: 0 },
	};

	return (
		<ChartErrorBoundary resetKey={`${startTime}-${endTime}-${chartData.length}-${selectedProvider}`}>
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
							width={yAxisWidth}
							tickFormatter={(v) => yAxisFormatter(v)}
							domain={[0, (dataMax: number) => Math.max(dataMax, isCount ? 1 : 0.01)]}
							allowDataOverflow={false}
						/>
						<Tooltip
							content={<CustomTooltip selectedProvider={selectedProvider} providers={data.providers} valueMode={valueMode} />}
							cursor={{ fill: "var(--chart-cursor)" }}
						/>
						{displayProviders.map((provider, idx) => (
							<Bar
								isAnimationActive={false}
								key={provider}
								dataKey={`provider_${idx}`}
								stackId="cost"
								fill={getModelColor(idx)}
								fillOpacity={0.9}
								barSize={30}
								radius={idx === displayProviders.length - 1 ? [2, 2, 0, 0] : [0, 0, 0, 0]}
							/>
						))}
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
							width={yAxisWidth}
							tickFormatter={(v) => yAxisFormatter(v)}
							domain={[0, (dataMax: number) => Math.max(dataMax, isCount ? 1 : 0.01)]}
							allowDataOverflow={false}
						/>
						<Tooltip content={<CustomTooltip selectedProvider={selectedProvider} providers={data.providers} valueMode={valueMode} />} />
						{displayProviders.map((provider, idx) => (
							<Area
								isAnimationActive={false}
								key={provider}
								type="monotone"
								dataKey={`provider_${idx}`}
								stackId="1"
								stroke={getModelColor(idx)}
								fill={getModelColor(idx)}
								fillOpacity={0.7}
							/>
						))}
					</AreaChart>
				)}
			</ResponsiveContainer>
		</ChartErrorBoundary>
	);
}
