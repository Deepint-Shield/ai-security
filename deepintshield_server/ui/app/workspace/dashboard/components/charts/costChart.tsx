"use client";

import type { CostHistogramResponse } from "@/lib/types/logs";
import { useMemo } from "react";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { CHART_COLORS, COST_CHART_Y_AXIS_WIDTH, formatCost, formatCostAxis, formatFullTimestamp, formatTimestamp, getModelColor } from "../../utils/chartUtils";
import { ChartErrorBoundary } from "./chartErrorBoundary";
import type { ChartType } from "./chartTypeToggle";

interface CostChartProps {
	data: CostHistogramResponse | null;
	chartType: ChartType;
	startTime: number;
	endTime: number;
	selectedModel: string;
}

function CustomTooltip({ active, payload, selectedModel, models }: any) {
	if (!active || !payload || !payload.length) return null;

	const data = payload[0]?.payload;
	if (!data) return null;

	const cacheSavings = Math.max(data.cacheSavingsSeries || 0, 0);
	const netCost = Math.max(data.netCostSeries || 0, 0);
	const grossCost = netCost + cacheSavings;

	return (
		<div className="dashboard-chart-tooltip">
			<div className="dashboard-chart-tooltip-title mb-1 text-xs">{formatFullTimestamp(data.timestamp)}</div>
			<div className="space-y-1 text-sm">
				{selectedModel === "all" ? (
					<>
						{models.map((model: string, idx: number) => {
							const cost = data.by_model?.[model] || 0;
							if (cost === 0) return null;
							return (
								<div key={model} className="flex items-center justify-between gap-4">
									<span className="flex items-center gap-1.5">
										<span className="h-2 w-2 rounded-full" style={{ backgroundColor: getModelColor(idx) }} />
										<span className="dashboard-chart-tooltip-meta max-w-[120px] truncate">{model}</span>
									</span>
									<span className="font-medium">{formatCost(cost)}</span>
								</div>
							);
						})}
					</>
				) : (
					<div className="flex items-center justify-between gap-4">
						<span className="flex items-center gap-1.5">
							<span className="h-2 w-2 rounded-full" style={{ backgroundColor: getModelColor(0) }} />
							<span className="dashboard-chart-tooltip-meta">{selectedModel}</span>
						</span>
						<span className="font-medium">{formatCost(data.by_model?.[selectedModel] || 0)}</span>
					</div>
				)}
				{cacheSavings > 0 && (
					<div className="flex items-center justify-between gap-4">
						<span className="flex items-center gap-1.5">
							<span className="h-2 w-2 rounded-full" style={{ backgroundColor: CHART_COLORS.cacheSavings }} />
							<span className="dashboard-chart-tooltip-meta">Cache savings</span>
						</span>
						<span className="font-medium">{formatCost(cacheSavings)}</span>
					</div>
				)}
				<div className="border-border/70 flex items-center justify-between gap-4 border-t pt-2">
					<span className="dashboard-chart-tooltip-meta">Gross LLM cost</span>
					<span className="font-medium">{formatCost(grossCost)}</span>
				</div>
				<div className="flex items-center justify-between gap-4">
					<span className="dashboard-chart-tooltip-meta">Net cost</span>
					<span className="font-medium">{formatCost(netCost)}</span>
				</div>
			</div>
		</div>
	);
}

export function CostChart({ data, chartType, startTime, endTime, selectedModel }: CostChartProps) {
	const { chartData, displayModels } = useMemo(() => {
		if (!data?.buckets || !data.bucket_size_seconds) {
			return { chartData: [], displayModels: [] };
		}

		const models = selectedModel === "all" ? data.models : [selectedModel];

		const processed = data.buckets.map((bucket, index) => {
			const netCostSeries =
				selectedModel === "all" ? Math.max(bucket.total_cost || 0, 0) : Math.max(bucket.by_model?.[selectedModel] || 0, 0);
			const cacheSavingsSeries =
				selectedModel === "all"
					? Math.max(bucket.cache_savings || 0, 0)
					: Math.max(bucket.by_model_cache_savings?.[selectedModel] || 0, 0);
			const item: any = {
				...bucket,
				index,
				formattedTime: formatTimestamp(bucket.timestamp, data.bucket_size_seconds),
				netCostSeries,
				cacheSavingsSeries,
			};
			models.forEach((model, idx) => {
				item[`model_${idx}`] = bucket.by_model?.[model] || 0;
			});
			return item;
		});

		return { chartData: processed, displayModels: models };
	}, [data, selectedModel]);

	if (!data?.buckets || chartData.length === 0) {
		return <div className="text-muted-foreground flex h-full items-center justify-center text-sm">No data available</div>;
	}

	const commonProps = {
		data: chartData,
		margin: { top: 6, right: 4, left: 4, bottom: 0 },
	};

	return (
		<ChartErrorBoundary resetKey={`${startTime}-${endTime}-${chartData.length}-${selectedModel}`}>
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
							width={COST_CHART_Y_AXIS_WIDTH}
							tickFormatter={(v) => formatCostAxis(v)}
							domain={[0, (dataMax: number) => Math.max(dataMax, 0.01)]}
							allowDataOverflow={false}
						/>
						<Tooltip
							content={<CustomTooltip selectedModel={selectedModel} models={data.models} />}
							cursor={{ fill: "var(--chart-cursor)" }}
						/>
						<Bar
							isAnimationActive={false}
							dataKey="cacheSavingsSeries"
							stackId="savings"
							fill={CHART_COLORS.cacheSavings}
							fillOpacity={0.98}
							barSize={14}
							radius={[4, 4, 0, 0]}
						/>
						{displayModels.map((model, idx) => (
							<Bar
								isAnimationActive={false}
								key={model}
								dataKey={`model_${idx}`}
								stackId="cost"
								fill={getModelColor(idx)}
								fillOpacity={0.9}
								barSize={30}
								radius={idx === displayModels.length - 1 ? [2, 2, 0, 0] : [0, 0, 0, 0]}
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
							width={COST_CHART_Y_AXIS_WIDTH}
							tickFormatter={(v) => formatCostAxis(v)}
							domain={[0, (dataMax: number) => Math.max(dataMax, 0.01)]}
							allowDataOverflow={false}
						/>
						<Tooltip content={<CustomTooltip selectedModel={selectedModel} models={data.models} />} />
						<Area
							isAnimationActive={false}
							type="monotone"
							dataKey="cacheSavingsSeries"
							stroke={CHART_COLORS.cacheSavings}
							fill={CHART_COLORS.cacheSavings}
							fillOpacity={0.35}
						/>
						{displayModels.map((model, idx) => (
							<Area
								isAnimationActive={false}
								key={model}
								type="monotone"
								dataKey={`model_${idx}`}
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
