"use client";

import { useMemo, type ReactNode } from "react";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { formatFullTimestamp } from "../../utils/chartUtils";
import { ChartErrorBoundary } from "./chartErrorBoundary";
import type { ChartType } from "./chartTypeToggle";

export interface GovernanceTimeSeriesDatum {
	timestamp: string;
	index: number;
	formattedTime: string;
	[key: string]: number | string | undefined;
}

export interface GovernanceTimeSeriesSeries {
	key: string;
	label: string;
	color: string;
}

interface GovernanceTimeSeriesChartProps {
	data: GovernanceTimeSeriesDatum[];
	series: GovernanceTimeSeriesSeries[];
	chartType: ChartType;
	startTime: number;
	endTime: number;
	stacked?: boolean;
	yAxisFormatter?: (value: number) => string;
	tooltipValueFormatter?: (value: number, series: GovernanceTimeSeriesSeries, datum: GovernanceTimeSeriesDatum) => string;
	tooltipFooter?: (datum: GovernanceTimeSeriesDatum) => ReactNode;
	yAxisWidth?: number;
}

interface CustomTooltipProps {
	active?: boolean;
	payload?: Array<{ payload?: GovernanceTimeSeriesDatum }>;
	series: GovernanceTimeSeriesSeries[];
	tooltipValueFormatter?: (value: number, series: GovernanceTimeSeriesSeries, datum: GovernanceTimeSeriesDatum) => string;
	tooltipFooter?: (datum: GovernanceTimeSeriesDatum) => ReactNode;
}

function CustomTooltip({
	active,
	payload,
	series,
	tooltipValueFormatter,
	tooltipFooter,
}: CustomTooltipProps) {
	if (!active || !payload || !payload.length) return null;

	const datum = payload[0]?.payload;
	if (!datum) return null;

	return (
		<div className="dashboard-chart-tooltip">
			<div className="dashboard-chart-tooltip-title mb-1 text-xs">{formatFullTimestamp(datum.timestamp)}</div>
			<div className="space-y-1 text-sm">
				{series.map((seriesItem) => {
					const rawValue = datum[seriesItem.key];
					const value = typeof rawValue === "number" ? rawValue : 0;
					if (value === 0) return null;

					return (
						<div key={seriesItem.key} className="flex items-center justify-between gap-4">
							<span className="flex items-center gap-1.5">
								<span className="h-2 w-2 rounded-full" style={{ backgroundColor: seriesItem.color }} />
								<span className="dashboard-chart-tooltip-meta">{seriesItem.label}</span>
							</span>
							<span className="font-medium">
								{tooltipValueFormatter ? tooltipValueFormatter(value, seriesItem, datum) : value.toLocaleString()}
							</span>
						</div>
					);
				})}
				{tooltipFooter ? tooltipFooter(datum) : null}
			</div>
		</div>
	);
}

export function GovernanceTimeSeriesChart({
	data,
	series,
	chartType,
	startTime,
	endTime,
	stacked = false,
	yAxisFormatter = (value) => value.toLocaleString(),
	tooltipValueFormatter,
	tooltipFooter,
	yAxisWidth = 50,
}: GovernanceTimeSeriesChartProps) {
	const chartData = useMemo(() => data, [data]);

	if (chartData.length === 0 || series.length === 0) {
		return <div className="text-muted-foreground flex h-full items-center justify-center text-sm">No data available</div>;
	}

	const commonProps = {
		data: chartData,
		margin: { top: 6, right: 4, left: 4, bottom: 0 },
	};

	const barSize = stacked || series.length === 1 ? 30 : 8;

	return (
		<ChartErrorBoundary resetKey={`${startTime}-${endTime}-${chartData.length}-${series.map((item) => item.key).join(",")}-${chartType}`}>
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
							tickFormatter={(index) => chartData[Math.round(index)]?.formattedTime || ""}
							interval="preserveStartEnd"
						/>
						<YAxis
							tick={{ fontSize: 11, fill: "var(--chart-axis)" }}
							tickLine={false}
							axisLine={false}
							width={yAxisWidth}
							tickFormatter={(value) => yAxisFormatter(Number(value))}
							domain={[0, (dataMax: number) => Math.max(dataMax, 1)]}
							allowDataOverflow={false}
						/>
						<Tooltip
							content={
								<CustomTooltip
									series={series}
									tooltipValueFormatter={tooltipValueFormatter}
									tooltipFooter={tooltipFooter}
								/>
							}
							cursor={{ fill: "var(--chart-cursor)" }}
						/>
						{series.map((seriesItem, index) => (
							<Bar
								isAnimationActive={false}
								key={seriesItem.key}
								dataKey={seriesItem.key}
								stackId={stacked ? "governance-series" : undefined}
								fill={seriesItem.color}
								fillOpacity={0.9}
								barSize={barSize}
								radius={stacked ? (index === series.length - 1 ? [2, 2, 0, 0] : [0, 0, 0, 0]) : [2, 2, 0, 0]}
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
							tickFormatter={(index) => chartData[Math.round(index)]?.formattedTime || ""}
							interval="preserveStartEnd"
						/>
						<YAxis
							tick={{ fontSize: 11, fill: "var(--chart-axis)" }}
							tickLine={false}
							axisLine={false}
							width={yAxisWidth}
							tickFormatter={(value) => yAxisFormatter(Number(value))}
							domain={[0, (dataMax: number) => Math.max(dataMax, 1)]}
							allowDataOverflow={false}
						/>
						<Tooltip
							content={
								<CustomTooltip
									series={series}
									tooltipValueFormatter={tooltipValueFormatter}
									tooltipFooter={tooltipFooter}
								/>
							}
						/>
						{series.map((seriesItem) => (
							<Area
								isAnimationActive={false}
								key={seriesItem.key}
								type="monotone"
								dataKey={seriesItem.key}
								stackId={stacked ? "governance-series" : undefined}
								stroke={seriesItem.color}
								fill={seriesItem.color}
								fillOpacity={stacked ? 0.7 : 0.3}
							/>
						))}
					</AreaChart>
				)}
			</ResponsiveContainer>
		</ChartErrorBoundary>
	);
}
