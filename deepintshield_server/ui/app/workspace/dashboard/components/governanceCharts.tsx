"use client";

import { useMemo } from "react";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import {
	CHART_CURSOR,
	CHART_GRID_STROKE,
	CHART_TICK_STYLE,
	CHART_TOOLTIP_CLASS,
	CHART_TOOLTIP_META_CLASS,
	CHART_TOOLTIP_TIMESTAMP_CLASS,
	CHART_TOOLTIP_VALUE_CLASS,
	getModelColor,
} from "../utils/chartUtils";
import { ChartErrorBoundary } from "./charts/chartErrorBoundary";

export interface MetricDatum {
	label: string;
	value: number;
}

interface MetricBarChartProps {
	data: MetricDatum[];
	formatValue?: (value: number) => string;
}

function MetricTooltip({
	active,
	payload,
	formatValue,
}: {
	active?: boolean;
	payload?: Array<{ payload?: MetricDatum }>;
	formatValue: (value: number) => string;
}) {
	if (!active || !payload?.length || !payload[0]?.payload) return null;

	const datum = payload[0].payload;
	return (
		<div className={CHART_TOOLTIP_CLASS}>
			<div className={CHART_TOOLTIP_TIMESTAMP_CLASS}>{datum.label}</div>
			<div className="flex items-center justify-between gap-4 text-sm">
				<span className={CHART_TOOLTIP_META_CLASS}>Value</span>
				<span className={CHART_TOOLTIP_VALUE_CLASS}>{formatValue(datum.value)}</span>
			</div>
		</div>
	);
}

export function MetricBarChart({ data, formatValue = (value) => value.toLocaleString() }: MetricBarChartProps) {
	const chartData = useMemo(() => data.filter((datum) => datum.value > 0).slice(0, 8), [data]);

	if (chartData.length === 0) {
		return <div className="text-muted-foreground flex h-full items-center justify-center text-sm">No data available</div>;
	}

	return (
		<ChartErrorBoundary resetKey={JSON.stringify(chartData)}>
			<ResponsiveContainer width="100%" height="100%">
				<BarChart data={chartData} layout="vertical" margin={{ top: 6, right: 8, left: 4, bottom: 0 }}>
					<CartesianGrid strokeDasharray="3 3" horizontal={false} stroke={CHART_GRID_STROKE} />
					<XAxis type="number" tick={CHART_TICK_STYLE} tickLine={false} axisLine={false} />
					<YAxis type="category" dataKey="label" tick={CHART_TICK_STYLE} tickLine={false} axisLine={false} width={120} interval={0} />
					<Tooltip content={<MetricTooltip formatValue={formatValue} />} cursor={CHART_CURSOR} />
					<Bar isAnimationActive={false} dataKey="value" radius={[0, 2, 2, 0]} barSize={20}>
						{chartData.map((_, index) => (
							<Cell key={`metric-cell-${index}`} fill={getModelColor(index)} fillOpacity={0.9} />
						))}
					</Bar>
				</BarChart>
			</ResponsiveContainer>
		</ChartErrorBoundary>
	);
}

export interface StackedMetricDatum {
	label: string;
	[key: string]: number | string;
}

export interface StackedSeries {
	key: string;
	label: string;
	color: string;
}

interface StackedMetricBarChartProps {
	data: StackedMetricDatum[];
	series: StackedSeries[];
	formatValue?: (value: number) => string;
}

function StackedTooltip({
	active,
	payload,
	label,
	series,
	formatValue,
}: {
	active?: boolean;
	payload?: Array<{ dataKey?: string; value?: number }>;
	label?: string;
	series: StackedSeries[];
	formatValue: (value: number) => string;
}) {
	if (!active || !payload?.length) return null;

	return (
		<div className={CHART_TOOLTIP_CLASS}>
			<div className={CHART_TOOLTIP_TIMESTAMP_CLASS}>{label}</div>
			<div className="space-y-1 text-sm">
				{series.map((entry) => {
					const point = payload.find((item) => item.dataKey === entry.key);
					if (!point || !point.value) return null;
					return (
						<div key={entry.key} className="flex items-center justify-between gap-4">
							<span className="flex items-center gap-2">
								<span className="h-2 w-2 rounded-full" style={{ backgroundColor: entry.color }} />
								<span className={CHART_TOOLTIP_META_CLASS}>{entry.label}</span>
							</span>
							<span className={CHART_TOOLTIP_VALUE_CLASS}>{formatValue(point.value)}</span>
						</div>
					);
				})}
			</div>
		</div>
	);
}

export function StackedMetricBarChart({
	data,
	series,
	formatValue = (value) => value.toLocaleString(),
}: StackedMetricBarChartProps) {
	if (data.length === 0 || series.length === 0) {
		return <div className="text-muted-foreground flex h-full items-center justify-center text-sm">No data available</div>;
	}

	return (
		<ChartErrorBoundary resetKey={JSON.stringify({ data, series })}>
			<ResponsiveContainer width="100%" height="100%">
				<BarChart data={data} layout="vertical" margin={{ top: 6, right: 8, left: 4, bottom: 0 }}>
					<CartesianGrid strokeDasharray="3 3" horizontal={false} stroke={CHART_GRID_STROKE} />
					<XAxis type="number" tick={CHART_TICK_STYLE} tickLine={false} axisLine={false} />
					<YAxis type="category" dataKey="label" tick={CHART_TICK_STYLE} tickLine={false} axisLine={false} width={120} interval={0} />
					<Tooltip content={<StackedTooltip series={series} formatValue={formatValue} />} cursor={CHART_CURSOR} />
					{series.map((entry) => (
						<Bar key={entry.key} isAnimationActive={false} dataKey={entry.key} stackId="total" fill={entry.color} radius={[0, 0, 0, 0]} />
					))}
				</BarChart>
			</ResponsiveContainer>
		</ChartErrorBoundary>
	);
}
