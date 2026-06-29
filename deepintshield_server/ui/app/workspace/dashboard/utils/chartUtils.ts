// Chart utility functions for the dashboard

// Format timestamp based on bucket size
export function formatTimestamp(timestamp: string, bucketSizeSeconds: number): string {
	const date = new Date(timestamp);

	if (bucketSizeSeconds >= 86400) {
		// Daily buckets: "Jan 20"
		return date.toLocaleDateString("en-US", { month: "short", day: "numeric" });
	} else if (bucketSizeSeconds >= 3600) {
		// Hourly buckets: "10:00"
		return date.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: false });
	} else {
		// Sub-hourly: "10:15"
		return date.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: false });
	}
}

// Format full timestamp for tooltip
export function formatFullTimestamp(timestamp: string): string {
	const date = new Date(timestamp);
	return date.toLocaleString("en-US", {
		month: "short",
		day: "numeric",
		hour: "2-digit",
		minute: "2-digit",
		hour12: false,
	});
}

// Format cost values
export function formatCost(cost: number): string {
	if (cost < 0.01) {
		return `$${cost.toFixed(4)}`;
	}
	return `$${cost.toFixed(2)}`;
}

export function formatCostAxis(cost: number): string {
	const absolute = Math.abs(cost);

	if (absolute === 0) {
		return "$0";
	}

	if (absolute >= 1) {
		return `$${cost.toFixed(2).replace(/\.00$/, "").replace(/(\.\d)0$/, "$1")}`;
	}

	if (absolute >= 0.01) {
		return `$${cost.toFixed(2)}`;
	}

	if (absolute >= 0.001) {
		return `$${cost.toFixed(4).replace(/0+$/, "").replace(/\.$/, "")}`;
	}

	return `$${cost.toFixed(5).replace(/0+$/, "").replace(/\.$/, "")}`;
}

// Format token values
export function formatTokens(tokens: number): string {
	if (tokens >= 1000000) {
		return `${(tokens / 1000000).toFixed(1)}M`;
	}
	if (tokens >= 1000) {
		return `${(tokens / 1000).toFixed(1)}K`;
	}
	return tokens.toLocaleString();
}

// Color palette for models
export const MODEL_COLORS = ["#21d3c4", "#60a9ff", "#8c8bff", "#ffbe5a", "#ff7b67", "#25d4e8", "#72f1b8", "#c8e86a"];

// Get color for a model by index
export function getModelColor(index: number): string {
	return MODEL_COLORS[index % MODEL_COLORS.length];
}

// Distinct color palette for teams (visually separated from model colors)
export const TEAM_COLORS = ["#e056a0", "#7c5cfc", "#ff8c42", "#3ecf8e", "#38bdf8", "#f59e0b", "#f472b6", "#a78bfa", "#fb7185", "#34d399"];

// Get color for a team by index
export function getTeamColor(index: number): string {
	return TEAM_COLORS[index % TEAM_COLORS.length];
}

// Format latency values
export function formatLatency(ms: number): string {
	if (ms >= 1000) return `${(ms / 1000).toFixed(2)}s`;
	return `${ms.toFixed(0)}ms`;
}

// Latency chart color palette
export const LATENCY_COLORS = {
	avg: "#25d4e8",
	p90: "#60a9ff",
	p95: "#ffbe5a",
	p99: "#ff7b67",
};

// Shared CSS class constants for chart card headers.
// `flex-wrap` is intentional on rows that mix pills + filters + toggles so
// the controls drop to a new line when the card column is narrow instead of
// being clipped by the card's overflow-hidden. Right-alignment (justify-end)
// is preserved per wrapped line so the visual alignment of each row stays
// consistent - only the number of lines changes when space is tight.
export const CHART_HEADER_ACTIONS_CLASS = "flex min-w-0 w-full flex-col-reverse gap-2";
export const CHART_HEADER_LEGEND_CLASS = "flex min-w-0 flex-wrap items-center gap-2 pl-2 text-xs";
export const CHART_HEADER_CONTROLS_CLASS = "flex min-w-0 flex-wrap items-center justify-end gap-2";
export const COST_CHART_HEADER_ACTIONS_CLASS = "flex min-w-0 w-full flex-col gap-2";
export const COST_CHART_HEADER_FILTERS_CLASS = "flex min-w-0 flex-wrap items-center justify-end gap-2";
export const COST_CHART_HEADER_SUMMARY_ROW_CLASS = "flex min-w-0 flex-wrap items-center gap-2";
export const CHART_GRID_STROKE = "var(--chart-grid)";
export const CHART_TICK_STYLE = { fontSize: 11, fill: "var(--chart-axis)" } as const;
export const CHART_TICK_STYLE_DY = { fontSize: 11, fill: "var(--chart-axis)", dy: 5 } as const;
export const CHART_CURSOR = { fill: "var(--chart-cursor)", fillOpacity: 1 } as const;
export const CHART_TOOLTIP_CLASS =
	"rounded-[1rem] border border-[color:var(--chart-tooltip-border)] bg-[color:var(--chart-tooltip-bg)]/94 px-3.5 py-3 shadow-[0_18px_40px_-24px_rgba(7,24,30,0.42)] backdrop-blur-xl";
export const CHART_TOOLTIP_TIMESTAMP_CLASS = "mb-1 text-xs text-muted-foreground";
export const CHART_TOOLTIP_META_CLASS = "text-muted-foreground";
export const CHART_TOOLTIP_VALUE_CLASS = "font-semibold text-foreground";
export const CHART_NEEDLE_COLOR = "var(--chart-axis-strong)";
export const COST_CHART_Y_AXIS_WIDTH = 55;

// Chart colors
export const CHART_COLORS = {
	success: "#21d3c4",
	error: "#ff7b67",
	promptTokens: "#60a9ff",
	completionTokens: "#21d3c4",
	totalTokens: "#8c8bff",
	cost: "#ffbe5a",
	cacheSavings: "#f7d66b",
	cachedReadTokens: "#25d4e8",
	cacheHit: "#21d3c4",
	cacheMiss: "#ff7b67",
	cacheDirectHit: "#60a9ff",
	cacheSemanticHit: "#25d4e8",
	cacheScopeUser: "#21d3c4",
	cacheScopeUseCase: "#60a9ff",
	cacheScopeSession: "#8c8bff",
	cacheScopeVirtualKey: "#ffbe5a",
	cacheScopeCustomMetadata: "#ff7b67",
	cacheScopeTenant: "#72f1b8",
	cacheSourceAuto: "#21d3c4",
	cacheSourceExplicit: "#60a9ff",
	cacheSourceDefault: "#ffbe5a",
	cacheSourceRequestFallback: "#ff7b67",
};
