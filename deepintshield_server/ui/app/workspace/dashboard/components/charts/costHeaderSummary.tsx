"use client";

import { CHART_COLORS, formatCost } from "../../utils/chartUtils";

interface CostHeaderSummaryProps {
	totalCost: number;
	totalSavings: number;
	testIdPrefix?: string;
	className?: string;
}

function SummaryMetric({
	label,
	value,
	color,
	testId,
}: {
	label: string;
	value: number;
	color: string;
	testId?: string;
}) {
	return (
		<span
			className="inline-flex min-w-0 items-center gap-1.5 whitespace-nowrap px-2.5 py-1 text-[11px] leading-none"
			data-testid={testId}
		>
			<span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
			<span className="text-muted-foreground">{label}</span>
			<span className="font-medium text-foreground">{formatCost(value)}</span>
		</span>
	);
}

export function CostHeaderSummary({ totalCost, totalSavings, testIdPrefix, className }: CostHeaderSummaryProps) {
	// `max-w-full` keeps the pill within its parent; the parent header row uses
	// `flex-wrap` so the pill drops to its own line on narrow cards instead of
	// being clipped. Inner metrics use `whitespace-nowrap` so the value never
	// wraps inside the pill.
	return (
		<div
			className={`inline-flex max-w-full items-center overflow-hidden rounded-full border border-border bg-muted/40 ${className ?? ""}`.trim()}
		>
			<SummaryMetric
				label="Cost"
				value={totalCost}
				color={CHART_COLORS.cost}
				testId={testIdPrefix ? `${testIdPrefix}-total-cost` : undefined}
			/>
			<span className="h-5 w-px bg-muted/40" aria-hidden="true" />
			<SummaryMetric
				label="Savings"
				value={totalSavings}
				color={CHART_COLORS.cacheSavings}
				testId={testIdPrefix ? `${testIdPrefix}-total-savings` : undefined}
			/>
		</div>
	);
}
