"use client";

import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

interface ChartCardProps {
	title: string;
	children: ReactNode;
	headerActions?: ReactNode;
	loading?: boolean;
	testId?: string;
	height?: string;
	icon?: ReactNode;
}

// ChartCard wraps every metric tile rendered across the analytics tabs.
// Polish here lifts every chart in the dashboard at once: rounder
// corners, a subtle title accent dot, soft hover tint, and a thin
// inset highlight at the top so cards visibly float on the gradient
// mesh background instead of looking pasted on.
export function ChartCard({ title, children, headerActions, loading, testId, height = "180px", icon }: ChartCardProps) {
	const cardClass = cn(
		"group relative min-w-0 rounded-2xl px-3.5 py-3 flex flex-col overflow-hidden",
		"transition-colors duration-150",
		"hover:border-primary/35",
	);

	const titleRow = (
		<div className="mb-3 flex items-start justify-between gap-3 shrink-0">
			{/*
			 * Title reserves its natural width via `shrink-0` so short labels
			 * like "COST" or "LATENCY" never collapse to "CO…" when the
			 * actions row is wide. The inner span caps at `max-w-[180px]` and
			 * truncates with an ellipsis only for unusually long titles
			 * (e.g. "AI GUARDRAIL LATENCY"), keeping the actions row safe
			 * from being pushed off the card.
			 */}
			<div className="flex shrink-0 items-center gap-2 min-w-0">
				{icon ? (
					<span className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-md border border-primary/20 bg-primary/10 text-primary">
						{icon}
					</span>
				) : (
					<span className="text-primary/90 inline-block h-2 w-2 shrink-0 rounded-full bg-primary/70 shadow-[0_0_0_3px_rgba(34,211,196,0.10)]" />
				)}
				<span
					title={title}
					className="text-primary/90 truncate max-w-[180px] text-[12px] font-semibold tracking-[0.12em] uppercase"
				>
					{title}
				</span>
			</div>
			{headerActions && (
				// Actions absorb all the space pressure: `min-w-0 flex-shrink` so the
				// inner `flex-wrap` rows actually have a chance to break onto a new
				// line instead of being clipped by the card's `overflow-hidden`.
				<div className="flex min-w-0 flex-shrink items-center" data-testid={testId ? `${testId}-actions` : undefined}>
					{headerActions}
				</div>
			)}
		</div>
	);

	if (loading) {
		return (
			<Card className={cardClass} data-testid={testId}>
				<TopAccent />
				{titleRow}
				<div
					className="min-h-0 flex-1"
					style={{ minHeight: height, marginBottom: 6 }}
					data-testid={testId ? `${testId}-chart-skeleton` : undefined}
				>
					<Skeleton className="h-full w-full rounded-xl" />
				</div>
			</Card>
		);
	}

	return (
		<Card className={cardClass} data-testid={testId}>
			<TopAccent />
			{titleRow}
			<div className="min-h-0 flex-1" style={{ minHeight: height }}>
				{children}
			</div>
		</Card>
	);
}

// TopAccent renders a hairline primary-tinted gradient strip at the
// very top of the card. Pure decoration - adds a subtle "branded"
// signal without shouting. Pointer-events disabled so it never
// intercepts hover/clicks.
function TopAccent() {
	return (
		<div
			className="pointer-events-none absolute inset-x-3 top-0 h-px bg-gradient-to-r from-transparent via-primary/40 to-transparent opacity-0 transition-opacity duration-200 group-hover:opacity-100"
			aria-hidden
		/>
	);
}
