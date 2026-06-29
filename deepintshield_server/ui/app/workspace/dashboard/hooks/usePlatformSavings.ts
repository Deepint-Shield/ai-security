"use client";

import { useMemo } from "react";

import { useGetAgenticCacheSavingsSeriesQuery } from "@/lib/store/apis";
import type { CostHistogramResponse } from "@/lib/types/logs";

import { getCostHistogramTotals } from "../utils/costTotals";

// PlatformSavings is the single canonical savings shape every cost surface
// reads, so the "Savings" number reconciles across Overview / Cost-Opt / Cache.
export interface PlatformSavings {
	totalCost: number;
	// Gateway cost-optimization savings (cache_savings) - the sum of all seven
	// log-pipeline sources: semantic + prompt-cache + reasoning + compression +
	// rag + summarization + Response-Consistency.
	gatewaySavings: number;
	// Agentic-cache savings (tool-result / decision cache) - a separate event
	// store, layered in as an additive overlay over the same window.
	agenticCacheSaved: number;
	// gatewaySavings + agenticCacheSaved - every cost-saving feature on the platform.
	totalSavings: number;
	// totalCost + totalSavings - the counterfactual "unoptimised" spend.
	wouldHaveSpent: number;
	// totalSavings / wouldHaveSpent × 100.
	savingsRatePct: number;
}

export interface UsePlatformSavingsArgs {
	// The gateway cost histogram the consuming tab already fetched. RCE savings
	// arrive inside its cache_savings (the 7th source), so no separate RCE query
	// is needed here.
	costData: CostHistogramResponse | null;
	// Active dashboard window (unix seconds) - scopes the agentic-cache overlay
	// to the same range as the cost histogram.
	startTime: number;
	endTime: number;
	// Cost-histogram dimension to roll up (default "all"). A specific model is
	// dimension-scoped, so the flat agentic-cache overlay is auto-omitted then
	// (gateway savings still include RCE, which is per-row model-stamped).
	selectedModel?: string;
	// Set false on dimension-scoped surfaces (per-provider / per-team) where a
	// flat platform total must not be sprayed across a breakdown. When false the
	// agentic-cache overlay is omitted (gateway savings still include RCE).
	includeAgenticCache?: boolean;
}

// usePlatformSavings composes the one reconciling savings number. Zero added
// latency: the agentic-cache savings-series is already polled by the Agentic
// Cache console and RTK-dedupes, and the gateway totals are a pure-CPU reduction
// over buckets the caller already holds.
export function usePlatformSavings({
	costData,
	startTime,
	endTime,
	selectedModel = "all",
	includeAgenticCache = true,
}: UsePlatformSavingsArgs): PlatformSavings {
	const since = useMemo(() => new Date(startTime * 1000).toISOString(), [startTime]);
	const until = useMemo(() => new Date(endTime * 1000).toISOString(), [endTime]);

	// The agentic-cache overlay is a flat platform total, so it only belongs on
	// the "all" view - never sprayed across a single-model breakdown.
	const wantAgenticCache = includeAgenticCache && selectedModel === "all";

	// skip the query entirely on dimension-scoped surfaces.
	const { data: savingsSeries } = useGetAgenticCacheSavingsSeriesQuery(
		{ bucket: "hour", since, until },
		{ skip: !wantAgenticCache },
	);

	return useMemo(() => {
		const gateway = getCostHistogramTotals(costData, selectedModel);
		const agenticCacheSaved = wantAgenticCache
			? (savingsSeries?.series || []).reduce((acc, b) => acc + (b.cost_saved_usd || 0), 0)
			: 0;

		const totalSavings = gateway.totalSavings + agenticCacheSaved;
		const wouldHaveSpent = gateway.totalCost + totalSavings;
		const savingsRatePct = wouldHaveSpent > 0 ? (totalSavings / wouldHaveSpent) * 100 : 0;

		return {
			totalCost: gateway.totalCost,
			gatewaySavings: gateway.totalSavings,
			agenticCacheSaved,
			totalSavings,
			wouldHaveSpent,
			savingsRatePct,
		};
	}, [costData, savingsSeries, selectedModel, wantAgenticCache]);
}
