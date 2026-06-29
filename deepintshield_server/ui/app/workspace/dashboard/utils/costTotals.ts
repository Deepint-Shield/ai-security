import type {
	CostHistogramResponse,
	MCPCostHistogramResponse,
	ProviderCostHistogramResponse,
} from "@/lib/types/logs";

export interface CostTotals {
	totalCost: number;
	totalSavings: number;
}

const ZERO_TOTALS: CostTotals = { totalCost: 0, totalSavings: 0 };

export function getCostHistogramTotals(data: CostHistogramResponse | null, selectedModel: string): CostTotals {
	if (!data?.buckets) {
		return ZERO_TOTALS;
	}

	return data.buckets.reduce<CostTotals>(
		(acc, bucket) => {
			acc.totalCost += selectedModel === "all" ? bucket.total_cost || 0 : bucket.by_model?.[selectedModel] || 0;
			acc.totalSavings +=
				selectedModel === "all" ? bucket.cache_savings || 0 : bucket.by_model_cache_savings?.[selectedModel] || 0;
			return acc;
		},
		{ ...ZERO_TOTALS },
	);
}

export function getCostHistogramTotalsFromResponses(
	responses: Array<CostHistogramResponse | null | undefined>,
	selectedModel: string,
): CostTotals {
	return responses.reduce<CostTotals>(
		(acc, response) => {
			const totals = getCostHistogramTotals(response ?? null, selectedModel);
			acc.totalCost += totals.totalCost;
			acc.totalSavings += totals.totalSavings;
			return acc;
		},
		{ ...ZERO_TOTALS },
	);
}

export function getProviderCostHistogramTotals(
	data: ProviderCostHistogramResponse | null,
	selectedProvider: string,
): CostTotals {
	if (!data?.buckets) {
		return ZERO_TOTALS;
	}

	return data.buckets.reduce<CostTotals>(
		(acc, bucket) => {
			acc.totalCost += selectedProvider === "all" ? bucket.total_cost || 0 : bucket.by_provider?.[selectedProvider] || 0;
			acc.totalSavings +=
				selectedProvider === "all"
					? bucket.cache_savings || 0
					: bucket.by_provider_cache_savings?.[selectedProvider] || 0;
			return acc;
		},
		{ ...ZERO_TOTALS },
	);
}

export function getProviderCostHistogramTotalsFromResponses(
	responses: Array<ProviderCostHistogramResponse | null | undefined>,
	selectedProvider: string,
): CostTotals {
	return responses.reduce<CostTotals>(
		(acc, response) => {
			const totals = getProviderCostHistogramTotals(response ?? null, selectedProvider);
			acc.totalCost += totals.totalCost;
			acc.totalSavings += totals.totalSavings;
			return acc;
		},
		{ ...ZERO_TOTALS },
	);
}

export function getMCPCostHistogramTotals(data: MCPCostHistogramResponse | null): CostTotals {
	if (!data?.buckets) {
		return ZERO_TOTALS;
	}

	return data.buckets.reduce<CostTotals>(
		(acc, bucket) => {
			acc.totalCost += bucket.total_cost || 0;
			return acc;
		},
		{ ...ZERO_TOTALS },
	);
}
