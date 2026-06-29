import type { Team, VirtualKey } from "@/lib/types/governance";
import type {
	LogFilters,
	ProviderCostHistogramBucket,
	ProviderCostHistogramResponse,
	ProviderLatencyHistogramBucket,
	ProviderLatencyHistogramResponse,
	ProviderLatencyStats,
	ProviderTokenHistogramBucket,
	ProviderTokenHistogramResponse,
	ProviderTokenStats,
} from "@/lib/types/logs";
import { formatTimestamp, getTeamColor } from "../utils/chartUtils";
import type { GovernanceTimeSeriesDatum, GovernanceTimeSeriesSeries } from "./charts/governanceTimeSeriesChart";

export const ALL_TEAMS_VALUE = "all";

export interface SyntheticTimeBucket {
	timestamp: string;
	index: number;
	formattedTime: string;
}

export interface TeamComparisonScope {
	teamId: string;
	teamName: string;
	filters: LogFilters;
}

export function buildTeamVirtualKeyMap(teams: Team[], virtualKeys: VirtualKey[]): Map<string, string[]> {
	const teamVirtualKeyMap = new Map<string, string[]>();

	for (const team of teams) {
		teamVirtualKeyMap.set(team.id, []);
	}

	for (const virtualKey of virtualKeys) {
		if (!virtualKey.team_id) continue;
		const currentTeamKeys = teamVirtualKeyMap.get(virtualKey.team_id) || [];
		currentTeamKeys.push(virtualKey.id);
		teamVirtualKeyMap.set(virtualKey.team_id, currentTeamKeys);
	}

	return teamVirtualKeyMap;
}

export function buildTeamScopedFilters(
	filters: LogFilters,
	selectedTeamId: string,
	teamVirtualKeyMap: Map<string, string[]>,
): { filters: LogFilters; hasData: boolean } {
	if (selectedTeamId === ALL_TEAMS_VALUE) {
		return { filters, hasData: true };
	}

	const teamVirtualKeyIds = teamVirtualKeyMap.get(selectedTeamId) || [];
	if (teamVirtualKeyIds.length === 0) {
		return { filters, hasData: false };
	}

	const scopedVirtualKeyIds = filters.virtual_key_ids?.length
		? filters.virtual_key_ids.filter((virtualKeyId) => teamVirtualKeyIds.includes(virtualKeyId))
		: teamVirtualKeyIds;

	if (scopedVirtualKeyIds.length === 0) {
		return { filters, hasData: false };
	}

	return {
		filters: {
			...filters,
			virtual_key_ids: scopedVirtualKeyIds,
		},
		hasData: true,
	};
}

export function buildTeamComparisonScopes(
	filters: LogFilters,
	teams: Team[],
	teamVirtualKeyMap: Map<string, string[]>,
): TeamComparisonScope[] {
	return teams.flatMap((team) => {
		const scoped = buildTeamScopedFilters(filters, team.id, teamVirtualKeyMap);
		if (!scoped.hasData) {
			return [];
		}

		return [
			{
				teamId: team.id,
				teamName: team.name,
				filters: scoped.filters,
			},
		];
	});
}

export function buildTeamComparisonSeries(
	teams: Array<{ teamId: string; teamName: string }>,
): GovernanceTimeSeriesSeries[] {
	return teams.map((team, index) => ({
		key: team.teamId,
		label: team.teamName,
		color: getTeamColor(index),
	}));
}

export function getSyntheticBucketSizeSeconds(startTime: number, endTime: number): number {
	const spanSeconds = Math.max(endTime - startTime, 1);

	if (spanSeconds <= 6 * 60 * 60) return 15 * 60;
	if (spanSeconds <= 24 * 60 * 60) return 60 * 60;
	if (spanSeconds <= 7 * 24 * 60 * 60) return 6 * 60 * 60;
	return 24 * 60 * 60;
}

export function buildSyntheticTimeBuckets(startTime: number, endTime: number, bucketSizeSeconds: number): SyntheticTimeBucket[] {
	if (!startTime || !endTime || endTime <= startTime || bucketSizeSeconds <= 0) {
		return [];
	}

	const bucketSizeMs = bucketSizeSeconds * 1000;
	const minTime = Math.floor((startTime * 1000) / bucketSizeMs) * bucketSizeMs;
	const maxTime = endTime * 1000;
	const buckets: SyntheticTimeBucket[] = [];

	for (let bucketStart = minTime, index = 0; bucketStart <= maxTime; bucketStart += bucketSizeMs, index += 1) {
		const timestamp = new Date(bucketStart).toISOString();
		buckets.push({
			timestamp,
			index,
			formattedTime: formatTimestamp(timestamp, bucketSizeSeconds),
		});
	}

	if (buckets.length === 1) {
		const nextTimestamp = new Date(new Date(buckets[0].timestamp).getTime() + bucketSizeMs).toISOString();
		buckets.push({
			timestamp: nextTimestamp,
			index: 1,
			formattedTime: formatTimestamp(nextTimestamp, bucketSizeSeconds),
		});
	}

	return buckets;
}

export function buildTeamComparisonRows<TBucket extends { timestamp: string }>(
	teamSeries: Array<{ teamId: string }>,
	teamBuckets: Array<{ teamId: string; buckets?: TBucket[] | null }>,
	startTime: number,
	endTime: number,
	bucketSizeSeconds?: number | null,
	getValue?: (bucket: TBucket) => number,
): GovernanceTimeSeriesDatum[] {
	const resolvedBucketSizeSeconds = bucketSizeSeconds ?? getSyntheticBucketSizeSeconds(startTime, endTime);
	const referenceBuckets = teamBuckets.find((entry) => (entry.buckets?.length ?? 0) > 0)?.buckets;

	const rows: GovernanceTimeSeriesDatum[] =
		referenceBuckets && referenceBuckets.length > 0
			? referenceBuckets.map((bucket, index) => {
					const row: GovernanceTimeSeriesDatum = {
						timestamp: bucket.timestamp,
						index,
						formattedTime: formatTimestamp(bucket.timestamp, resolvedBucketSizeSeconds),
					};

					for (const series of teamSeries) {
						row[series.teamId] = 0;
					}

					return row;
				})
			: buildSyntheticTimeBuckets(startTime, endTime, resolvedBucketSizeSeconds).map((bucket) => {
					const row: GovernanceTimeSeriesDatum = {
						timestamp: bucket.timestamp,
						index: bucket.index,
						formattedTime: bucket.formattedTime,
					};

					for (const series of teamSeries) {
						row[series.teamId] = 0;
					}

					return row;
				});

	if (rows.length === 0) {
		return [];
	}

	const rowsByTimestamp = new Map(rows.map((row) => [row.timestamp, row]));

	for (const entry of teamBuckets) {
		for (const bucket of entry.buckets ?? []) {
			const row = rowsByTimestamp.get(bucket.timestamp);
			if (!row) {
				continue;
			}

			const rawValue = getValue ? getValue(bucket) : Number.NaN;
			row[entry.teamId] = Number.isFinite(rawValue) ? rawValue : 0;
		}
	}

	return rows;
}

// ── Provider data merge utilities ────────────────────────────────────────────
// Merge multiple team-scoped provider responses into one so the standard
// per-provider chart components can render a per-provider color breakdown
// even in the "All Teams" view.

export function mergeProviderCostResponses(
	responses: Array<ProviderCostHistogramResponse | null | undefined>,
): ProviderCostHistogramResponse | null {
	const valid = responses.filter((r): r is ProviderCostHistogramResponse => !!r?.buckets?.length);
	if (valid.length === 0) return null;

	const providers = [...new Set(valid.flatMap((r) => r.providers))].sort();
	const bucketSize = valid[0].bucket_size_seconds;

	// Merge by timestamp
	const merged = new Map<string, ProviderCostHistogramBucket>();
	for (const resp of valid) {
		for (const bucket of resp.buckets) {
			const existing = merged.get(bucket.timestamp);
			if (!existing) {
				merged.set(bucket.timestamp, {
					timestamp: bucket.timestamp,
					total_cost: bucket.total_cost,
					cache_savings: bucket.cache_savings,
					by_provider: { ...bucket.by_provider },
					by_provider_cache_savings: { ...bucket.by_provider_cache_savings },
				});
			} else {
				existing.total_cost += bucket.total_cost;
				existing.cache_savings += bucket.cache_savings;
				for (const [p, v] of Object.entries(bucket.by_provider ?? {})) {
					existing.by_provider[p] = (existing.by_provider[p] ?? 0) + v;
				}
				for (const [p, v] of Object.entries(bucket.by_provider_cache_savings ?? {})) {
					existing.by_provider_cache_savings[p] = (existing.by_provider_cache_savings[p] ?? 0) + v;
				}
			}
		}
	}

	return {
		buckets: [...merged.values()].sort((a, b) => a.timestamp.localeCompare(b.timestamp)),
		bucket_size_seconds: bucketSize,
		providers,
	};
}

export function mergeProviderTokenResponses(
	responses: Array<ProviderTokenHistogramResponse | null | undefined>,
): ProviderTokenHistogramResponse | null {
	const valid = responses.filter((r): r is ProviderTokenHistogramResponse => !!r?.buckets?.length);
	if (valid.length === 0) return null;

	const providers = [...new Set(valid.flatMap((r) => r.providers))].sort();
	const bucketSize = valid[0].bucket_size_seconds;

	const merged = new Map<string, ProviderTokenHistogramBucket>();
	for (const resp of valid) {
		for (const bucket of resp.buckets) {
			const existing = merged.get(bucket.timestamp);
			if (!existing) {
				const byProvider: Record<string, ProviderTokenStats> = {};
				for (const [p, stats] of Object.entries(bucket.by_provider ?? {})) {
					byProvider[p] = { ...stats };
				}
				merged.set(bucket.timestamp, { timestamp: bucket.timestamp, by_provider: byProvider });
			} else {
				for (const [p, stats] of Object.entries(bucket.by_provider ?? {})) {
					const e = existing.by_provider[p];
					if (e) {
						e.prompt_tokens += stats.prompt_tokens;
						e.completion_tokens += stats.completion_tokens;
						e.total_tokens += stats.total_tokens;
					} else {
						existing.by_provider[p] = { ...stats };
					}
				}
			}
		}
	}

	return {
		buckets: [...merged.values()].sort((a, b) => a.timestamp.localeCompare(b.timestamp)),
		bucket_size_seconds: bucketSize,
		providers,
	};
}

export function mergeProviderLatencyResponses(
	responses: Array<ProviderLatencyHistogramResponse | null | undefined>,
): ProviderLatencyHistogramResponse | null {
	const valid = responses.filter((r): r is ProviderLatencyHistogramResponse => !!r?.buckets?.length);
	if (valid.length === 0) return null;

	const providers = [...new Set(valid.flatMap((r) => r.providers))].sort();
	const bucketSize = valid[0].bucket_size_seconds;

	const merged = new Map<string, ProviderLatencyHistogramBucket>();
	for (const resp of valid) {
		for (const bucket of resp.buckets) {
			const existing = merged.get(bucket.timestamp);
			if (!existing) {
				const byProvider: Record<string, ProviderLatencyStats> = {};
				for (const [p, stats] of Object.entries(bucket.by_provider ?? {})) {
					byProvider[p] = { ...stats };
				}
				merged.set(bucket.timestamp, { timestamp: bucket.timestamp, by_provider: byProvider });
			} else {
				for (const [p, stats] of Object.entries(bucket.by_provider ?? {})) {
					const e = existing.by_provider[p];
					if (e) {
						// Weighted average for latency metrics
						const totalReq = e.total_requests + stats.total_requests;
						if (totalReq > 0) {
							e.avg_latency = (e.avg_latency * e.total_requests + stats.avg_latency * stats.total_requests) / totalReq;
							e.p90_latency = Math.max(e.p90_latency, stats.p90_latency);
							e.p95_latency = Math.max(e.p95_latency, stats.p95_latency);
							e.p99_latency = Math.max(e.p99_latency, stats.p99_latency);
						}
						e.total_requests = totalReq;
					} else {
						existing.by_provider[p] = { ...stats };
					}
				}
			}
		}
	}

	return {
		buckets: [...merged.values()].sort((a, b) => a.timestamp.localeCompare(b.timestamp)),
		bucket_size_seconds: bucketSize,
		providers,
	};
}
