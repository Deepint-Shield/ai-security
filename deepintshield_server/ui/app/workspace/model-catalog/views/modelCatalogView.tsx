"use client";

import { useGetModelsQuery, useGetProvidersQuery, useLazyGetLogsStatsQuery, useLazyGetLogsModelHistogramQuery } from "@/lib/store";
import { ProviderNames } from "@/lib/constants/logs";
import { KnownProvider } from "@/lib/types/config";
import { LogStats } from "@/lib/types/logs";
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib";
import { useEffect, useMemo, useState } from "react";
import { DateRange } from "react-day-picker";
import ModelCatalogTable, { ModelCatalogRow } from "./modelCatalogTable";
import { ModelCatalogEmptyState } from "./modelCatalogEmptyState";
import FullPageLoader from "@/components/fullPageLoader";
import { NoPermissionView } from "@/components/noPermissionView";

// Time-range presets - same shape Analytics uses so the picker UI is
// 1:1 between the two pages. "24h" matches the legacy hard-coded window
// this page shipped with, so existing dashboards stay anchored on first load.
const TIME_PERIODS = [
	{ label: "Last hour", value: "1h" },
	{ label: "Last 6 hours", value: "6h" },
	{ label: "Last 24 hours", value: "24h" },
	{ label: "Last 7 days", value: "7d" },
	{ label: "Last 30 days", value: "30d" },
];

// Translate a preset string into a concrete DateRange. The picker can also
// hand us an arbitrary {from,to} pair when the operator picks "Custom" -
// we treat that as the source of truth (`predefinedPeriod` clears).
function getTimeRangeFromPeriod(period: string): DateRange {
	const now = new Date();
	const from = new Date(now);
	switch (period) {
		case "1h":
			from.setHours(now.getHours() - 1);
			break;
		case "6h":
			from.setHours(now.getHours() - 6);
			break;
		case "7d":
			from.setDate(now.getDate() - 7);
			break;
		case "30d":
			from.setDate(now.getDate() - 30);
			break;
		case "24h":
		default:
			from.setHours(now.getHours() - 24);
			break;
	}
	return { from, to: now };
}

export default function ModelCatalogView() {
	const hasAccess = useRbac(RbacResource.ModelProvider, RbacOperation.View);

	const [providerFilter, setProviderFilter] = useState("");
	const [statsMap, setStatsMap] = useState<Map<string, LogStats>>(new Map());
	const [modelsUsedMap, setModelsUsedMap] = useState<Map<string, string[]>>(new Map());
	const [isLoadingModels, setIsLoadingModels] = useState(true);

	// Date-range state mirrors Analytics: a predefined-period string drives
	// the chip row, while `dateRange` is the concrete window every query
	// (stats + per-provider stats + models histogram) reads off.
	const [predefinedPeriod, setPredefinedPeriod] = useState<string>("24h");
	const [dateRange, setDateRange] = useState<DateRange>(() => getTimeRangeFromPeriod("24h"));

	const { data: providers, isLoading: isLoadingProviders, error: providersError, refetch: refetchProviders } = useGetProvidersQuery(undefined, { skip: !hasAccess });
	const { data: modelsData } = useGetModelsQuery({ unfiltered: true }, { skip: !hasAccess });

	// Global stats for summary cards (lazy so we get fresh timestamps each refetch)
	const [triggerGlobalStats, { data: globalStats }] = useLazyGetLogsStatsQuery();

	// Per-provider traffic stats (lazy, fired when providers load OR range changes)
	const [triggerStats] = useLazyGetLogsStatsQuery();
	const [triggerModelHistogram] = useLazyGetLogsModelHistogramQuery();

	// Serialise the picked range to ISO so each effect depends on a stable
	// string value (Date objects re-create on every render and would spam refetches).
	const rangeFromISO = useMemo(() => dateRange?.from?.toISOString() ?? "", [dateRange]);
	const rangeToISO = useMemo(() => dateRange?.to?.toISOString() ?? "", [dateRange]);

	useEffect(() => {
		if (!hasAccess || !rangeFromISO || !rangeToISO) return;
		triggerGlobalStats({ filters: { start_time: rangeFromISO, end_time: rangeToISO } });
	}, [hasAccess, rangeFromISO, rangeToISO, triggerGlobalStats]);

	useEffect(() => {
		if (!providers || providers.length === 0) return;
		if (!rangeFromISO || !rangeToISO) return;
		let cancelled = false;

		Promise.all(
			providers.map((p) =>
				triggerStats({ filters: { providers: [p.name], start_time: rangeFromISO, end_time: rangeToISO } })
					.unwrap()
					.then((stats) => [p.name, stats] as const)
					.catch(() => [p.name, { total_requests: 0, success_rate: 0, average_latency: 0, total_tokens: 0, total_cost: 0 }] as const),
			),
		).then((results) => {
			if (!cancelled) setStatsMap(new Map(results));
		});
		return () => { cancelled = true; };
	}, [providers, rangeFromISO, rangeToISO, triggerStats]);

	// Per-provider models used in the picked window. Previously hardcoded to
	// the last 30 days regardless of the range - now follows the picker so a
	// "Last hour" view shows only models that actually ran in the last hour.
	useEffect(() => {
		if (!providers || providers.length === 0) return;
		if (!rangeFromISO || !rangeToISO) return;
		let cancelled = false;
		setIsLoadingModels(true);

		Promise.all(
			providers.map((p) =>
				triggerModelHistogram({ filters: { providers: [p.name], start_time: rangeFromISO, end_time: rangeToISO } })
					.unwrap()
					.then((data): [string, string[]] => [p.name, data.models ?? []])
					.catch((): [string, string[]] => [p.name, []]),
			),
		).then((results) => {
			if (!cancelled) {
				setModelsUsedMap(new Map(results));
				setIsLoadingModels(false);
			}
		});
		return () => { cancelled = true; };
	}, [providers, rangeFromISO, rangeToISO, triggerModelHistogram]);

	const handlePredefinedPeriodChange = (period: string | undefined) => {
		if (!period) {
			setPredefinedPeriod("");
			return;
		}
		setPredefinedPeriod(period);
		setDateRange(getTimeRangeFromPeriod(period));
	};

	const handleDateTimeUpdate = (nextRange: DateRange) => {
		setPredefinedPeriod("");
		setDateRange(nextRange);
	};

	// Build table rows
	const rows: ModelCatalogRow[] = useMemo(() => {
		if (!providers) return [];

		return providers.map((p) => {
			const isCustom = !ProviderNames.includes(p.name as KnownProvider);
			const modelsUsed = modelsUsedMap.get(p.name) ?? [];

			const providerStats = statsMap.get(p.name);
			const totalTraffic24h = providerStats?.total_requests ?? 0;
			const totalCost24h = providerStats?.total_cost ?? 0;

			return {
				providerName: p.name,
				isCustom,
				baseProviderType: p.custom_provider_config?.base_provider_type,
				modelsUsed,
				totalTraffic24h,
				totalCost24h,
			};
		});
	}, [providers, statsMap, modelsUsedMap]);

	// Filter rows by provider
	const filteredRows = useMemo(() => {
		if (!providerFilter) return rows;
		return rows.filter((r) => r.providerName === providerFilter);
	}, [rows, providerFilter]);

	if (isLoadingProviders) {
		return <FullPageLoader />;
	}

	if (!hasAccess) {
		return <NoPermissionView entity="model catalog" />;
	}

	if (providersError) {
		return (
			<div className="flex h-full flex-col items-center justify-center gap-4 text-center">
				<p className="text-muted-foreground text-sm">Failed to load providers</p>
				<button type="button" data-testid="model-catalog-retry-btn" onClick={refetchProviders} className="text-sm underline">
					Retry
				</button>
			</div>
		);
	}

	if (!providers || providers.length === 0) {
		return <ModelCatalogEmptyState />;
	}

	return (
		<div className="workspace-page-shell">
			<ModelCatalogTable
				rows={filteredRows}
				providers={(providers ?? []).map((p) => p.name)}
				providerFilter={providerFilter}
				onProviderFilterChange={setProviderFilter}
				totalProviders={(providers ?? []).length}
				totalModels={modelsData?.total ?? 0}
				totalRequests={globalStats?.total_requests ?? 0}
				totalCost={globalStats?.total_cost ?? 0}
				isLoadingModels={isLoadingModels}
				dateRange={dateRange}
				predefinedPeriod={predefinedPeriod}
				timePeriods={TIME_PERIODS}
				onDateTimeUpdate={handleDateTimeUpdate}
				onPredefinedPeriodChange={handlePredefinedPeriodChange}
			/>
		</div>
	);
}
