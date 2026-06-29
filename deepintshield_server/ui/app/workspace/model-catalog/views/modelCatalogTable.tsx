"use client";

import { Badge } from "@/components/ui/badge";
import { DateTimePickerWithRange } from "@/components/ui/datePickerWithRange";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { ProviderIconType, RenderProviderIcon } from "@/lib/constants/icons";
import { ProviderLabels } from "@/lib/constants/logs";
import { Activity, Boxes, Coins, DollarSign, Info, LayoutGrid, Network, Sparkles } from "lucide-react";
import { DateRange } from "react-day-picker";

function formatCost(dollars: number) {
	return `$${dollars.toFixed(4)}`;
}

export interface ModelCatalogRow {
	providerName: string;
	isCustom: boolean;
	baseProviderType?: string;
	modelsUsed: string[];
	totalTraffic24h: number;
	totalCost24h: number;
}

interface ModelCatalogTableProps {
	rows: ModelCatalogRow[];
	providers: string[];
	providerFilter: string;
	onProviderFilterChange: (value: string) => void;
	totalProviders: number;
	totalModels: number;
	// Summary metrics for the picked time window. Renamed from
	// totalRequests24h / totalCost24h to drop the hard-coded "24h" - the
	// label below now reflects whichever range the picker selected.
	totalRequests: number;
	totalCost: number;
	isLoadingModels: boolean;
	// Date-range picker plumbing. Same contract as Analytics so the two
	// pages share the picker component verbatim.
	dateRange: DateRange;
	predefinedPeriod: string;
	timePeriods: { label: string; value: string }[];
	onDateTimeUpdate: (next: DateRange) => void;
	onPredefinedPeriodChange: (value: string | undefined) => void;
}

// Friendly label for the active range. Used both in the summary tile copy
// ("Total Requests (last 24 hours)") and the per-card tooltip so the
// operator never has to guess what window they're looking at.
function rangeLabel(predefinedPeriod: string, timePeriods: { label: string; value: string }[]) {
	if (predefinedPeriod) {
		const hit = timePeriods.find((p) => p.value === predefinedPeriod);
		if (hit) return hit.label.toLowerCase();
	}
	return "custom range";
}

export default function ModelCatalogTable({
	rows,
	providers,
	providerFilter,
	onProviderFilterChange,
	totalProviders,
	totalModels,
	totalRequests,
	totalCost,
	isLoadingModels,
	dateRange,
	predefinedPeriod,
	timePeriods,
	onDateTimeUpdate,
	onPredefinedPeriodChange,
}: ModelCatalogTableProps) {
	const label = rangeLabel(predefinedPeriod, timePeriods);
	const summaryTiles = [
		{
			label: "Total Providers",
			value: totalProviders.toLocaleString(),
			icon: <Network className="h-4 w-4" />,
			accent: "primary" as const,
		},
		{
			label: "Total Models",
			value: totalModels.toLocaleString(),
			icon: <Boxes className="h-4 w-4" />,
			accent: "primary" as const,
		},
		{
			label: `Total Requests (${label})`,
			value: totalRequests.toLocaleString(),
			icon: <Activity className="h-4 w-4" />,
			accent: "blue" as const,
		},
		{
			label: `Total Cost (${label})`,
			value: formatCost(totalCost),
			icon: <DollarSign className="h-4 w-4" />,
			accent: "amber" as const,
		},
	];

	return (
		<div className="flex flex-col gap-6 p-4">
			{/* Header */}
			<header className="flex items-end justify-between gap-4">
				<div className="space-y-1.5">
					<div className="text-muted-foreground text-[11px] font-semibold uppercase tracking-[0.18em]">
						Model Hub
					</div>
					<div className="flex items-center gap-2.5">
						<span className="inline-flex h-9 w-9 items-center justify-center rounded-xl bg-primary/12 text-primary shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
							<LayoutGrid className="h-4.5 w-4.5" />
						</span>
						<div>
							<h1 className="text-2xl font-semibold tracking-tight leading-none">Model Catalog</h1>
							{/* <p className="text-muted-foreground mt-1 max-w-3xl text-sm">
								Overview of all configured providers, models, and usage across the workspace.
							</p> */}
						</div>
					</div>
				</div>
			</header>

			{/* Summary Tiles */}
			<div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
				{summaryTiles.map((tile) => (
					<SummaryTile key={tile.label} {...tile} />
				))}
			</div>

			{/* Filters - provider dropdown + date-range picker mirroring the
			    chrome on the Analytics page so both pages share one control
			    set. Wrapped in the same translucent card-ish row Analytics
			    uses so the visual language stays consistent. */}
			<div className="flex flex-wrap items-center justify-end gap-2 rounded-xl border border-border/60 bg-card/70 p-1.5 shadow-[0_1px_2px_rgba(11,42,49,0.04),0_8px_18px_-12px_rgba(11,42,49,0.10)] backdrop-blur-md">
				<Select
					value={providerFilter || "all"}
					onValueChange={(val) => onProviderFilterChange(val === "all" ? "" : val)}
					data-testid="model-catalog-provider-filter"
				>
					<SelectTrigger className="w-[200px]" data-testid="model-catalog-provider-trigger">
						<SelectValue placeholder="All Providers" />
					</SelectTrigger>
					<SelectContent>
						<SelectItem value="all">All Providers</SelectItem>
						{providers.map((p) => (
							<SelectItem key={p} value={p}>
								{ProviderLabels[p as keyof typeof ProviderLabels] || p}
							</SelectItem>
						))}
					</SelectContent>
				</Select>
				<div className="h-6 w-px bg-border/60" />
				<DateTimePickerWithRange
					popupAlignment="end"
					buttonClassName="!w-auto min-w-[180px]"
					dateTime={dateRange}
					preDefinedPeriods={timePeriods}
					predefinedPeriod={predefinedPeriod}
					onDateTimeUpdate={onDateTimeUpdate}
					onPredefinedPeriodChange={onPredefinedPeriodChange}
				/>
			</div>

			{/* Provider Cards Grid */}
			{rows.length === 0 ? (
				<div className="rounded-xl border border-border/60 bg-card/40 px-6 py-16 text-center">
					<span className="mx-auto mb-4 inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-muted text-muted-foreground">
						<LayoutGrid className="h-5 w-5" strokeWidth={1.75} />
					</span>
					<h3 className="text-sm font-semibold">No matching providers found</h3>
					<p className="text-muted-foreground mt-1 text-xs">
						Try clearing the filter to see all configured providers.
					</p>
				</div>
			) : (
				<div className="grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6">
					{rows.map((row) => (
						<ProviderCard key={row.providerName} row={row} isLoadingModels={isLoadingModels} rangeLabel={label} />
					))}
				</div>
			)}
		</div>
	);
}

/* ─────────────────────────── provider card ─────────────────────────── */

function ProviderCard({
	row,
	isLoadingModels,
	rangeLabel,
}: {
	row: ModelCatalogRow;
	isLoadingModels: boolean;
	rangeLabel: string;
}) {
	const providerLabel = row.isCustom
		? row.providerName
		: ProviderLabels[row.providerName as keyof typeof ProviderLabels] || row.providerName;

	const isActive = row.totalTraffic24h > 0;
	const hasCost = row.totalCost24h > 0;

	return (
		<div
			className={`group relative flex aspect-square flex-col overflow-hidden rounded-2xl border bg-card transition-all hover:shadow-[0_10px_28px_-14px_rgba(15,23,42,0.22)] ${
				isActive ? "border-emerald-500/30 hover:border-emerald-500/50" : "border-border/60 hover:border-border"
			}`}
		>
			{/* Top accent stripe - visible when active, fades in on hover when idle */}
			<div
				className={`pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/60 to-transparent transition-opacity ${
					isActive ? "opacity-70" : "opacity-0 group-hover:opacity-60"
				}`}
			/>

			{/* Header */}
			<div className="flex items-center gap-3 px-4 pt-4 pb-3">
				<span className="inline-flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-[linear-gradient(135deg,rgba(34,211,196,0.20),rgba(96,169,255,0.14))] shadow-[inset_0_1px_0_rgba(255,255,255,0.22)]">
					<RenderProviderIcon
						provider={(row.isCustom ? row.baseProviderType : row.providerName) as ProviderIconType}
						size="md"
						className="h-8 w-8 shrink-0"
					/>
				</span>
				<div className="min-w-0 flex-1">
					<div className="flex items-center gap-1.5">
						<h3 className="truncate text-sm font-semibold leading-tight tracking-tight">{providerLabel}</h3>
						<TooltipProvider>
							<Tooltip>
								<TooltipTrigger asChild>
									<span
										className={`ml-auto inline-flex h-2 w-2 shrink-0 rounded-full ${
											isActive
												? "bg-emerald-500 shadow-[0_0_0_3px_rgba(16,185,129,0.20)]"
												: "bg-muted-foreground/30"
										}`}
										aria-label={isActive ? "Active" : "Idle"}
									/>
								</TooltipTrigger>
								<TooltipContent side="top">
									{isActive ? `Active in ${rangeLabel}` : `No traffic in ${rangeLabel}`}
								</TooltipContent>
							</Tooltip>
						</TooltipProvider>
					</div>
					{row.isCustom && (
						<div className="mt-1 flex items-center gap-1.5">
							<Badge variant="secondary" className="text-muted-foreground px-1.5 py-0 text-[9px] font-bold leading-tight">
								CUSTOM
							</Badge>
							{row.baseProviderType && (
								<span className="text-muted-foreground truncate text-[10px]">on {row.baseProviderType}</span>
							)}
						</div>
					)}
				</div>
			</div>

			{/* Models */}
			<div className="flex-1 overflow-hidden px-4 pb-3">
				<div className="mb-1.5 flex items-center gap-1.5">
					<Sparkles className="text-muted-foreground h-3 w-3" />
					<p className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">
						Models
					</p>
					<TooltipProvider>
						<Tooltip>
							<TooltipTrigger data-testid="model-catalog-models-info-trigger">
								<Info className="text-muted-foreground h-3 w-3" />
							</TooltipTrigger>
							<TooltipContent side="bottom">Models used in {rangeLabel}</TooltipContent>
						</Tooltip>
					</TooltipProvider>
				</div>
				{isLoadingModels ? (
					<div className="flex flex-wrap items-center gap-1">
						<Skeleton className="h-4 w-20 rounded-full" />
						<Skeleton className="h-4 w-14 rounded-full" />
					</div>
				) : (
					<ModelsUsedCell models={row.modelsUsed} />
				)}
			</div>

			{/* Footer stats */}
			<div className="mt-auto grid grid-cols-2 divide-x divide-border/60 border-t border-border/60 bg-muted/30">
				<StatBlock
					icon={<Activity className="h-3 w-3" />}
					label="Traffic"
					value={row.totalTraffic24h.toLocaleString()}
					accent={isActive ? "emerald" : undefined}
				/>
				<StatBlock
					icon={<Coins className="h-3 w-3" />}
					label="Cost"
					value={formatCost(row.totalCost24h)}
					accent={hasCost ? "amber" : undefined}
				/>
			</div>
		</div>
	);
}

function StatBlock({
	icon,
	label,
	value,
	accent,
}: {
	icon: React.ReactNode;
	label: string;
	value: string;
	accent?: "emerald" | "amber";
}) {
	const valueColor =
		accent === "emerald"
			? "text-emerald-700 dark:text-emerald-400"
			: accent === "amber"
				? "text-amber-700 dark:text-amber-400"
				: "text-muted-foreground/70";
	return (
		<div className="px-3.5 py-2.5">
			<div className="text-muted-foreground flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.14em]">
				{icon}
				{label}
			</div>
			<p className={`mt-1 truncate font-mono text-[13px] font-semibold tabular-nums ${valueColor}`}>
				{value}
			</p>
		</div>
	);
}

/* ─────────────────────────── summary tile ─────────────────────────── */

type SummaryAccent = "primary" | "blue" | "amber" | "green";

const accentClasses: Record<SummaryAccent, { ring: string; icon: string }> = {
	primary: {
		ring: "border-border/60",
		icon: "bg-primary/12 text-primary",
	},
	blue: {
		ring: "border-border/60",
		icon: "bg-sky-500/12 text-sky-600",
	},
	amber: {
		ring: "border-border/60",
		icon: "bg-amber-500/12 text-amber-600",
	},
	green: {
		ring: "border-border/60",
		icon: "bg-green-500/12 text-green-600",
	},
};

function SummaryTile({
	icon,
	label,
	value,
	accent,
}: {
	icon: React.ReactNode;
	label: string;
	value: string;
	accent: SummaryAccent;
}) {
	const cls = accentClasses[accent];
	return (
		<div
			className={`flex items-center gap-3 rounded-xl border ${cls.ring} bg-card/60 px-4 py-3 transition-colors hover:bg-card`}
		>
			<span
				className={`inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl ${cls.icon} shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]`}
			>
				{icon}
			</span>
			<div className="min-w-0">
				<p className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">
					{label}
				</p>
				<p className="text-foreground mt-1 text-xl font-semibold tabular-nums leading-none">
					{value}
				</p>
			</div>
		</div>
	);
}

/* ─────────────────────────── models cell ─────────────────────────── */

function ModelsUsedCell({ models: rawModels }: { models: string[] }) {
	const models = Array.from(new Set(rawModels.filter(Boolean)));
	if (models.length === 0) {
		return (
			<span className="border-border/60 text-muted-foreground inline-flex items-center rounded-full border border-dashed px-2 py-0.5 text-[10px] italic">
				No activity
			</span>
		);
	}

	const MAX_VISIBLE = 2;
	const visible = models.slice(0, MAX_VISIBLE);
	const remaining = models.length - MAX_VISIBLE;

	return (
		<TooltipProvider>
			<div className="flex flex-wrap items-center gap-1">
				{visible.map((m) => (
					<Badge
						key={m}
						variant="outline"
						className="max-w-full truncate px-1.5 py-0.5 font-mono text-[10px] font-normal leading-tight"
					>
						{m}
					</Badge>
				))}
				{remaining > 0 && (
					<Tooltip>
						<TooltipTrigger data-testid="model-catalog-models-overflow-trigger">
							<Badge variant="outline" className="px-1.5 py-0.5 text-[10px] font-medium leading-tight">
								+{remaining}
							</Badge>
						</TooltipTrigger>
						<TooltipContent side="bottom" className="max-w-xs">
							{models.slice(MAX_VISIBLE).join(", ")}
						</TooltipContent>
					</Tooltip>
				)}
			</div>
		</TooltipProvider>
	);
}
