"use client";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useGetKeyHealthQuery, useGetVirtualKeysQuery } from "@/lib/store";
import { useAppSelector } from "@/lib/store/hooks";
import { selectActiveWorkspaceId } from "@/lib/store/slices/activeScopeSlice";
import type { KeyHealthStatus, KeySelectionStrategy, VirtualKey } from "@/lib/types/governance";
import {
	Activity,
	AlertTriangle,
	CheckCircle2,
	HeartPulse,
	KeyRound,
	Scale,
	Settings,
	XCircle,
} from "lucide-react";
import { useState } from "react";
import LoadBalancerConfigSheet from "./loadBalancerConfigSheet";

const strategyLabels: Record<KeySelectionStrategy, string> = {
	weighted_random: "Weighted Random",
	round_robin: "Round Robin",
	least_load: "Least Load",
};

function getCircuitBadge(state: KeyHealthStatus["circuit_state"]) {
	switch (state) {
		case "closed":
			return (
				<Badge variant="outline" className="border-green-500/30 bg-green-500/10 text-green-600">
					<CheckCircle2 className="mr-1 h-3 w-3" />
					Healthy
				</Badge>
			);
		case "half_open":
			return (
				<Badge variant="outline" className="border-yellow-500/30 bg-yellow-500/10 text-yellow-600">
					<AlertTriangle className="mr-1 h-3 w-3" />
					Recovering
				</Badge>
			);
		case "open":
			return (
				<Badge variant="outline" className="border-red-500/30 bg-red-500/10 text-red-600">
					<XCircle className="mr-1 h-3 w-3" />
					Circuit Open
				</Badge>
			);
	}
}

function getVKStrategySummary(vk: VirtualKey): string {
	if (!vk.provider_configs || vk.provider_configs.length === 0) return "No providers";
	const strategies = new Set(
		vk.provider_configs.map((pc) => pc.key_selection_strategy || "weighted_random"),
	);
	if (strategies.size === 1) {
		const strategy = strategies.values().next().value as KeySelectionStrategy;
		return strategyLabels[strategy];
	}
	return "Mixed";
}

function getVKKeyCount(vk: VirtualKey): number {
	if (!vk.provider_configs) return 0;
	return vk.provider_configs.reduce((sum, pc) => sum + (pc.keys?.length || 0), 0);
}

function getVKProviders(vk: VirtualKey): string[] {
	if (!vk.provider_configs) return [];
	return vk.provider_configs.map((pc) => pc.provider);
}

export default function LoadBalancerView() {
	const activeWorkspaceId = useAppSelector(selectActiveWorkspaceId);
	// Server already supports workspace scoping on virtual keys - pass the
	// active workspace so the page never surfaces VKs from a sibling
	// workspace. When no workspace is selected we leave the param off and
	// fall through to the org-scoped default.
	const { data: vkData, isLoading: vkLoading } = useGetVirtualKeysQuery({
		workspace_id: activeWorkspaceId || undefined,
	});
	const { data: healthData } = useGetKeyHealthQuery(undefined, {
		pollingInterval: 10000,
	});
	const [selectedVK, setSelectedVK] = useState<VirtualKey | null>(null);

	const virtualKeys = vkData?.virtual_keys || [];

	const loadBalancerVKs = virtualKeys.filter(
		(vk) => vk.provider_configs && vk.provider_configs.length > 0,
	);

	// /governance/key-health returns every tracked key in the gateway's
	// in-memory load tracker - no workspace filter on the server. Build the
	// set of key ids that belong to this workspace's VKs and project the
	// health payload through it so the charts + cards stay strictly scoped.
	const workspaceKeyIds = new Set<string>();
	loadBalancerVKs.forEach((vk) => {
		vk.provider_configs?.forEach((pc) => {
			pc.keys?.forEach((k) => {
				if (k.key_id) workspaceKeyIds.add(k.key_id);
			});
		});
	});
	const keyHealth = (healthData?.keys || []).filter((k) => workspaceKeyIds.has(k.key_id));

	const healthyCount = keyHealth.filter((k) => k.circuit_state === "closed").length;
	const degradedCount = keyHealth.filter((k) => k.circuit_state === "half_open").length;
	const openCount = keyHealth.filter((k) => k.circuit_state === "open").length;
	const totalKeys = loadBalancerVKs.reduce((sum, vk) => sum + getVKKeyCount(vk), 0);

	return (
		<div className="flex flex-col gap-6 p-4">
			{/* Header */}
			<header className="flex items-end justify-between gap-4">
				<div className="space-y-1.5">
					<div className="text-muted-foreground text-[11px] font-semibold uppercase tracking-[0.18em]">
						Governance Hub
					</div>
					<div className="flex items-center gap-2.5">
						<span className="inline-flex h-9 w-9 items-center justify-center rounded-xl bg-primary/12 text-primary shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
							<Scale className="h-4.5 w-4.5" />
						</span>
						<div>
							<h1 className="text-2xl font-semibold tracking-tight leading-none">LLM Load Balancer</h1>
							{/* <p className="text-muted-foreground mt-1 max-w-3xl text-sm">
								Distribute requests across multiple API keys using configurable load balancing strategies.
								Configure per-provider strategies on each{" "}
								<span className="text-foreground font-medium">virtual key</span>.
							</p> */}
						</div>
					</div>
				</div>
			</header>

			{/* Summary tiles */}
			{(loadBalancerVKs.length > 0 || keyHealth.length > 0) && (
				<div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
					<SummaryTile
						icon={<KeyRound className="h-4 w-4" />}
						label="Virtual Keys"
						value={loadBalancerVKs.length}
						accent="primary"
					/>
					<SummaryTile
						icon={<Activity className="h-4 w-4" />}
						label="Total Keys"
						value={totalKeys}
						accent="primary"
					/>
					<SummaryTile
						icon={<CheckCircle2 className="h-4 w-4" />}
						label="Healthy"
						value={healthyCount}
						accent="green"
					/>
					<SummaryTile
						icon={openCount > 0 ? <XCircle className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4" />}
						label={openCount > 0 ? "Circuit Open" : "Recovering"}
						value={openCount > 0 ? openCount : degradedCount}
						accent={openCount > 0 ? "red" : "amber"}
					/>
				</div>
			)}

			{/* Routing / Rate-Limit / Throttling charts live on
			    Analytics → Overview → LLM Load Balancer (this page stays
			    operational: keys, health, and config). */}

			{/* Key Health Overview */}
			{keyHealth.length > 0 && (
				<Card>
					<CardHeader className="pb-3">
						<CardTitle className="flex items-center gap-2 text-base">
							<HeartPulse className="h-4 w-4 text-primary" />
							Key Health
							{/* <span className="text-muted-foreground ml-1 text-xs font-normal">
								· refreshed every 10s
							</span> */}
						</CardTitle>
					</CardHeader>
					<CardContent>
						<div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
							{keyHealth.map((key) => (
								<div
									key={key.key_id}
									className="group relative overflow-hidden rounded-xl border border-border/60 bg-card/60 p-3 transition-colors hover:border-border hover:bg-card"
								>
									<div className="mb-2 flex items-start justify-between gap-2">
										<div className="min-w-0 flex-1">
											<p className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">
												Key
											</p>
											<p className="mt-0.5 truncate font-mono text-xs font-medium" title={key.key_id}>
												{key.key_id}
											</p>
										</div>
										{getCircuitBadge(key.circuit_state)}
									</div>
									<div className="grid grid-cols-2 gap-x-3 gap-y-2">
										<MetricCell label="Active" value={key.active_requests.toLocaleString()} />
										<MetricCell label="Total" value={key.total_requests.toLocaleString()} />
										<MetricCell label="Tokens" value={key.total_tokens.toLocaleString()} />
										<MetricCell
											label="Errors"
											value={key.error_count.toLocaleString()}
											tone={key.error_count > 0 ? "danger" : undefined}
										/>
									</div>
									{key.last_error && (
										<p className="text-muted-foreground mt-2.5 truncate text-[11px]">
											Last error: {new Date(key.last_error).toLocaleString()}
										</p>
									)}
								</div>
							))}
						</div>
					</CardContent>
				</Card>
			)}

			{/* Virtual Keys */}
			<Card>
				<CardHeader className="pb-2">
					<CardTitle className="flex items-center gap-2 text-base">
						<KeyRound className="h-4 w-4 text-primary" />
						Virtual Keys
						<span className="text-muted-foreground ml-1 text-xs font-normal">
							{loadBalancerVKs.length} configured
						</span>
					</CardTitle>
				</CardHeader>
				<CardContent className="px-0">
					{vkLoading ? (
						<div className="text-muted-foreground flex items-center justify-center py-12 text-sm">
							Loading virtual keys…
						</div>
					) : loadBalancerVKs.length === 0 ? (
						<div className="px-6 py-12">
							<div className="mx-auto flex max-w-md flex-col items-center text-center">
								<span className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-primary/10 text-primary shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
									<Activity className="h-5 w-5" strokeWidth={1.75} />
								</span>
								<h4 className="text-base font-semibold tracking-tight">
									No load balancing configured
								</h4>
								<p className="text-muted-foreground mt-1.5 text-sm leading-relaxed">
									Add provider configurations with multiple keys to your virtual keys to enable load
									balancing. You can configure strategies from the{" "}
									<span className="text-foreground font-medium">Virtual Keys</span> page.
								</p>
							</div>
						</div>
					) : (
						<div className="divide-border/40 divide-y">
							<Table>
								<TableHeader>
									<TableRow className="hover:bg-transparent">
										<TableHead className="px-6 text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
											Virtual Key
										</TableHead>
										<TableHead className="text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
											Providers
										</TableHead>
										<TableHead className="text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
											Keys
										</TableHead>
										<TableHead className="text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
											Strategy
										</TableHead>
										<TableHead className="text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
											Status
										</TableHead>
										<TableHead className="w-[80px]" />
									</TableRow>
								</TableHeader>
								<TableBody>
									{loadBalancerVKs.map((vk) => (
										<TableRow
											key={vk.id}
											className="group cursor-pointer transition-colors hover:bg-muted/40"
											onClick={() => setSelectedVK(vk)}
										>
											<TableCell className="px-6">
												<div className="flex items-center gap-3">
													<span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[linear-gradient(135deg,rgba(34,211,196,0.18),rgba(96,169,255,0.14))] text-primary shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
														<span className="text-[11px] font-semibold">
															{vk.name.slice(0, 2).toUpperCase()}
														</span>
													</span>
													<div className="min-w-0">
														<p className="truncate text-sm font-medium group-hover:underline">
															{vk.name}
														</p>
														{vk.description && (
															<p className="text-muted-foreground line-clamp-1 text-[11px]">
																{vk.description}
															</p>
														)}
													</div>
												</div>
											</TableCell>
											<TableCell>
												<div className="flex flex-wrap gap-1">
													{getVKProviders(vk).map((provider) => (
														<Badge
															key={provider}
															variant="secondary"
															className="text-[10px] font-medium uppercase tracking-wide"
														>
															{provider}
														</Badge>
													))}
												</div>
											</TableCell>
											<TableCell>
												<span className="text-sm font-medium tabular-nums">
													{getVKKeyCount(vk)}
												</span>
											</TableCell>
											<TableCell>
												<Badge variant="outline" className="font-medium">
													{getVKStrategySummary(vk)}
												</Badge>
											</TableCell>
											<TableCell>
												{vk.is_active ? (
													<Badge
														variant="outline"
														className="border-green-500/30 bg-green-500/10 text-green-600"
													>
														<span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-green-500" />
														Active
													</Badge>
												) : (
													<Badge
														variant="outline"
														className="border-gray-500/30 bg-gray-500/10 text-gray-500"
													>
														<span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-gray-400" />
														Inactive
													</Badge>
												)}
											</TableCell>
											<TableCell>
												<Button
													variant="ghost"
													size="icon"
													className="h-8 w-8 opacity-60 transition-opacity group-hover:opacity-100"
													onClick={(e) => {
														e.stopPropagation();
														setSelectedVK(vk);
													}}
													aria-label={`Configure ${vk.name}`}
												>
													<Settings className="h-4 w-4" />
												</Button>
											</TableCell>
										</TableRow>
									))}
								</TableBody>
							</Table>
						</div>
					)}
				</CardContent>
			</Card>

			{/* Config Sheet */}
			{selectedVK && (
				<LoadBalancerConfigSheet
					virtualKey={selectedVK}
					open={!!selectedVK}
					onClose={() => setSelectedVK(null)}
				/>
			)}
		</div>
	);
}

/* ─────────────────────────── helpers ─────────────────────────── */

type SummaryAccent = "primary" | "green" | "amber" | "red";

const accentClasses: Record<SummaryAccent, { ring: string; icon: string; value: string }> = {
	primary: {
		ring: "border-border/60",
		icon: "bg-primary/12 text-primary",
		value: "text-foreground",
	},
	green: {
		ring: "border-green-500/30",
		icon: "bg-green-500/12 text-green-600",
		value: "text-green-600",
	},
	amber: {
		ring: "border-amber-500/30",
		icon: "bg-amber-500/12 text-amber-600",
		value: "text-amber-600",
	},
	red: {
		ring: "border-red-500/30",
		icon: "bg-red-500/12 text-red-600",
		value: "text-red-600",
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
	value: number;
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
				<p className={`text-xl font-semibold tabular-nums leading-none mt-1 ${cls.value}`}>
					{value.toLocaleString()}
				</p>
			</div>
		</div>
	);
}

function MetricCell({
	label,
	value,
	tone,
}: {
	label: string;
	value: string;
	tone?: "danger";
}) {
	return (
		<div>
			<p className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.14em]">
				{label}
			</p>
			<p
				className={`mt-0.5 text-sm font-medium tabular-nums ${
					tone === "danger" ? "text-red-600" : "text-foreground"
				}`}
			>
				{value}
			</p>
		</div>
	);
}
