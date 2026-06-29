/**
 * Routing Rules View
 * Main orchestrator component for routing rules management
 */

"use client";

import { RbacOperation, RbacResource, useRbac } from "@/app/_fallbacks/enterprise/lib/contexts/rbacContext";
import { Button } from "@/components/ui/button";
import { useDebouncedValue } from "@/hooks/useDebounce";
import { useGetRoutingRulesQuery } from "@/lib/store/apis/routingRulesApi";
import { RoutingRule } from "@/lib/types/routingRules";
import { Plus, Route } from "lucide-react";
import { useEffect, useState } from "react";
import { RoutingRuleSheet } from "./routingRuleSheet";
import { RoutingRulesEmptyState } from "./routingRulesEmptyState";
import { RoutingRulesTable } from "./routingRulesTable";

const POLLING_INTERVAL = 5000;
const PAGE_SIZE = 25;

export function RoutingRulesView() {
	const [dialogOpen, setDialogOpen] = useState(false);
	const [editingRule, setEditingRule] = useState<RoutingRule | null>(null);

	const [search, setSearch] = useState("");
	const [offset, setOffset] = useState(0);

	const debouncedSearch = useDebouncedValue(search, 300);

	// Reset to first page when search changes
	useEffect(() => {
		setOffset(0);
	}, [debouncedSearch]);

	// Permissions
	const canCreate = useRbac(RbacResource.RoutingRules, RbacOperation.Create);
	const canDelete = useRbac(RbacResource.RoutingRules, RbacOperation.Delete);

	// API
	const { data: rulesData, isLoading } = useGetRoutingRulesQuery(
		{
			limit: PAGE_SIZE,
			offset,
			search: debouncedSearch || undefined,
		},
		{
			pollingInterval: POLLING_INTERVAL,
			// Revalidate on mount so a hard refresh reflects server truth rather than
			// a stale cross-session cache snapshot (see persistence.ts).
			refetchOnMountOrArgChange: true,
		},
	);

	const rules = rulesData?.rules || [];
	const totalCount = rulesData?.total_count || 0;


	// Snap offset back when total shrinks past current page (e.g. delete last item on last page)
	useEffect(() => {
		if (!rulesData || offset < totalCount) return;
		setOffset(totalCount === 0 ? 0 : Math.floor((totalCount - 1) / PAGE_SIZE) * PAGE_SIZE);
	}, [totalCount, offset]);

	const handleCreateNew = () => {
		setEditingRule(null);
		setDialogOpen(true);
	};

	const handleEdit = (rule: RoutingRule) => {
		setEditingRule(rule);
		setDialogOpen(true);
	};

	const handleDialogOpenChange = (open: boolean) => {
		setDialogOpen(open);
		if (!open) {
			setEditingRule(null);
		}
	};

	const hasActiveFilters = debouncedSearch;

	// True empty state: no rules at all (not just filtered to zero)
	if (!isLoading && totalCount === 0 && !hasActiveFilters) {
		return (
			<>
				<RoutingRulesEmptyState onAddClick={handleCreateNew} canCreate={canCreate} />
				<RoutingRuleSheet open={dialogOpen} onOpenChange={handleDialogOpenChange} editingRule={editingRule} />
			</>
		);
	}

	return (
		<div className="space-y-5">
			<header className="flex flex-wrap items-end justify-between gap-4">
				<div className="space-y-1.5">
					<div className="text-muted-foreground text-[11px] font-semibold uppercase tracking-[0.18em]">
						Model Hub
					</div>
					<div className="flex items-center gap-2.5">
						<span className="bg-primary/12 text-primary inline-flex h-9 w-9 items-center justify-center rounded-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
							<Route className="h-4 w-4" />
						</span>
						<div>
							<h1 className="text-2xl font-semibold leading-none tracking-tight">Routing Rules</h1>
							<p className="text-muted-foreground mt-1 max-w-3xl text-sm">
								Manage CEL-based routing rules for intelligent request routing across providers.
							</p>
						</div>
					</div>
				</div>
				{canCreate && (
					<Button data-testid="create-routing-rule-btn" onClick={handleCreateNew} disabled={isLoading}>
						<Plus className="h-4 w-4" />
						<span>New Rule</span>
					</Button>
				)}
			</header>

			<RoutingRulesTable
				rules={rules}
				totalCount={totalCount}
				isLoading={isLoading}
				onEdit={handleEdit}
				canDelete={canDelete}
				search={search}
				onSearchChange={setSearch}
				offset={offset}
				limit={PAGE_SIZE}
				onOffsetChange={setOffset}
			/>

			<RoutingRuleSheet open={dialogOpen} onOpenChange={handleDialogOpenChange} editingRule={editingRule} />
		</div>
	);
}
