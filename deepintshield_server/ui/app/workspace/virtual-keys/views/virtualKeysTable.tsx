"use client"

import {
	AlertDialog,
	AlertDialogAction,
	AlertDialogCancel,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
	AlertDialogTrigger,
} from "@/components/ui/alertDialog";
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { getErrorMessage, useDeleteVirtualKeyMutation, useListMyWorkspacesQuery } from "@/lib/store"
import { Customer, Team, VirtualKey } from "@/lib/types/governance"
import { cn } from "@/lib/utils"
import { formatCurrency } from "@/lib/utils/governance"
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib"
import { ChevronLeft, ChevronRight, Copy, Edit, Eye, EyeOff, KeyRound, Layers, Plus, Search, Trash2 } from "lucide-react"
import { useMemo, useState } from "react"
import { toast } from "sonner"
import { BulkAgentAttributesDialog } from "./bulkAgentAttributesDialog"
import VirtualKeyDetailSheet from "./virtualKeyDetailsSheet"
import { VirtualKeysEmptyState } from "./virtualKeysEmptyState"
import VirtualKeySheet from "./virtualKeySheet"

interface VirtualKeysTableProps {
	virtualKeys: VirtualKey[];
	totalCount: number;
	teams: Team[];
	customers: Customer[];
	search: string;
	debouncedSearch: string;
	onSearchChange: (value: string) => void;
	customerFilter: string;
	onCustomerFilterChange: (value: string) => void;
	teamFilter: string;
	onTeamFilterChange: (value: string) => void;
	offset: number;
	limit: number;
	onOffsetChange: (offset: number) => void;
}

export default function VirtualKeysTable({
	virtualKeys,
	totalCount,
	teams,
	customers,
	search,
	debouncedSearch,
	onSearchChange,
	customerFilter,
	onCustomerFilterChange,
	teamFilter,
	onTeamFilterChange,
	offset,
	limit,
	onOffsetChange,
}: VirtualKeysTableProps) {
  const [showVirtualKeySheet, setShowVirtualKeySheet] = useState(false)
  const [editingVirtualKeyId, setEditingVirtualKeyId] = useState<string | null>(null)
  const [revealedKeys, setRevealedKeys] = useState<Set<string>>(new Set())
  const [selectedVirtualKeyId, setSelectedVirtualKeyId] = useState<string | null>(null)
  const [showDetailSheet, setShowDetailSheet] = useState(false)
  const [showBulkAgentDialog, setShowBulkAgentDialog] = useState(false)

  // Derive objects from props so they stay in sync with RTK cache updates
  const editingVirtualKey = useMemo(
    () => (editingVirtualKeyId ? virtualKeys.find((vk) => vk.id === editingVirtualKeyId) ?? null : null),
    [editingVirtualKeyId, virtualKeys],
  )
  const selectedVirtualKey = useMemo(
    () => (selectedVirtualKeyId ? virtualKeys.find((vk) => vk.id === selectedVirtualKeyId) ?? null : null),
    [selectedVirtualKeyId, virtualKeys],
  )

  const hasCreateAccess = useRbac(RbacResource.VirtualKeys, RbacOperation.Create)
  const hasUpdateAccess = useRbac(RbacResource.VirtualKeys, RbacOperation.Update)
  const hasDeleteAccess = useRbac(RbacResource.VirtualKeys, RbacOperation.Delete)

  // Open-source edition is limited to a single virtual key (enforced server-side
  // too). Cloud / Enterprise lifts this and adds team / workspace scoping.
  const OSS_MAX_VIRTUAL_KEYS = 1
  const atVkLimit = totalCount >= OSS_MAX_VIRTUAL_KEYS

  // Workspace-name lookup so the Scope column can render a friendly name
  // rather than a raw ID. We piggyback on the user's accessible workspaces
  // - if a VK references a workspace the user can't see, the badge falls
  // back to the literal "Workspace" label.
  const { data: workspacesData } = useListMyWorkspacesQuery()
  const workspaceNameByID = useMemo(() => {
    const m = new Map<string, string>()
    for (const w of workspacesData?.workspaces ?? []) {
      m.set(w.id, w.name)
    }
    return m
  }, [workspacesData])

  const [deleteVirtualKey, { isLoading: isDeleting }] = useDeleteVirtualKeyMutation()

	const handleDelete = async (vkId: string) => {
		try {
			await deleteVirtualKey(vkId).unwrap();
			toast.success("Virtual key deleted successfully");
		} catch (error) {
			toast.error(getErrorMessage(error));
		}
	};

	const handleAddVirtualKey = () => {
		setEditingVirtualKeyId(null);
		setShowVirtualKeySheet(true);
	};

	const handleEditVirtualKey = (vk: VirtualKey, e: React.MouseEvent) => {
		e.stopPropagation(); // Prevent row click
		setEditingVirtualKeyId(vk.id);
		setShowVirtualKeySheet(true);
	};

	const handleVirtualKeySaved = () => {
		setShowVirtualKeySheet(false);
		setEditingVirtualKeyId(null);
	};

	const handleRowClick = (vk: VirtualKey) => {
		setSelectedVirtualKeyId(vk.id);
		setShowDetailSheet(true);
	};

	const handleDetailSheetClose = () => {
		setShowDetailSheet(false);
		setSelectedVirtualKeyId(null);
	};

	const toggleKeyVisibility = (vkId: string) => {
		const newRevealed = new Set(revealedKeys);
		if (newRevealed.has(vkId)) {
			newRevealed.delete(vkId);
		} else {
			newRevealed.add(vkId);
		}
		setRevealedKeys(newRevealed);
	};

	const maskKey = (key: string, revealed: boolean) => {
		if (revealed) return key;
		return key.substring(0, 8) + "•".repeat(Math.max(0, key.length - 8));
	};

	const copyToClipboard = (key: string) => {
		navigator.clipboard.writeText(key);
		toast.success("Copied to clipboard");
	};

	const hasActiveFilters = debouncedSearch || customerFilter || teamFilter;

	const renderPolicySummary = (vk: VirtualKey) => {
		if (vk.guardrail_policies && vk.guardrail_policies.length > 0) {
			return (
				<div className="flex flex-wrap gap-1">
					{vk.guardrail_policies.slice(0, 2).map((policy) => (
						<Badge key={policy.id} variant="outline">
							{policy.name}
						</Badge>
					))}
					{vk.guardrail_policies.length > 2 ? <Badge variant="outline">+{vk.guardrail_policies.length - 2} more</Badge> : null}
				</div>
			);
		}
		return (
			<span className="text-muted-foreground text-sm">
				No explicit policies
			</span>
		);
	};

	// True empty state: no VKs at all (not just filtered to zero)
	if (totalCount === 0 && !hasActiveFilters) {
		return (
			<>
				{showVirtualKeySheet && (
					<VirtualKeySheet
						virtualKey={editingVirtualKey}
						teams={teams}
						customers={customers}
						onSave={handleVirtualKeySaved}
						onCancel={() => setShowVirtualKeySheet(false)}
					/>
				)}
				<VirtualKeysEmptyState onAddClick={handleAddVirtualKey} canCreate={hasCreateAccess} />
			</>
		);
	}

	return (
		<>
			{showVirtualKeySheet && (
				<VirtualKeySheet
					virtualKey={editingVirtualKey}
					teams={teams}
					customers={customers}
					onSave={handleVirtualKeySaved}
					onCancel={() => setShowVirtualKeySheet(false)}
				/>
			)}

			{showDetailSheet && selectedVirtualKey && <VirtualKeyDetailSheet virtualKey={selectedVirtualKey} onClose={handleDetailSheetClose} />}

			<BulkAgentAttributesDialog
				open={showBulkAgentDialog}
				onOpenChange={setShowBulkAgentDialog}
				virtualKeys={virtualKeys}
			/>

			<div className="space-y-5">
				<header className="flex flex-wrap items-end justify-between gap-4">
					<div className="space-y-1.5">
						<div className="text-muted-foreground text-[11px] font-semibold uppercase tracking-[0.18em]">
							Access &amp; Credentials
						</div>
						<div className="flex items-center gap-2.5">
							<span className="bg-primary/12 text-primary inline-flex h-9 w-9 items-center justify-center rounded-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
								<KeyRound className="h-4 w-4" />
							</span>
							<div>
								<h1 className="text-2xl font-semibold leading-none tracking-tight">Virtual Keys</h1>
								<p className="text-muted-foreground mt-1 max-w-3xl text-sm">
									Manage virtual keys, their permissions, budgets, and rate limits.
								</p>
							</div>
						</div>
					</div>
					<div className="flex items-center gap-2">
						{virtualKeys.some((vk) => vk.bound_identity_provider) && (
							<Button
								variant="outline"
								onClick={() => setShowBulkAgentDialog(true)}
								data-testid="bulk-agent-attrs-btn"
							>
								<Layers className="h-4 w-4" />
								Bulk agent attributes
							</Button>
						)}
						{atVkLimit && (
							<span className="text-muted-foreground text-xs">
								OSS is limited to 1 virtual key (unlimited on Cloud / Enterprise)
							</span>
						)}
						<Button
							onClick={handleAddVirtualKey}
							disabled={!hasCreateAccess || atVkLimit}
							title={atVkLimit ? "Open-source edition is limited to a single virtual key. Upgrade to Cloud / Enterprise for unlimited." : undefined}
							data-testid="create-vk-btn"
						>
							<Plus className="h-4 w-4" />
							Add Virtual Key
						</Button>
					</div>
				</header>

				{/* Toolbar: Search + Filters */}
				<div className="flex items-center gap-3">
					<div className="relative max-w-sm flex-1">
						<Search className="text-muted-foreground absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2" />
						<Input
							aria-label="Search virtual keys by name"
							placeholder="Search by name..."
							value={search}
							onChange={(e) => onSearchChange(e.target.value)}
							className="pl-9"
							data-testid="vk-search-input"
						/>
					</div>
					<Select value={customerFilter} onValueChange={(val) => onCustomerFilterChange(val === "all" ? "" : val)}>
						<SelectTrigger className="w-[180px]" data-testid="vk-customer-filter">
							<SelectValue placeholder="All Members" />
						</SelectTrigger>
						<SelectContent>
							<SelectItem value="all">All Members</SelectItem>
							{customers.map((c) => (
								<SelectItem key={c.id} value={c.id}>{c.name}</SelectItem>
							))}
						</SelectContent>
					</Select>
					{customerFilter && teamFilter && (
						<span className="text-muted-foreground text-xs font-medium">or</span>
					)}
					<Select value={teamFilter} onValueChange={(val) => onTeamFilterChange(val === "all" ? "" : val)}>
						<SelectTrigger className="w-[180px]" data-testid="vk-team-filter">
							<SelectValue placeholder="All Teams" />
						</SelectTrigger>
						<SelectContent>
							<SelectItem value="all">All Teams</SelectItem>
							{teams.map((t) => (
								<SelectItem key={t.id} value={t.id}>{t.name}</SelectItem>
							))}
						</SelectContent>
					</Select>
				</div>

				<div className="border-border/60 bg-card/40 overflow-hidden rounded-2xl border shadow-[0_1px_0_rgba(255,255,255,0.04)_inset]">
					<Table data-testid="vk-table">
						<TableHeader className="bg-muted/30">
							<TableRow className="hover:bg-transparent">
								<TableHead className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">Name</TableHead>
								<TableHead className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">Scope</TableHead>
								<TableHead className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">Assigned To</TableHead>
								<TableHead className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">Policies</TableHead>
								<TableHead className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">Key</TableHead>
								<TableHead className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">Budget</TableHead>
								<TableHead className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">Status</TableHead>
								<TableHead className="text-right"></TableHead>
							</TableRow>
						</TableHeader>
						<TableBody>
							{virtualKeys.length === 0 ? (
								<TableRow className="hover:bg-transparent">
									<TableCell colSpan={8} className="py-12 text-center">
										<div className="flex flex-col items-center gap-1.5">
											<span className="bg-muted text-muted-foreground inline-flex h-10 w-10 items-center justify-center rounded-xl">
												<Search className="h-4 w-4" strokeWidth={1.75} />
											</span>
											<p className="text-foreground text-sm font-semibold">No matching virtual keys</p>
											<p className="text-muted-foreground text-xs">Try a different search term.</p>
										</div>
									</TableCell>
								</TableRow>
							) : (
								virtualKeys.map((vk) => {
									const isRevealed = revealedKeys.has(vk.id);
									const isExhausted =
										(vk.budget?.current_usage && vk.budget?.max_limit && vk.budget.current_usage >= vk.budget.max_limit) ||
										(vk.rate_limit?.token_current_usage &&
											vk.rate_limit?.token_max_limit &&
											vk.rate_limit.token_current_usage >= vk.rate_limit.token_max_limit) ||
										(vk.rate_limit?.request_current_usage &&
											vk.rate_limit?.request_max_limit &&
											vk.rate_limit.request_current_usage >= vk.rate_limit.request_max_limit);

									return (
										<TableRow
											key={vk.id}
											data-testid={`vk-row-${vk.name}`}
											className="border-border/40 hover:bg-primary/5 cursor-pointer transition-colors"
											onClick={() => handleRowClick(vk)}
										>
											<TableCell className="max-w-[200px]">
												<div className="flex items-center gap-2">
													<span className="bg-primary/12 text-primary inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg">
														<KeyRound className="h-3.5 w-3.5" />
													</span>
													<span className="truncate text-sm font-medium">{vk.name}</span>
												</div>
											</TableCell>
											<TableCell>
												{vk.workspace_id ? (
													<Badge
														variant="outline"
														className="border-amber-500/60 text-amber-700 dark:text-amber-300"
													>
														{workspaceNameByID.get(vk.workspace_id) ?? "Workspace"}
													</Badge>
												) : (
													<Badge variant="secondary">Org-wide</Badge>
												)}
											</TableCell>
											<TableCell>
												<div className="flex flex-wrap items-center gap-1">
													{vk.team ? (
														<Badge variant="outline">Team: {vk.team.name}</Badge>
													) : vk.customer ? (
														<Badge variant="outline">Member: {vk.customer.name}</Badge>
													) : (
														<span className="text-muted-foreground text-sm">-</span>
													)}
													{vk.bound_identity_provider ? (
														// "Agent" pill - surfaces unified-VK keys that opted into
														// PEP-gated agent semantics. Hover-target only when set.
														<Badge
															variant="outline"
															className="border-primary/40 bg-primary/10 text-[10.5px] font-medium text-primary"
															title={`Agent-bound via ${vk.bound_identity_provider}`}
														>
															Agent
														</Badge>
													) : null}
												</div>
											</TableCell>
											<TableCell className="max-w-[280px]">
												{renderPolicySummary(vk)}
											</TableCell>
											<TableCell onClick={(e) => e.stopPropagation()}>
												<div className="flex items-center gap-2">
													<code className="cursor-default px-2 py-1 font-mono text-sm" data-testid="vk-key-value">{maskKey(vk.value, isRevealed)}</code>
													<Button
														variant="ghost"
														size="sm"
														onClick={() => toggleKeyVisibility(vk.id)}
														data-testid={`vk-visibility-btn-${vk.name}`}
													>
														{isRevealed ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
													</Button>
													<Button
														variant="ghost"
														size="sm"
														onClick={() => copyToClipboard(vk.value)}
														data-testid={`vk-copy-btn-${vk.name}`}
													>
														<Copy className="h-4 w-4" />
													</Button>
												</div>
											</TableCell>
											<TableCell>
												{vk.budget ? (
													<span className={cn("font-mono text-sm", vk.budget.current_usage >= vk.budget.max_limit && "text-red-400")}>
														{formatCurrency(vk.budget.current_usage)} / {formatCurrency(vk.budget.max_limit)}
													</span>
												) : (
													<span className="text-muted-foreground text-sm">-</span>
												)}
											</TableCell>
											<TableCell>
												<Badge variant={vk.is_active ? (isExhausted ? "destructive" : "default") : "secondary"}>
													{vk.is_active ? (isExhausted ? "Exhausted" : "Active") : "Inactive"}
												</Badge>
											</TableCell>
											<TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
												<div className="flex items-center justify-end gap-2">
													<Button
														variant="ghost"
														size="sm"
														onClick={(e) => handleEditVirtualKey(vk, e)}
														disabled={!hasUpdateAccess}
														data-testid={`vk-edit-btn-${vk.name}`}
													>
														<Edit className="h-4 w-4" />
													</Button>
													<AlertDialog>
														<AlertDialogTrigger asChild>
															<Button
																variant="ghost"
																size="sm"
																onClick={(e) => e.stopPropagation()}
																disabled={!hasDeleteAccess}
																data-testid={`vk-delete-btn-${vk.name}`}
															>
																<Trash2 className="h-4 w-4" />
															</Button>
														</AlertDialogTrigger>
														<AlertDialogContent>
															<AlertDialogHeader>
																<AlertDialogTitle>Delete Virtual Key</AlertDialogTitle>
																<AlertDialogDescription>
																	Are you sure you want to delete &quot;{vk.name.length > 20 ? `${vk.name.slice(0, 20)}...` : vk.name}
																	&quot;? This action cannot be undone.
																</AlertDialogDescription>
															</AlertDialogHeader>
															<AlertDialogFooter>
																<AlertDialogCancel>Cancel</AlertDialogCancel>
																<AlertDialogAction onClick={() => handleDelete(vk.id)} disabled={isDeleting}>
																	{isDeleting ? "Deleting..." : "Delete"}
																</AlertDialogAction>
															</AlertDialogFooter>
														</AlertDialogContent>
													</AlertDialog>
												</div>
											</TableCell>
										</TableRow>
									);
								})
							)}
						</TableBody>
					</Table>
				</div>

				{/* Pagination */}
				{totalCount > 0 && (
					<div className="flex items-center justify-between px-1">
						<p className="text-muted-foreground text-xs tabular-nums">
							Showing <span className="text-foreground font-medium">{offset + 1}-{Math.min(offset + limit, totalCount)}</span> of{" "}
							<span className="text-foreground font-medium">{totalCount}</span>
						</p>
						<div className="flex gap-2">
							<Button
								variant="outline"
								size="sm"
								disabled={offset === 0}
								onClick={() => onOffsetChange(Math.max(0, offset - limit))}
								data-testid="vk-pagination-prev-btn"
							>
								<ChevronLeft className="mr-1 h-4 w-4" />
								Previous
							</Button>
							<Button
								variant="outline"
								size="sm"
								disabled={offset + limit >= totalCount}
								onClick={() => onOffsetChange(offset + limit)}
								data-testid="vk-pagination-next-btn"
							>
								Next
								<ChevronRight className="ml-1 h-4 w-4" />
							</Button>
						</div>
					</div>
				)}
			</div>
		</>
	);
}
