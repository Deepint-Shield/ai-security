"use client";

// BulkAgentAttributesDialog - apply the agent attribute taxonomy
// (risk tier + capabilities) across many VKs at once. Two selection modes:
//   • "All agent-bound keys in this workspace" - the apply_to_all_in_workspace
//     path (workspace-scoped on the server).
//   • "Selected keys" - an explicit multi-select of the agent-bound VKs the
//     operator ticks.
// Only agent-bound VKs (those the PEP fires on) are offered, since attribute
// matching is meaningless for LLM-only keys.
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scrollArea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { useBulkUpdateVirtualKeyAgentAttributesMutation } from "@/lib/store/apis/governanceApi";
import { selectActiveWorkspaceId } from "@/lib/store/slices/activeScopeSlice";
import { useAppSelector } from "@/lib/store/hooks";
import type { VirtualKey } from "@/lib/types/governance";
import { Layers } from "lucide-react";
import { useMemo, useState } from "react";

type RiskTier = "" | "low" | "medium" | "high" | "critical";

export function BulkAgentAttributesDialog({
	open,
	onOpenChange,
	virtualKeys,
}: {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	virtualKeys: VirtualKey[];
}) {
	const { toast } = useToast();
	const activeWorkspaceId = useAppSelector(selectActiveWorkspaceId);
	const [bulkApply, { isLoading }] = useBulkUpdateVirtualKeyAgentAttributesMutation();

	const [mode, setMode] = useState<"all" | "selected">("all");
	const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
	const [riskTier, setRiskTier] = useState<RiskTier>("");
	const [applyRisk, setApplyRisk] = useState<boolean>(true);
	const [capabilities, setCapabilities] = useState<string>("");
	const [applyCaps, setApplyCaps] = useState<boolean>(false);

	// Only agent-bound VKs are eligible - the PEP doesn't fire on LLM-only keys.
	const agentVKs = useMemo(
		() => virtualKeys.filter((vk) => !!vk.bound_identity_provider),
		[virtualKeys],
	);

	const toggleId = (id: string) => {
		setSelectedIds((prev) => {
			const next = new Set(prev);
			if (next.has(id)) next.delete(id);
			else next.add(id);
			return next;
		});
	};

	const targetCount = mode === "all" ? agentVKs.length : selectedIds.size;
	const nothingToApply = !applyRisk && !applyCaps;

	const handleApply = async () => {
		if (nothingToApply) {
			toast({ variant: "destructive", title: "Pick at least one attribute to apply" });
			return;
		}
		if (mode === "selected" && selectedIds.size === 0) {
			toast({ variant: "destructive", title: "Select at least one key" });
			return;
		}
		const caps = capabilities
			.split(",")
			.map((s) => s.trim().toLowerCase())
			.filter(Boolean);
		try {
			const res = await bulkApply({
				workspace_id: activeWorkspaceId || undefined,
				apply_to_all_in_workspace: mode === "all",
				virtual_key_ids: mode === "selected" ? Array.from(selectedIds) : undefined,
				only_agent_bound: true,
				// Send the field only when its "apply" toggle is on; an empty
				// risk tier clears the value server-side.
				...(applyRisk ? { agent_risk_level: riskTier } : {}),
				...(applyCaps ? { agent_capabilities: caps } : {}),
			}).unwrap();
			toast({ title: `Updated ${res.updated} of ${res.matched} key${res.matched === 1 ? "" : "s"}` });
			onOpenChange(false);
			setSelectedIds(new Set());
		} catch (e) {
			toast({ variant: "destructive", title: "Bulk apply failed", description: (e as Error)?.message });
		}
	};

	return (
		<Dialog open={open} onOpenChange={onOpenChange}>
			<DialogContent className="max-w-lg">
				<DialogHeader>
					<DialogTitle className="flex items-center gap-2">
						<Layers className="h-4 w-4" /> Bulk agent attributes
					</DialogTitle>
					<DialogDescription>
						Apply risk tier / capabilities to many agent-bound keys at once. Changes take effect on the next decision - no restart.
					</DialogDescription>
				</DialogHeader>

				<div className="flex flex-col gap-4">
					{/* Target selection */}
					<div className="flex flex-col gap-2">
						<Label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Apply to</Label>
						<div className="grid grid-cols-2 gap-2">
							<button
								type="button"
								onClick={() => setMode("all")}
								className={`rounded-lg border p-2.5 text-left text-[12px] transition ${
									mode === "all" ? "border-primary/50 bg-primary/5" : "border-border/60 hover:bg-muted/40"
								}`}
							>
								<div className="font-medium">All agent keys in workspace</div>
								<div className="text-[10.5px] text-muted-foreground">{agentVKs.length} eligible</div>
							</button>
							<button
								type="button"
								onClick={() => setMode("selected")}
								className={`rounded-lg border p-2.5 text-left text-[12px] transition ${
									mode === "selected" ? "border-primary/50 bg-primary/5" : "border-border/60 hover:bg-muted/40"
								}`}
							>
								<div className="font-medium">Selected keys</div>
								<div className="text-[10.5px] text-muted-foreground">{selectedIds.size} chosen</div>
							</button>
						</div>
					</div>

					{mode === "selected" && (
						<ScrollArea className="h-40 rounded-lg border border-border/60">
							<div className="flex flex-col gap-1 p-2">
								{agentVKs.length === 0 ? (
									<div className="p-2 text-[12px] text-muted-foreground">No agent-bound keys in this workspace.</div>
								) : (
									agentVKs.map((vk) => (
										<label
											key={vk.id}
											className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 hover:bg-muted/40"
										>
											<Checkbox checked={selectedIds.has(vk.id)} onCheckedChange={() => toggleId(vk.id)} />
											<span className="flex-1 truncate text-[12px]">{vk.name}</span>
											{vk.agent_risk_level ? (
												<Badge variant="outline" className="text-[10px]">{vk.agent_risk_level}</Badge>
											) : null}
										</label>
									))
								)}
							</div>
						</ScrollArea>
					)}

					{/* Risk tier */}
					<div className="flex items-start gap-2 rounded-lg border border-border/60 p-3">
						<Checkbox checked={applyRisk} onCheckedChange={(v) => setApplyRisk(!!v)} className="mt-0.5" />
						<div className="flex flex-1 flex-col gap-1.5">
							<Label className="text-[12px] font-medium">Set risk tier</Label>
							<Select value={riskTier || "unset"} onValueChange={(v) => setRiskTier(v === "unset" ? "" : (v as RiskTier))} disabled={!applyRisk}>
								<SelectTrigger className="h-8 text-[12px]"><SelectValue placeholder="Unset" /></SelectTrigger>
								<SelectContent>
									<SelectItem value="unset">Unset (clear)</SelectItem>
									<SelectItem value="low">Low</SelectItem>
									<SelectItem value="medium">Medium</SelectItem>
									<SelectItem value="high">High</SelectItem>
									<SelectItem value="critical">Critical</SelectItem>
								</SelectContent>
							</Select>
						</div>
					</div>

					{/* Capabilities */}
					<div className="flex items-start gap-2 rounded-lg border border-border/60 p-3">
						<Checkbox checked={applyCaps} onCheckedChange={(v) => setApplyCaps(!!v)} className="mt-0.5" />
						<div className="flex flex-1 flex-col gap-1.5">
							<Label className="text-[12px] font-medium">Set capabilities <span className="font-normal text-muted-foreground">(comma-separated; replaces existing)</span></Label>
							<Input
								value={capabilities}
								onChange={(e) => setCapabilities(e.target.value)}
								placeholder="financial-analysis, compliance-query"
								disabled={!applyCaps}
								className="h-8 text-[12px]"
							/>
						</div>
					</div>
				</div>

				<DialogFooter>
					<Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
					<Button onClick={handleApply} disabled={isLoading || nothingToApply || targetCount === 0}>
						{isLoading ? "Applying…" : `Apply to ${targetCount} key${targetCount === 1 ? "" : "s"}`}
					</Button>
				</DialogFooter>
			</DialogContent>
		</Dialog>
	);
}
