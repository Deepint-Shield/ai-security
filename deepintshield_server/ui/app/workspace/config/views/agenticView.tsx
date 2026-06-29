"use client";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { getErrorMessage, useGetAgenticRolloutQuery, useUpdateAgenticRolloutMutation } from "@/lib/store";
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib";
import { Bot, Info } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

// AgenticView - basic OSS enable/disable surface for the Agentic Policy
// Decision Point (the /decide endpoint). There is no standalone "agentic
// enabled" config flag; the runtime gate is the per-workspace rollout state's
// kill_switch. So the master switch here drives `kill_switch` (inverted) and
// the enforcement `mode` (enforce vs shadow) through the existing rollout
// mutation. Advanced agentic supply-chain security (AIBOM, tool-integrity,
// ReBAC identity, observability exporters) is Cloud/Enterprise.
export default function AgenticView() {
	const hasSettingsUpdateAccess = useRbac(RbacResource.Settings, RbacOperation.Update);
	const { data: rollout, isLoading } = useGetAgenticRolloutQuery();
	const [updateRollout, { isLoading: isSaving }] = useUpdateAgenticRolloutMutation();

	// enabled = decisions are live (kill switch off). enforce = a DENY actually
	// blocks; shadow = decisions are logged but never block.
	const [enabled, setEnabled] = useState(false);
	const [enforce, setEnforce] = useState(false);
	// fail-closed posture: on a PDP error / unavailability, deny (true) vs allow (false).
	const [failClosed, setFailClosed] = useState(true);

	useEffect(() => {
		if (!rollout) return;
		setEnabled(!rollout.kill_switch);
		setEnforce(rollout.mode === "enforce" || rollout.mode === "canary");
		setFailClosed(rollout.default_fail_closed ?? true);
	}, [rollout]);

	const hasChanges = useMemo(() => {
		if (!rollout) return false;
		const serverEnforce = rollout.mode === "enforce" || rollout.mode === "canary";
		return (
			enabled !== !rollout.kill_switch ||
			enforce !== serverEnforce ||
			failClosed !== (rollout.default_fail_closed ?? true)
		);
	}, [rollout, enabled, enforce, failClosed]);

	const handleSave = useCallback(async () => {
		if (!rollout) return;
		try {
			await updateRollout({
				...rollout,
				kill_switch: !enabled,
				mode: enforce ? "enforce" : "shadow",
				default_fail_closed: failClosed,
			}).unwrap();
			toast.success("Agentic policy settings updated successfully.");
		} catch (error) {
			toast.error(getErrorMessage(error));
		}
	}, [rollout, enabled, enforce, failClosed, updateRollout]);

	return (
		<div className="workspace-page-shell space-y-5">
			<header className="space-y-1.5">
				<div className="text-muted-foreground text-[11px] font-semibold tracking-[0.18em] uppercase">Settings</div>
				<div className="flex items-center gap-2.5">
					<span className="bg-primary/12 text-primary inline-flex h-9 w-9 items-center justify-center rounded-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
						<Bot className="h-4 w-4" />
					</span>
					<div>
						<h1 className="text-2xl leading-none font-semibold tracking-tight">Agentic Policy</h1>
						<p className="text-muted-foreground mt-1 text-sm">Control the agentic Policy Decision Point for tool / delegation calls.</p>
					</div>
				</div>
			</header>

			<Alert variant="default" className="border-blue-20">
				<Info className="h-4 w-4 text-blue-600" />
				<AlertDescription>
					The basic PDP evaluates ABAC rules (Rego / typed-AST) against each <code className="font-mono">/decide</code> request, with an
					in-process decision cache and an append-only audit. Advanced agentic supply-chain security (AIBOM / code-scan, tool integrity,
					ReBAC identity, observability exporters) is available on Cloud / Enterprise.
				</AlertDescription>
			</Alert>

			{isLoading && (
				<div className="flex items-center justify-center py-8">
					<p className="text-muted-foreground">Loading agentic configuration...</p>
				</div>
			)}

			{!isLoading && !rollout && (
				<div className="rounded-lg border p-4">
					<p className="text-sm font-medium">Agentic runtime not initialized</p>
					<p className="text-muted-foreground mt-1 text-sm">
						No rollout state is available for this workspace yet. Make a decision call to initialize it.
					</p>
				</div>
			)}

			{!isLoading && rollout && (
				<div className="space-y-4">
					{/* Master enable/disable - drives the rollout kill switch (inverted) */}
					<div className="flex items-center justify-between space-x-2 rounded-lg border p-4">
						<div className="space-y-0.5">
							<Label htmlFor="agentic-enabled" className="text-sm font-medium">
								Enable agentic policy decisions (/decide)
							</Label>
							<p className="text-muted-foreground text-sm">
								When on, the PDP evaluates policies for each agent tool / delegation call. When off, the kill switch is engaged and the
								runtime fails open per its posture.
							</p>
						</div>
						<Switch id="agentic-enabled" checked={enabled} onCheckedChange={setEnabled} />
					</div>

					{/* Sub-toggle: enforce vs shadow */}
					<div className="flex items-center justify-between space-x-2 rounded-lg border p-4">
						<div className="space-y-0.5">
							<Label htmlFor="agentic-enforce" className="text-sm font-medium">
								Enforce decisions
							</Label>
							<p className="text-muted-foreground text-sm">
								When on, a <b>DENY</b> verdict blocks the call (enforce mode). When off, decisions are logged for observability only and
								never block (shadow mode).
							</p>
						</div>
						<Switch id="agentic-enforce" checked={enforce} disabled={!enabled} onCheckedChange={setEnforce} />
					</div>

					{/* Fail-closed posture: on PDP error / unavailability, deny vs allow */}
					<div className="flex items-center justify-between space-x-2 rounded-lg border p-4">
						<div className="space-y-0.5">
							<Label htmlFor="agentic-fail-closed" className="text-sm font-medium">
								Fail closed on PDP error
							</Label>
							<p className="text-muted-foreground text-sm">
								When on, a tool / delegation call is <b>denied</b> if the decision point errors or is unavailable (fail-closed). When off,
								such calls are allowed through (fail-open).
							</p>
						</div>
						<Switch id="agentic-fail-closed" checked={failClosed} disabled={!enabled} onCheckedChange={setFailClosed} />
					</div>
				</div>
			)}

			<div className="flex justify-end pt-2">
				<Button onClick={handleSave} disabled={!hasChanges || isSaving || !hasSettingsUpdateAccess || !rollout}>
					{isSaving ? "Saving..." : "Save Changes"}
				</Button>
			</div>
		</div>
	);
}
