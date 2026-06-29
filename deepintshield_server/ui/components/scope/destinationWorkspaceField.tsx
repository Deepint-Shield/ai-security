"use client";

import { Layers } from "lucide-react";

import { Label } from "@/components/ui/label";
import { useAppSelector } from "@/lib/store/hooks";
import { useListMyWorkspacesQuery } from "@/lib/store/apis";
import { selectActiveOrgId, selectActiveWorkspaceId } from "@/lib/store/slices/activeScopeSlice";

/**
 * DestinationWorkspaceField - a small read-only field for use in create
 * dialogs. Surfaces *where* the resource will land (the current sidebar
 * workspace), so the user has a clear mental model of the scope at the
 * moment they hit Save. To change the destination, the user switches
 * workspaces in the sidebar - the same control that drives every list
 * page on the dashboard.
 *
 * Why read-only and not a dropdown:
 *  - Avoids two scope-switching surfaces fighting each other (sidebar +
 *    per-dialog dropdown).
 *  - Matches the OpenAI / Anthropic Projects model where you're always
 *    creating in "the project I'm currently looking at".
 *  - Forces the user to switch context first, which is the right
 *    affordance once they realise they were about to save in the wrong
 *    workspace.
 */
export function DestinationWorkspaceField() {
	const activeOrgId = useAppSelector(selectActiveOrgId);
	const activeWorkspaceId = useAppSelector(selectActiveWorkspaceId);
	const { data } = useListMyWorkspacesQuery();
	const activeWorkspace = data?.workspaces.find((w) => w.id === activeWorkspaceId) ?? null;

	if (!activeOrgId || !activeWorkspaceId) {
		return null;
	}

	return (
		<div className="grid gap-1.5">
			<Label className="text-muted-foreground text-xs">Destination workspace</Label>
			<div className="border-border bg-muted/40 text-foreground inline-flex items-center gap-2 rounded-md border px-3 py-2 text-sm">
				<Layers className="text-muted-foreground h-3.5 w-3.5" />
				<span className="font-medium">{activeWorkspace?.name ?? "Active workspace"}</span>
				<span className="text-muted-foreground ml-auto text-[11px]">
					Change via the sidebar workspace switcher
				</span>
			</div>
		</div>
	);
}
