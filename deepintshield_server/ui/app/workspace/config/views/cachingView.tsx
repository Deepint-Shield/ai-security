"use client";

import { getErrorMessage, useGetCoreConfigQuery } from "@/lib/store";
import { PiggyBank } from "lucide-react";
import PluginsForm from "./pluginsForm";

/**
 * "Cost Optimization" page. Bundles all caching/cost-reduction surfaces under
 * a single tabbed view - semantic cache (skip the LLM call entirely on
 * duplicates) and provider prompt caching (skip the prefix prefill on KV
 * reuse). The actual tab UI lives inside PluginsForm; this wrapper handles
 * page chrome + config loading.
 */
export default function CachingView() {
	const { data: deepintshieldConfig, isLoading, error: configError } = useGetCoreConfigQuery({ fromDB: true });

	return (
		<div className="workspace-page-shell space-y-6">
			<header className="space-y-1.5">
				<div className="text-muted-foreground text-[11px] font-semibold uppercase tracking-[0.18em]">Settings</div>
				<div className="flex items-center gap-2.5">
					<span className="bg-primary/12 text-primary inline-flex h-9 w-9 items-center justify-center rounded-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
						<PiggyBank className="h-4 w-4" />
					</span>
					<div>
						<h1 className="text-2xl font-semibold leading-none tracking-tight">Cost Optimization</h1>
						{/* <p className="text-muted-foreground mt-1 text-sm">One toggle per technique. Sensible defaults on; tune behind <em>Advanced parameters</em>.</p> */}
					</div>
				</div>
			</header>

			{isLoading && (
				<div className="flex items-center justify-center py-8">
					<p className="text-muted-foreground">Loading configuration...</p>
				</div>
			)}

			{configError !== undefined && (
				<div className="border-destructive/50 bg-destructive/10 rounded-lg border p-4">
					<p className="text-destructive text-sm font-medium">Failed to load configuration</p>
					<p className="text-muted-foreground mt-1 text-sm">
						{getErrorMessage(configError) || "An unexpected error occurred. Please try again."}
					</p>
				</div>
			)}

			{!isLoading && !configError && <PluginsForm isVectorStoreEnabled={deepintshieldConfig?.is_cache_connected ?? false} />}
		</div>
	);
}
