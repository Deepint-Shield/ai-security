"use client";

import { Rocket } from "lucide-react";

import { useGetUpdatesQuery } from "@/lib/store/apis";

// UpdatesVersionChip renders the current platform/SDK version in the sidebar
// footer. The OSS portal has no Updates page, so this is a static, non-linking
// version label.
export function UpdatesVersionChip() {
	const { data } = useGetUpdatesQuery();
	const rawVersion = data?.current_version;

	if (!rawVersion) return null;

	// Normalize so we never render a double "v" (e.g. backend "v2.3.0" + our prefix).
	const version = rawVersion.replace(/^v/i, "");

	return (
		<div
			title={`You're on version v${version}`}
			className="text-muted-foreground flex items-center justify-between gap-2 rounded-lg px-2.5 py-1.5 text-xs group-data-[collapsible=icon]:justify-center group-data-[collapsible=icon]:px-2"
			aria-label={`Version ${version}`}
		>
			<span className="flex items-center gap-1.5">
				<Rocket className="h-3 w-3 shrink-0" />
				<span className="tabular-nums group-data-[collapsible=icon]:hidden">v{version}</span>
			</span>
		</div>
	);
}
