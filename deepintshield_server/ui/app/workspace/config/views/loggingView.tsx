"use client";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { getErrorMessage } from "@/lib/store";
import {
	useGetWorkspaceLoggingQuery,
	useResetWorkspaceLoggingMutation,
	useUpdateWorkspaceLoggingMutation,
	type WorkspaceLoggingSettings,
} from "@/lib/store/apis/workspaceLoggingApi";
import { parseArrayFromText } from "@/lib/utils/array";
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib";
import { Database, EyeOff, KeyRound, RotateCcw, ScrollText, Tags, Timer } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

// loggingView is the per-workspace Logs Settings page. The five knobs below
// are scoped to whatever workspace the sidebar switcher has selected - the
// active workspace ID is propagated to the backend via X-Active-Workspace-Id
// (injected by baseApi.prepareHeaders), so this component just reads/writes
// through the workspaceLoggingApi without threading the ID through props.
//
// When no override row exists for the workspace, GET /workspace-logging
// returns the tenant-global defaults with is_override=false. The form
// populates from those values and only writes a row on first save - so a
// fresh workspace can keep inheriting until an operator explicitly diverges.
export default function LoggingView() {
	const hasSettingsUpdateAccess = useRbac(RbacResource.Settings, RbacOperation.Update);
	const { data: settings, isFetching } = useGetWorkspaceLoggingQuery(undefined);
	const [updateSettings, { isLoading: isSaving }] = useUpdateWorkspaceLoggingMutation();
	const [resetSettings, { isLoading: isResetting }] = useResetWorkspaceLoggingMutation();

	// Mirror the server payload into local form state so the operator can
	// edit several fields before saving. `original` tracks the last-fetched
	// shape so hasChanges is a pure diff against what's persisted.
	const [local, setLocal] = useState<WorkspaceLoggingSettings | null>(null);
	const [headersText, setHeadersText] = useState<string>("");
	useEffect(() => {
		if (!settings) return;
		setLocal(settings);
		setHeadersText((settings.logging_headers || []).join(", "));
	}, [settings]);

	const hasChanges = useMemo(() => {
		if (!settings || !local) return false;
		return (
			local.enable_logging !== settings.enable_logging ||
			local.disable_content_logging !== settings.disable_content_logging ||
			local.log_retention_days !== settings.log_retention_days ||
			local.hide_deleted_virtual_keys_in_filters !== settings.hide_deleted_virtual_keys_in_filters ||
			JSON.stringify(local.logging_headers || []) !== JSON.stringify(settings.logging_headers || [])
		);
	}, [settings, local]);

	const updateField = useCallback(<K extends keyof WorkspaceLoggingSettings>(key: K, value: WorkspaceLoggingSettings[K]) => {
		setLocal((prev) => (prev ? { ...prev, [key]: value } : prev));
	}, []);

	const updateHeadersText = useCallback((text: string) => {
		setHeadersText(text);
		setLocal((prev) => (prev ? { ...prev, logging_headers: parseArrayFromText(text) } : prev));
	}, []);

	const handleSave = useCallback(async () => {
		if (!local) return;
		if (local.log_retention_days < 1) {
			toast.error("Log retention days must be at least 1 day");
			return;
		}
		try {
			await updateSettings(local).unwrap();
			toast.success("Workspace logging settings saved.");
		} catch (error) {
			toast.error(getErrorMessage(error));
		}
	}, [local, updateSettings]);

	const handleReset = useCallback(async () => {
		if (typeof window !== "undefined" && !window.confirm("Reset Logs Settings for this workspace to tenant defaults? Any per-workspace overrides will be removed.")) {
			return;
		}
		try {
			await resetSettings().unwrap();
			toast.success("Workspace reverted to tenant defaults.");
		} catch (error) {
			toast.error(getErrorMessage(error));
		}
	}, [resetSettings]);

	const showAdvanced = !!local?.enable_logging;

	return (
		<div className="workspace-page-shell space-y-6 pb-24">
			{/* Page header with workspace badge */}
			<div className="space-y-1.5">
				<div className="text-muted-foreground text-[11px] font-semibold uppercase tracking-[0.18em]">Settings</div>
				<div className="flex flex-wrap items-end justify-between gap-3">
					<div className="flex items-center gap-2.5">
						<span className="inline-flex h-9 w-9 items-center justify-center rounded-xl bg-primary/12 text-primary shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
							<ScrollText className="h-4.5 w-4.5" />
						</span>
						<div>
							<h1 className="text-2xl font-semibold tracking-tight leading-none">Logs Settings</h1>
							<p className="text-muted-foreground mt-1 text-xs">
								Applies to the entire gateway.
							</p>
						</div>
					</div>
					<div className="flex items-center gap-2">
						{settings?.is_override ? (
							<Badge variant="outline" className="border-emerald-500/60 text-emerald-700 dark:text-emerald-300">
								Override active
							</Badge>
						) : (
							<Badge variant="outline" className="border-border/60 text-muted-foreground">
								Inheriting defaults
							</Badge>
						)}
						{hasChanges ? (
							<Badge variant="outline" className="border-amber-500/60 bg-amber-500/10 text-amber-700 dark:text-amber-300">
								<span className="mr-1.5 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-amber-500" />
								Unsaved changes
							</Badge>
						) : null}
					</div>
				</div>
			</div>

			{/* Storage / capture */}
			<Card>
				<CardHeader className="pb-3">
					<CardTitle className="flex items-center gap-2 text-base">
						<Database className="h-4 w-4" />
						Storage &amp; Capture
					</CardTitle>
				</CardHeader>
				<CardContent className="px-0">
					<div className="divide-border/50 divide-y">
						<SettingRow
							icon={<Database className="h-4 w-4" />}
							htmlFor="enable-logging"
							title="Enable Logs"
							description="When off, no requests from this workspace are written to the logs table. Other workspaces are unaffected."
							control={
								<Switch
									id="enable-logging"
									size="md"
									checked={!!local?.enable_logging}
									disabled={!local || isFetching}
									onCheckedChange={(checked) => updateField("enable_logging", checked)}
								/>
							}
						/>
						{showAdvanced && (
							<SettingRow
								icon={<EyeOff className="h-4 w-4" />}
								htmlFor="disable-content-logging"
								title="Disable Content Logging"
								description="When on, only usage metadata (latency, cost, tokens) is logged for this workspace. Request and response bodies are dropped before persistence."
								control={
									<Switch
										id="disable-content-logging"
										size="md"
										checked={!!local?.disable_content_logging}
										disabled={!local || isFetching}
										onCheckedChange={(checked) => updateField("disable_content_logging", checked)}
									/>
								}
							/>
						)}
						{showAdvanced && (
							<SettingRow
								icon={<Timer className="h-4 w-4" />}
								htmlFor="log-retention-days"
								title="Log Retention Days"
								description="Days to retain logs from this workspace. Older rows are automatically deleted by the retention sweeper."
								control={
									<div className="flex items-center gap-2">
										<Input
											id="log-retention-days"
											type="number"
											min="1"
											value={local?.log_retention_days ?? 365}
											onChange={(e) => {
												const value = parseInt(e.target.value) || 1;
												updateField("log_retention_days", Math.max(1, value));
											}}
											className="w-24 text-right"
											disabled={!local || isFetching}
										/>
										<span className="text-muted-foreground text-xs">days</span>
									</div>
								}
							/>
						)}
						<SettingRow
							icon={<KeyRound className="h-4 w-4" />}
							htmlFor="hide-deleted-vk"
							title="Do Not Show Deleted Virtual Keys In Filters"
							description="When enabled, deleted virtual keys are excluded from VK filter dropdowns in this workspace's Logs, Dashboard, and MCP Logs."
							control={
								<Switch
									id="hide-deleted-vk"
									size="md"
									checked={!!local?.hide_deleted_virtual_keys_in_filters}
									disabled={!local || isFetching}
									onCheckedChange={(checked) => updateField("hide_deleted_virtual_keys_in_filters", checked)}
								/>
							}
						/>
					</div>
				</CardContent>
			</Card>

			{/* Logging headers */}
			{showAdvanced && (
				<Card>
					<CardHeader className="pb-3">
						<CardTitle className="flex items-center gap-2 text-base">
							<Tags className="h-4 w-4" />
							Logging Headers
						</CardTitle>
						<p className="text-muted-foreground text-xs">
							Comma-separated request headers to capture into log metadata for this workspace. Headers with the{" "}
							<code className="bg-muted rounded px-1 font-mono text-xs">x-bf-lh-</code> prefix are always captured automatically.
						</p>
					</CardHeader>
					<CardContent>
						<Textarea
							id="logging-headers"
							className="h-24 font-mono text-xs"
							placeholder="X-Tenant-ID, X-Request-Source, X-Correlation-ID"
							value={headersText}
							onChange={(e) => updateHeadersText(e.target.value)}
							disabled={!local || isFetching}
						/>
					</CardContent>
				</Card>
			)}

			{/* Sticky save bar */}
			<div className="bg-background/85 sticky bottom-0 -mx-2 mt-4 flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-border/70 px-4 py-3 backdrop-blur-md shadow-[0_-4px_18px_-12px_rgba(11,42,49,0.18)]">
				<div className="text-muted-foreground text-xs">
					{hasChanges ? (
						<span className="text-foreground">You have unsaved changes for this workspace.</span>
					) : settings?.is_override ? (
						<span>Workspace override saved.</span>
					) : (
						<span>Inheriting tenant defaults. Editing and saving will create a per-workspace override.</span>
					)}
				</div>
				<div className="flex items-center gap-2">
					{settings?.is_override ? (
						<Button
							variant="ghost"
							size="sm"
							onClick={handleReset}
							disabled={isResetting || !hasSettingsUpdateAccess}
							className="text-muted-foreground hover:text-foreground"
						>
							<RotateCcw className="mr-1 h-3.5 w-3.5" />
							{isResetting ? "Resetting…" : "Reset to defaults"}
						</Button>
					) : null}
					<Button onClick={handleSave} disabled={!hasChanges || isSaving || !hasSettingsUpdateAccess}>
						{isSaving ? "Saving..." : "Save Changes"}
					</Button>
				</div>
			</div>
		</div>
	);
}

// SettingRow - shared row layout (icon tile + label+description on the
// left, control on the right). Same shape as the legacy global settings
// page so the visual language stays consistent across workspaces.
function SettingRow({
	icon,
	htmlFor,
	title,
	description,
	control,
}: {
	icon: React.ReactNode;
	htmlFor: string;
	title: string;
	description: React.ReactNode;
	control: React.ReactNode;
}) {
	return (
		<div className="flex items-start justify-between gap-4 px-5 py-4">
			<div className="flex min-w-0 flex-1 items-start gap-3">
				<span className="text-muted-foreground mt-0.5 inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-border/60 bg-muted/50">
					{icon}
				</span>
				<div className="min-w-0 space-y-0.5">
					<label htmlFor={htmlFor} className="text-foreground block text-sm font-medium">
						{title}
					</label>
					<p className="text-muted-foreground text-xs leading-relaxed">{description}</p>
				</div>
			</div>
			<div className="flex shrink-0 items-center pt-0.5">{control}</div>
		</div>
	);
}
