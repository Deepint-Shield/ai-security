"use client";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { getErrorMessage } from "@/lib/store";
import {
	useGetWorkspaceMCPQuery,
	useResetWorkspaceMCPMutation,
	useUpdateWorkspaceMCPMutation,
	type WorkspaceMCPSettings,
} from "@/lib/store/apis/workspaceMCPApi";
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib";
import { Database, Layers, RotateCcw, Save, Settings2, Timer, Zap } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

// mcpView is the per-workspace MCP Settings page. The five knobs below are
// scoped to whichever workspace the sidebar switcher has selected - the
// active workspace ID rides every request via X-Active-Workspace-Id
// (injected by baseApi.prepareHeaders), so this component just reads/writes
// through the workspaceMCPApi without threading the ID through props.
//
// When no override row exists for the workspace, GET /workspace-mcp returns
// the tenant-global defaults with is_override=false. The form populates
// from those values and only writes a row on first save - a fresh
// workspace keeps inheriting until an operator explicitly diverges.
export default function MCPView() {
	const hasSettingsUpdateAccess = useRbac(RbacResource.Settings, RbacOperation.Update);
	// Revalidate on mount so a hard refresh reflects server truth rather than a
	// stale cross-session cache snapshot (see persistence.ts).
	const { data: settings, isFetching } = useGetWorkspaceMCPQuery(undefined, { refetchOnMountOrArgChange: true });
	const [updateSettings, { isLoading: isSaving }] = useUpdateWorkspaceMCPMutation();
	const [resetSettings, { isLoading: isResetting }] = useResetWorkspaceMCPMutation();

	// Numeric inputs are stored as strings so the operator can clear the
	// field mid-edit without the value snapping back to "0". `local`
	// tracks the canonical numeric form sent to the server.
	const [local, setLocal] = useState<WorkspaceMCPSettings | null>(null);
	const [agentDepthText, setAgentDepthText] = useState<string>("");
	const [toolTimeoutText, setToolTimeoutText] = useState<string>("");
	const [syncIntervalText, setSyncIntervalText] = useState<string>("");
	const [cacheTTLText, setCacheTTLText] = useState<string>("");
	useEffect(() => {
		if (!settings) return;
		setLocal(settings);
		setAgentDepthText(String(settings.agent_depth));
		setToolTimeoutText(String(settings.tool_execution_timeout_sec));
		setSyncIntervalText(String(settings.tool_sync_interval_minutes));
		setCacheTTLText(String(settings.cache_ttl_seconds));
	}, [settings]);

	const hasChanges = useMemo(() => {
		if (!settings || !local) return false;
		return (
			local.agent_depth !== settings.agent_depth ||
			local.tool_execution_timeout_sec !== settings.tool_execution_timeout_sec ||
			local.tool_sync_interval_minutes !== settings.tool_sync_interval_minutes ||
			local.code_mode_binding_level !== settings.code_mode_binding_level ||
			local.cache_enabled !== settings.cache_enabled ||
			local.cache_ttl_seconds !== settings.cache_ttl_seconds
		);
	}, [settings, local]);

	const updateNumericField = useCallback(
		(field: keyof WorkspaceMCPSettings, text: string, setText: (v: string) => void, minValue: number) => {
			setText(text);
			const parsed = Number.parseInt(text, 10);
			if (!Number.isNaN(parsed) && parsed >= minValue) {
				setLocal((prev) => (prev ? { ...prev, [field]: parsed } : prev));
			}
		},
		[],
	);

	const handleSave = useCallback(async () => {
		if (!local) return;
		const agent = Number.parseInt(agentDepthText, 10);
		const timeout = Number.parseInt(toolTimeoutText, 10);
		if (Number.isNaN(agent) || agent < 1) {
			toast.error("Max agent depth must be at least 1.");
			return;
		}
		if (Number.isNaN(timeout) || timeout < 1) {
			toast.error("Tool execution timeout must be at least 1 second.");
			return;
		}
		try {
			await updateSettings(local).unwrap();
			toast.success("Workspace MCP settings saved.");
		} catch (error) {
			toast.error(getErrorMessage(error));
		}
	}, [local, agentDepthText, toolTimeoutText, updateSettings]);

	const handleReset = useCallback(async () => {
		if (typeof window !== "undefined" && !window.confirm("Reset MCP Settings for this workspace to tenant defaults? Any per-workspace overrides will be removed.")) {
			return;
		}
		try {
			await resetSettings().unwrap();
			toast.success("Workspace reverted to tenant defaults.");
		} catch (error) {
			toast.error(getErrorMessage(error));
		}
	}, [resetSettings]);

	return (
		<div className="workspace-page-shell space-y-5" data-testid="mcp-settings-view">
			<header className="flex flex-wrap items-end justify-between gap-4">
				<div className="space-y-1.5">
					<div className="text-muted-foreground text-[11px] font-semibold uppercase tracking-[0.18em]">MCP Hub</div>
					<div className="flex items-center gap-2.5">
						<span className="bg-primary/12 text-primary inline-flex h-9 w-9 items-center justify-center rounded-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
							<Settings2 className="h-4 w-4" />
						</span>
						<div>
							<h1 className="text-2xl font-semibold leading-none tracking-tight">MCP Settings</h1>
							<p className="text-muted-foreground mt-1 text-sm">Applies to the entire gateway.</p>
						</div>
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
			</header>

			<div className="space-y-3">
				<SettingRow
					icon={<Layers className="h-3.5 w-3.5" />}
					htmlFor="mcp-agent-depth"
					label="Max Agent Depth"
					description="Maximum depth for MCP agent execution in this workspace."
				>
					<Input
						id="mcp-agent-depth"
						type="number"
						className="w-24"
						min="1"
						value={agentDepthText}
						disabled={!local || isFetching}
						onChange={(e) => updateNumericField("agent_depth", e.target.value, setAgentDepthText, 1)}
					/>
				</SettingRow>

				<SettingRow
					icon={<Timer className="h-3.5 w-3.5" />}
					htmlFor="mcp-tool-execution-timeout"
					label="Tool Execution Timeout (seconds)"
					description="Maximum time in seconds for tool execution under this workspace."
				>
					<Input
						id="mcp-tool-execution-timeout"
						type="number"
						className="w-24"
						min="1"
						value={toolTimeoutText}
						disabled={!local || isFetching}
						onChange={(e) => updateNumericField("tool_execution_timeout_sec", e.target.value, setToolTimeoutText, 1)}
					/>
				</SettingRow>

				<SettingRow
					icon={<Timer className="h-3.5 w-3.5" />}
					htmlFor="mcp-tool-sync-interval"
					label="Tool Sync Interval (minutes)"
					description="How often to refresh tool lists from MCP servers for this workspace. Set to 0 to disable polling."
				>
					<Input
						id="mcp-tool-sync-interval"
						type="number"
						className="w-24"
						min="0"
						value={syncIntervalText}
						disabled={!local || isFetching}
						onChange={(e) => updateNumericField("tool_sync_interval_minutes", e.target.value, setSyncIntervalText, 0)}
					/>
				</SettingRow>

				<div className="border-border/60 bg-card/40 space-y-3 rounded-xl border p-4">
					<div className="flex items-start justify-between gap-3">
						<div className="flex items-start gap-2.5">
							<span className="bg-muted text-muted-foreground inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg">
								<Zap className="h-3.5 w-3.5" />
							</span>
							<div>
								<Label htmlFor="mcp-cache-enabled" className="text-sm font-medium">Tool Result Cache</Label>
								<p className="text-muted-foreground mt-0.5 text-[11px]">
									Cache identical tool calls in this workspace so duplicates skip the upstream server. Direct hash match - not semantic.
								</p>
							</div>
						</div>
						<Switch
							id="mcp-cache-enabled"
							checked={local?.cache_enabled ?? true}
							disabled={!local || isFetching}
							onCheckedChange={(checked) => setLocal((prev) => (prev ? { ...prev, cache_enabled: checked } : prev))}
						/>
					</div>
					{local?.cache_enabled ? (
						<div className="border-border/40 flex items-center justify-between border-t pt-3">
							<div>
								<Label htmlFor="mcp-cache-ttl" className="text-sm font-medium">Cache TTL (seconds)</Label>
								<p className="text-muted-foreground mt-0.5 text-[11px]">How long to keep a cached result before re-executing.</p>
							</div>
							<Input
								id="mcp-cache-ttl"
								type="number"
								className="w-24"
								min="0"
								value={cacheTTLText}
								disabled={!local || isFetching}
								onChange={(e) => updateNumericField("cache_ttl_seconds", e.target.value, setCacheTTLText, 0)}
							/>
						</div>
					) : null}
				</div>

				<div className="border-border/60 bg-card/40 space-y-3 rounded-xl border p-4">
					<div className="flex items-start gap-2.5">
						<span className="bg-muted text-muted-foreground inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg">
							<Database className="h-3.5 w-3.5" />
						</span>
						<div className="flex-1">
							<Label htmlFor="mcp-binding-level" className="text-sm font-medium">Code Mode Binding Level</Label>
							<p className="text-muted-foreground mt-0.5 text-[11px]">
								Server-level exposes all tools per server; tool-level exposes individual tools.
							</p>
						</div>
					</div>
					<Select
						value={local?.code_mode_binding_level ?? "server"}
						onValueChange={(value) => setLocal((prev) => (prev ? { ...prev, code_mode_binding_level: value } : prev))}
						disabled={!local || isFetching}
					>
						<SelectTrigger id="mcp-binding-level" className="w-full sm:w-56">
							<SelectValue placeholder="Select binding level" />
						</SelectTrigger>
						<SelectContent>
							<SelectItem value="server">Server-Level</SelectItem>
							<SelectItem value="tool">Tool-Level</SelectItem>
						</SelectContent>
					</Select>

					<div className="space-y-2">
						<p className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">VFS Structure</p>
						{(local?.code_mode_binding_level ?? "server") === "server" ? (
							<div className="bg-muted/50 border-border/60 rounded-lg border p-3">
								<div className="text-foreground space-y-1 font-mono text-xs">
									<div>servers/</div>
									<div className="pl-3">├─ calculator.d.ts</div>
									<div className="pl-3">├─ youtube.d.ts</div>
									<div className="pl-3">└─ weather.d.ts</div>
								</div>
								<p className="text-muted-foreground mt-2 text-[11px] italic">All tools per server in a single .d.ts file</p>
							</div>
						) : (
							<div className="bg-muted/50 border-border/60 rounded-lg border p-3">
								<div className="text-foreground space-y-1 font-mono text-xs">
									<div>servers/</div>
									<div className="pl-3">├─ calculator/</div>
									<div className="pl-6">├─ add.d.ts</div>
									<div className="pl-6">└─ subtract.d.ts</div>
									<div className="pl-3">├─ youtube/</div>
									<div className="pl-6">├─ GET_CHANNELS.d.ts</div>
									<div className="pl-6">└─ SEARCH_VIDEOS.d.ts</div>
									<div className="pl-3">└─ weather/</div>
									<div className="pl-6">└─ get_forecast.d.ts</div>
								</div>
								<p className="text-muted-foreground mt-2 text-[11px] italic">Individual .d.ts file for each tool</p>
							</div>
						)}
					</div>
				</div>
			</div>

			<div className="border-border/60 bg-card/60 sticky bottom-0 -mx-px flex flex-wrap items-center justify-end gap-2 rounded-b-2xl border-t px-4 py-3 backdrop-blur">
				<span className="text-muted-foreground mr-auto text-[11px]">
					{hasChanges ? (
						<span className="text-foreground">You have unsaved changes for this workspace.</span>
					) : settings?.is_override ? (
						<span>Workspace override saved.</span>
					) : (
						<span>Inheriting tenant defaults. Editing and saving will create a per-workspace override.</span>
					)}
				</span>
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
					<Save className="h-4 w-4" />
					{isSaving ? "Saving..." : "Save Changes"}
				</Button>
			</div>
		</div>
	);
}

function SettingRow({
	icon,
	htmlFor,
	label,
	description,
	children,
}: {
	icon: React.ReactNode;
	htmlFor?: string;
	label: string;
	description?: string;
	children: React.ReactNode;
}) {
	return (
		<div className="border-border/60 bg-card/40 flex items-center justify-between gap-3 rounded-xl border p-4">
			<div className="flex items-start gap-2.5">
				<span className="bg-muted text-muted-foreground inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg">
					{icon}
				</span>
				<div>
					<Label htmlFor={htmlFor} className="text-sm font-medium">{label}</Label>
					{description && <p className="text-muted-foreground mt-0.5 text-[11px]">{description}</p>}
				</div>
			</div>
			<div className="shrink-0">{children}</div>
		</div>
	);
}
