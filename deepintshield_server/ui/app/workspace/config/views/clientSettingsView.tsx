"use client";

import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { getErrorMessage, useGetCoreConfigQuery, useGetDroppedRequestsQuery, useUpdateCoreConfigMutation } from "@/lib/store";
import { CoreConfig, DefaultCoreConfig, DefaultGlobalHeaderFilterConfig, GlobalHeaderFilterConfig } from "@/lib/types/config";
import { cn } from "@/lib/utils";
import LargePayloadSettingsFragment from "@enterprise/components/large-payload/largePayloadSettingsFragment";
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib";
import { useGetLargePayloadConfigQuery, useUpdateLargePayloadConfigMutation } from "@enterprise/lib/store/apis/largePayloadApi";
import { DefaultLargePayloadConfig, LargePayloadConfig } from "@enterprise/lib/types/largePayload";
import {
	Filter,
	GitBranch,
	HeartPulse,
	Info,
	ListChecks,
	ListX,
	Network,
	Plus,
	ShieldAlert,
	SlidersHorizontal,
	Timer,
	X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

// Security headers that cannot be configured in allowlist/denylist
// These headers are always blocked for security reasons regardless of configuration
const SECURITY_HEADERS = [
	"proxy-authorization",
	"cookie",
	"host",
	"content-length",
	"connection",
	"transfer-encoding",
	"x-api-key",
	"x-goog-api-key",
	"x-bf-api-key",
	"x-bf-vk",
];

// Helper to check if a header is a security header
function isSecurityHeader(header: string): boolean {
	const h = header.toLowerCase().trim();
	// Wildcard patterns are not literal security headers
	if (h.includes("*")) return false;
	return SECURITY_HEADERS.includes(h);
}

// Helper to compare header filter configs
function headerFilterConfigEqual(a?: GlobalHeaderFilterConfig, b?: GlobalHeaderFilterConfig): boolean {
	const aAllowlist = a?.allowlist || [];
	const bAllowlist = b?.allowlist || [];
	const aDenylist = a?.denylist || [];
	const bDenylist = b?.denylist || [];

	if (aAllowlist.length !== bAllowlist.length || aDenylist.length !== bDenylist.length) {
		return false;
	}

	return aAllowlist.every((v, i) => v === bAllowlist[i]) && aDenylist.every((v, i) => v === bDenylist[i]);
}

// Helper to compare large payload configs
function largePayloadConfigEqual(a: LargePayloadConfig, b: LargePayloadConfig): boolean {
	return (
		a.enabled === b.enabled &&
		a.request_threshold_bytes === b.request_threshold_bytes &&
		a.response_threshold_bytes === b.response_threshold_bytes &&
		a.prefetch_size_bytes === b.prefetch_size_bytes &&
		a.max_payload_bytes === b.max_payload_bytes &&
		a.truncated_log_bytes === b.truncated_log_bytes
	);
}

export default function ClientSettingsView() {
	const hasSettingsUpdateAccess = useRbac(RbacResource.Settings, RbacOperation.Update);
	const [droppedRequests, setDroppedRequests] = useState<number>(0);
	const { data: droppedRequestsData } = useGetDroppedRequestsQuery();
	const { data: deepintshieldConfig, isLoading: isCoreConfigLoading } = useGetCoreConfigQuery({ fromDB: true });
	const config = deepintshieldConfig?.client_config;
	const [updateCoreConfig, { isLoading: isSavingCoreConfig }] = useUpdateCoreConfigMutation();
	const [localConfig, setLocalConfig] = useState<CoreConfig>(DefaultCoreConfig);

	// Large payload config state
	const { data: serverLargePayloadConfig, isLoading: isLargePayloadConfigLoading } = useGetLargePayloadConfigQuery();
	const [updateLargePayloadConfig, { isLoading: isSavingLargePayload }] = useUpdateLargePayloadConfigMutation();
	const [localLargePayloadConfig, setLocalLargePayloadConfig] = useState<LargePayloadConfig>(DefaultLargePayloadConfig);

	const isQueriesLoading = isCoreConfigLoading || isLargePayloadConfigLoading;
	const isLoading = isSavingCoreConfig || isSavingLargePayload;

	useEffect(() => {
		if (droppedRequestsData) {
			setDroppedRequests(droppedRequestsData.dropped_requests);
		}
	}, [droppedRequestsData]);

	useEffect(() => {
		if (config) {
			setLocalConfig({
				...config,
				header_filter_config: config.header_filter_config || DefaultGlobalHeaderFilterConfig,
			});
		}
	}, [config]);

	useEffect(() => {
		if (serverLargePayloadConfig) {
			setLocalLargePayloadConfig(serverLargePayloadConfig);
		}
	}, [serverLargePayloadConfig]);

	const hasCoreConfigChanges = useMemo(() => {
		if (!config) return false;
		return (
			localConfig.drop_excess_requests !== config.drop_excess_requests ||
			localConfig.enable_litellm_fallbacks !== config.enable_litellm_fallbacks ||
			localConfig.disable_db_pings_in_health !== config.disable_db_pings_in_health ||
			localConfig.async_job_result_ttl !== config.async_job_result_ttl ||
			!headerFilterConfigEqual(localConfig.header_filter_config, config.header_filter_config)
		);
	}, [config, localConfig]);

	const hasLargePayloadChanges = useMemo(() => {
		const baseline = serverLargePayloadConfig ?? DefaultLargePayloadConfig;
		return !largePayloadConfigEqual(localLargePayloadConfig, baseline);
	}, [serverLargePayloadConfig, localLargePayloadConfig]);

	const hasChanges = hasCoreConfigChanges || hasLargePayloadChanges;

	// Detect security headers in allowlist/denylist
	const invalidSecurityHeaders = useMemo(() => {
		const allowlist = localConfig.header_filter_config?.allowlist || [];
		const denylist = localConfig.header_filter_config?.denylist || [];
		const invalidInAllowlist = allowlist.filter((h) => h && isSecurityHeader(h));
		const invalidInDenylist = denylist.filter((h) => h && isSecurityHeader(h));
		return [...new Set([...invalidInAllowlist, ...invalidInDenylist])];
	}, [localConfig.header_filter_config]);

	const hasSecurityHeaderError = invalidSecurityHeaders.length > 0;

	const handleConfigChange = useCallback((field: keyof CoreConfig, value: boolean | number | string[] | GlobalHeaderFilterConfig) => {
		setLocalConfig((prev) => ({ ...prev, [field]: value }));
	}, []);

	const handleLargePayloadConfigChange = useCallback((newConfig: LargePayloadConfig) => {
		setLocalLargePayloadConfig(newConfig);
	}, []);

	const handleSave = useCallback(async () => {
		// Defense in depth - don't save if security headers are present
		if (hasSecurityHeaderError) {
			return;
		}

		// Validate large payload config if it has changes
		if (hasLargePayloadChanges) {
			const minBytes = 1024;
			if (
				localLargePayloadConfig.request_threshold_bytes < minBytes ||
				localLargePayloadConfig.response_threshold_bytes < minBytes ||
				localLargePayloadConfig.prefetch_size_bytes < minBytes ||
				localLargePayloadConfig.max_payload_bytes < minBytes ||
				localLargePayloadConfig.truncated_log_bytes < minBytes
			) {
				toast.error("All byte values must be at least 1024 (1 KB).");
				return;
			}
			if (localLargePayloadConfig.max_payload_bytes < localLargePayloadConfig.request_threshold_bytes) {
				toast.error("Max payload size must be greater than or equal to the request threshold.");
				return;
			}
			if (localLargePayloadConfig.max_payload_bytes < localLargePayloadConfig.response_threshold_bytes) {
				toast.error("Max payload size must be greater than or equal to the response threshold.");
				return;
			}
		}

		let coreConfigSaved = false;
		let largePayloadSaved = false;

		// Save core config if changed
		if (hasCoreConfigChanges) {
			if (!deepintshieldConfig) {
				toast.error("Configuration not loaded. Please refresh and try again.");
				return;
			}
			// Clean up empty strings from header filter config
			const cleanedConfig = {
				...localConfig,
				header_filter_config: {
					allowlist: (localConfig.header_filter_config?.allowlist || []).filter((h) => h && h.trim().length > 0),
					denylist: (localConfig.header_filter_config?.denylist || []).filter((h) => h && h.trim().length > 0),
				},
			};

			try {
				await updateCoreConfig({ ...deepintshieldConfig!, client_config: cleanedConfig }).unwrap();
				coreConfigSaved = true;
			} catch (error) {
				toast.error(`Failed to save core config: ${getErrorMessage(error)}`);
			}
		}

		// Save large payload config if changed
		if (hasLargePayloadChanges) {
			try {
				await updateLargePayloadConfig(localLargePayloadConfig).unwrap();
				largePayloadSaved = true;
			} catch (error) {
				toast.error(`Failed to save large payload config: ${getErrorMessage(error)}`);
			}
		}

		if (coreConfigSaved || largePayloadSaved) {
			if (largePayloadSaved) {
				toast.success("Settings updated. Large payload changes require a restart to apply.");
			} else {
				toast.success("Client settings updated successfully.");
			}
		}
	}, [
		deepintshieldConfig,
		hasSecurityHeaderError,
		hasCoreConfigChanges,
		hasLargePayloadChanges,
		localConfig,
		localLargePayloadConfig,
		updateCoreConfig,
		updateLargePayloadConfig,
	]);

	// Header filter list handlers
	const handleAddAllowlistHeader = useCallback(() => {
		setLocalConfig((prev) => ({
			...prev,
			header_filter_config: {
				...prev.header_filter_config,
				allowlist: [...(prev.header_filter_config?.allowlist || []), ""],
			},
		}));
	}, []);

	const handleRemoveAllowlistHeader = useCallback((index: number) => {
		setLocalConfig((prev) => ({
			...prev,
			header_filter_config: {
				...prev.header_filter_config,
				allowlist: (prev.header_filter_config?.allowlist || []).filter((_, i) => i !== index),
			},
		}));
	}, []);

	const handleAllowlistChange = useCallback((index: number, value: string) => {
		const lowerValue = value.toLowerCase();
		setLocalConfig((prev) => ({
			...prev,
			header_filter_config: {
				...prev.header_filter_config,
				allowlist: (prev.header_filter_config?.allowlist || []).map((h, i) => (i === index ? lowerValue : h)),
			},
		}));
	}, []);

	const handleAddDenylistHeader = useCallback(() => {
		setLocalConfig((prev) => ({
			...prev,
			header_filter_config: {
				...prev.header_filter_config,
				denylist: [...(prev.header_filter_config?.denylist || []), ""],
			},
		}));
	}, []);

	const handleRemoveDenylistHeader = useCallback((index: number) => {
		setLocalConfig((prev) => ({
			...prev,
			header_filter_config: {
				...prev.header_filter_config,
				denylist: (prev.header_filter_config?.denylist || []).filter((_, i) => i !== index),
			},
		}));
	}, []);

	const handleDenylistChange = useCallback((index: number, value: string) => {
		const lowerValue = value.toLowerCase();
		setLocalConfig((prev) => ({
			...prev,
			header_filter_config: {
				...prev.header_filter_config,
				denylist: (prev.header_filter_config?.denylist || []).map((h, i) => (i === index ? lowerValue : h)),
			},
		}));
	}, []);

	return (
		<div className="workspace-page-shell space-y-6 pb-24">
			{/* Page header */}
			<div className="space-y-1.5">
				<div className="text-muted-foreground text-[11px] font-semibold uppercase tracking-[0.18em]">Settings</div>
				<div className="flex flex-wrap items-end justify-between gap-3">
					<div>
						<h1 className="text-2xl font-semibold tracking-tight">Client Settings</h1>
						{/* <p className="text-muted-foreground text-sm">
							Configure runtime client behavior, async job retention, and which headers are forwarded to LLM providers.
						</p> */}
					</div>
					{hasChanges ? (
						<Badge variant="outline" className="border-amber-500/60 bg-amber-500/10 text-amber-700 dark:text-amber-300">
							<span className="mr-1.5 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-amber-500" />
							Unsaved changes
						</Badge>
					) : null}
				</div>
			</div>

			{/* Runtime Behavior */}
			<Card>
				<CardHeader className="pb-3">
					<CardTitle className="flex items-center gap-2 text-base">
						<SlidersHorizontal className="h-4 w-4" />
						Runtime Behavior
					</CardTitle>
					{/* <p className="text-muted-foreground text-xs">Live-toggle behavior takes effect immediately - no restart needed.</p> */}
				</CardHeader>
				<CardContent className="px-0">
					<div className="divide-border/50 divide-y">
						{/* Drop Excess Requests */}
						<SettingRow
							icon={<Filter className="h-4 w-4" />}
							htmlFor="drop-excess-requests"
							title="Drop Excess Requests"
							description={
								<>
									If enabled, DeepIntShield will drop requests that exceed pool capacity.{" "}
									{localConfig.drop_excess_requests && droppedRequests > 0 ? (
										<span className="text-amber-700 dark:text-amber-300">
											Dropped <b>{droppedRequests}</b> requests since last restart.
										</span>
									) : null}
								</>
							}
							control={
								<Switch
									id="drop-excess-requests"
									size="md"
									checked={localConfig.drop_excess_requests}
									onCheckedChange={(checked) => handleConfigChange("drop_excess_requests", checked)}
									disabled={!hasSettingsUpdateAccess}
								/>
							}
						/>

						{/* Enable LiteLLM Fallbacks */}
						<SettingRow
							icon={<GitBranch className="h-4 w-4" />}
							htmlFor="enable-litellm-fallbacks"
							title="Enable LiteLLM Fallbacks"
							description={
								<>
									Enable litellm-specific fallbacks.{" "}
									{/* <a
										className="text-primary underline-offset-2 hover:underline"
										href="https://deepintshield.com"
										target="_blank"
										rel="noopener noreferrer"
										data-testid="litellm-docs-link"
									>
										Learn more
									</a> */}
								</>
							}
							control={
								<Switch
									id="enable-litellm-fallbacks"
									size="md"
									checked={localConfig.enable_litellm_fallbacks}
									onCheckedChange={(checked) => handleConfigChange("enable_litellm_fallbacks", checked)}
									disabled={!hasSettingsUpdateAccess}
								/>
							}
						/>

						{/* Disable DB Pings */}
						<SettingRow
							icon={<HeartPulse className="h-4 w-4" />}
							htmlFor="disable-db-pings-in-health"
							title="Disable DB Pings in Health Check"
							description="If enabled, the /health endpoint will skip database connectivity checks and return OK immediately."
							control={
								<Switch
									id="disable-db-pings-in-health"
									size="md"
									checked={localConfig.disable_db_pings_in_health}
									onCheckedChange={(checked) => handleConfigChange("disable_db_pings_in_health", checked)}
									disabled={!hasSettingsUpdateAccess}
								/>
							}
						/>

						{/* Async Job Result TTL */}
						<SettingRow
							icon={<Timer className="h-4 w-4" />}
							htmlFor="async-job-result-ttl"
							title="Async Job Result TTL"
							description="Time-to-live for async job results in seconds. Results are automatically cleaned up after expiry."
							control={
								<div className="flex items-center gap-2">
									<Input
										id="async-job-result-ttl"
										type="number"
										min={1}
										className="w-28 text-right"
										value={localConfig.async_job_result_ttl}
										onChange={(e) => handleConfigChange("async_job_result_ttl", parseInt(e.target.value) || 0)}
										disabled={!hasSettingsUpdateAccess}
										data-testid="client-settings-async-job-result-ttl-input"
									/>
									<span className="text-muted-foreground text-xs">sec</span>
								</div>
							}
						/>
					</div>
				</CardContent>
			</Card>

			{/* Header Forwarding */}
			<Card>
				<CardHeader className="pb-3">
					<CardTitle className="flex items-center gap-2 text-base">
						<Network className="h-4 w-4" />
						Header Forwarding
					</CardTitle>
					<p className="text-muted-foreground text-xs">Control which extra headers are forwarded to LLM providers.</p>
				</CardHeader>
				<CardContent className="space-y-5">
					<Accordion type="multiple" className="w-full rounded-xl border bg-muted/20 px-4">
						<AccordionItem value="about-extra-headers" className="border-b-0">
							<AccordionTrigger>
								<span className="flex items-center gap-2 text-sm">
									<Info className="text-muted-foreground h-4 w-4" />
									About Header Forwarding
								</span>
							</AccordionTrigger>
							<AccordionContent className="space-y-3">
								<div>
									<p className="mb-2 font-medium">Two ways to forward headers:</p>
									<ul className="text-muted-foreground list-inside list-disc space-y-1 text-sm">
										<li>
											<span className="font-medium">Prefixed headers:</span> Use{" "}
											<code className="bg-muted rounded px-1 py-0.5 font-mono text-xs">x-bf-eh-*</code> prefix. For example,{" "}
											<code className="bg-muted rounded px-1 py-0.5 font-mono text-xs">x-bf-eh-custom-id</code> is forwarded as{" "}
											<code className="bg-muted rounded px-1 py-0.5 font-mono text-xs">custom-id</code>.
										</li>
										<li>
											<span className="font-medium">Direct headers:</span> Any header explicitly added to the allowlist can be forwarded
											directly without the prefix (e.g.,{" "}
											<code className="bg-muted rounded px-1 py-0.5 font-mono text-xs">anthropic-beta</code>).
										</li>
									</ul>
								</div>
								<div>
									<p className="mb-2 font-medium">How allowlist and denylist work:</p>
									<ul className="text-muted-foreground list-inside list-disc space-y-1 text-sm">
										<li>
											<span className="font-medium">Allowlist empty:</span> Only{" "}
											<code className="bg-muted rounded px-1 py-0.5 font-mono text-xs">x-bf-eh-*</code> prefixed headers are forwarded
											(default behavior)
										</li>
										<li>
											<span className="font-medium">Allowlist configured:</span> Prefixed headers filtered by allowlist, plus any direct
											header in the allowlist is forwarded
										</li>
										<li>
											<span className="font-medium">Denylist:</span> Headers in the denylist are always blocked from forwarding
										</li>
										<li>
											<span className="font-medium">Wildcards:</span> Use{" "}
											<code className="bg-muted rounded px-1 py-0.5 font-mono text-xs">*</code> at the end of a pattern to match prefixes
											(e.g., <code className="bg-muted rounded px-1 py-0.5 font-mono text-xs">anthropic-*</code> matches all headers
											starting with <code className="bg-muted rounded px-1 py-0.5 font-mono text-xs">anthropic-</code>). Use{" "}
											<code className="bg-muted rounded px-1 py-0.5 font-mono text-xs">*</code> alone to match all headers.
										</li>
									</ul>
								</div>
								<div>
									<p className="mb-2 font-medium">Important:</p>
									<ul className="text-muted-foreground list-inside list-disc space-y-1 text-sm">
										<li>
											Allowlist/denylist entries should be the header name <span className="font-medium">without</span> the{" "}
											<code className="bg-muted rounded px-1 py-0.5 font-mono text-xs">x-bf-eh-</code> prefix
										</li>
										<li>
											Example: To allow <code className="bg-muted rounded px-1 py-0.5 font-mono text-xs">x-bf-eh-custom-id</code> or
											direct <code className="bg-muted rounded px-1 py-0.5 font-mono text-xs">custom-id</code>, add{" "}
											<code className="bg-muted rounded px-1 py-0.5 font-mono text-xs">custom-id</code> to the allowlist
										</li>
									</ul>
								</div>
							</AccordionContent>
						</AccordionItem>

						<AccordionItem value="security-note" className="border-b-0">
							<AccordionTrigger>
								<span className="flex items-center gap-2 text-sm">
									<ShieldAlert className="h-4 w-4 text-amber-600 dark:text-amber-400" />
									Security Note
								</span>
							</AccordionTrigger>
							<AccordionContent>
								<p className="text-sm">
									Some headers are always blocked for security reasons regardless of configuration. These headers cannot be added to the
									allowlist or denylist:
								</p>
								<p className="text-muted-foreground mt-2 flex flex-wrap gap-1.5 font-mono text-xs">
									{SECURITY_HEADERS.map((h) => (
										<span key={h} className="bg-muted rounded px-1.5 py-0.5">
											{h}
										</span>
									))}
								</p>
							</AccordionContent>
						</AccordionItem>
					</Accordion>

					{/* Allowlist Section */}
					<HeaderListSection
						icon={<ListChecks className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />}
						title="Allowlist"
						description={
							<>
								Headers to allow. Enter names without the <code className="bg-muted rounded px-1 font-mono">x-bf-eh-</code> prefix. Any
								header in this list can also be sent directly without the prefix.
							</>
						}
						headers={localConfig.header_filter_config?.allowlist || []}
						placeholder="e.g. anthropic-*, custom-id"
						onChange={handleAllowlistChange}
						onAdd={handleAddAllowlistHeader}
						onRemove={handleRemoveAllowlistHeader}
						isSecurityHeader={isSecurityHeader}
						disabled={!hasSettingsUpdateAccess}
						testId="header-filter-allowlist-input"
					/>

					{/* Denylist Section */}
					<HeaderListSection
						icon={<ListX className="h-4 w-4 text-rose-600 dark:text-rose-400" />}
						title="Denylist"
						description={
							<>
								Headers to block. Enter names without the <code className="bg-muted rounded px-1 font-mono">x-bf-eh-</code> prefix. Applies
								to both prefixed and direct header forwarding.
							</>
						}
						headers={localConfig.header_filter_config?.denylist || []}
						placeholder="e.g. x-internal-*"
						onChange={handleDenylistChange}
						onAdd={handleAddDenylistHeader}
						onRemove={handleRemoveDenylistHeader}
						isSecurityHeader={isSecurityHeader}
						disabled={!hasSettingsUpdateAccess}
						testId="header-filter-denylist-input"
					/>
				</CardContent>
			</Card>

			{/* Large Payload Optimization - Enterprise only */}
			<LargePayloadSettingsFragment
				config={localLargePayloadConfig}
				onConfigChange={handleLargePayloadConfigChange}
				controlsDisabled={isLoading || !hasSettingsUpdateAccess}
			/>

			{/* Sticky save bar */}
			<div className="bg-background/85 sticky bottom-0 -mx-2 mt-4 flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-border/70 px-4 py-3 backdrop-blur-md shadow-[0_-4px_18px_-12px_rgba(11,42,49,0.18)]">
				<div className="text-muted-foreground text-xs">
					{hasChanges ? (
						<span className="text-foreground">You have unsaved changes.</span>
					) : (
						<span>All changes saved.</span>
					)}
				</div>
				{hasSecurityHeaderError ? (
					<Tooltip>
						<TooltipTrigger asChild>
							<span>
								<Button disabled>{isLoading ? "Saving..." : "Save Changes"}</Button>
							</span>
						</TooltipTrigger>
						<TooltipContent>
							Remove security header{invalidSecurityHeaders.length > 1 ? "s" : ""}: {invalidSecurityHeaders.join(", ")}
						</TooltipContent>
					</Tooltip>
				) : (
					<Button onClick={handleSave} disabled={!hasChanges || isLoading || isQueriesLoading || !hasSettingsUpdateAccess}>
						{isLoading ? "Saving..." : "Save Changes"}
					</Button>
				)}
			</div>
		</div>
	);
}

// SettingRow renders a single Switch/Input row inside the Runtime
// Behavior card. Keeps the leading icon, label + description, and the
// control (Switch or Input) on a consistent baseline so the card reads
// as a clean stack.
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
			<div className="flex items-start gap-3 min-w-0 flex-1">
				<span className="text-muted-foreground mt-0.5 inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-border/60 bg-muted/50">
					{icon}
				</span>
				<div className="min-w-0 space-y-0.5">
					<label htmlFor={htmlFor} className="block text-sm font-medium text-foreground">
						{title}
					</label>
					<p className="text-muted-foreground text-xs leading-relaxed">{description}</p>
				</div>
			</div>
			<div className="flex shrink-0 items-center pt-0.5">{control}</div>
		</div>
	);
}

// HeaderListSection renders the Allowlist / Denylist editor - title +
// helper copy + either an empty-state CTA or the list of inputs. Keeps
// the visual treatment identical between the two lists by parameterising
// just the icon, title, and handlers.
function HeaderListSection({
	icon,
	title,
	description,
	headers,
	placeholder,
	onChange,
	onAdd,
	onRemove,
	isSecurityHeader,
	disabled,
	testId,
}: {
	icon: React.ReactNode;
	title: string;
	description: React.ReactNode;
	headers: string[];
	placeholder: string;
	onChange: (index: number, value: string) => void;
	onAdd: () => void;
	onRemove: (index: number) => void;
	isSecurityHeader: (h: string) => boolean;
	disabled: boolean;
	testId: string;
}) {
	const isEmpty = headers.length === 0;
	return (
		<div className="space-y-3">
			<div className="space-y-1">
				<h4 className="flex items-center gap-2 text-sm font-medium">
					{icon}
					{title}
					<Badge variant="secondary" className="ml-auto font-mono text-[10px]">
						{headers.length}
					</Badge>
				</h4>
				<p className="text-muted-foreground text-xs">{description}</p>
			</div>

			{isEmpty ? (
				<div className="flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-border/70 bg-muted/20 px-4 py-6 text-center">
					<p className="text-muted-foreground text-xs">No headers configured.</p>
					<Button type="button" variant="outline" size="sm" onClick={onAdd} disabled={disabled}>
						<Plus className="mr-1.5 h-4 w-4" />
						Add Header
					</Button>
				</div>
			) : (
				<div className="space-y-2">
					{headers.map((header, index) => (
						<div key={index} className="flex items-center gap-2">
							<Input
								placeholder={placeholder}
								data-testid={testId}
								className={cn(
									"font-mono lowercase",
									isSecurityHeader(header) &&
										"border-destructive focus:border-destructive focus-visible:border-destructive focus-visible:ring-destructive/50",
								)}
								value={header}
								onChange={(e) => onChange(index, e.target.value)}
								disabled={disabled}
							/>
							<Button
								type="button"
								variant="ghost"
								size="icon"
								onClick={() => onRemove(index)}
								className="text-muted-foreground hover:text-destructive"
								disabled={disabled}
							>
								<X className="h-4 w-4" />
							</Button>
						</div>
					))}
					<Button type="button" variant="outline" size="sm" onClick={onAdd} disabled={disabled}>
						<Plus className="mr-2 h-4 w-4" />
						Add Header
					</Button>
				</div>
			)}
		</div>
	);
}
