"use client";

import { useEffect } from "react";
import { useGetGuardrailFindingsQuery, useGetGuardrailTracesQuery } from "@/lib/store/apis";
import { useLazyGetLogByIdQuery } from "@/lib/store/apis/logsApi";
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
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdownMenu";
import { DottedSeparator } from "@/components/ui/separator";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { ProviderIconType, RenderProviderIcon, RoutingEngineUsedIcons } from "@/lib/constants/icons";
import {
	RequestTypeColors,
	RequestTypeLabels,
	RoutingEngineUsedColors,
	RoutingEngineUsedLabels,
	Status,
	StatusColors,
} from "@/lib/constants/logs";
import { GuardrailFinding, GuardrailTrace } from "@/lib/types/guardrails";
import { LogEntry } from "@/lib/types/logs";
import { Clipboard, Loader2, MoreVertical, Trash2 } from "lucide-react";
import moment from "moment";
import { toast } from "sonner";
import BlockHeader from "../views/blockHeader";
import CollapsibleBox from "../views/collapsibleBox";
import ImageView from "../views/imageView";
import LogChatMessageView from "../views/logChatMessageView";
import LogEntryDetailsView from "../views/logEntryDetailsView";
import { MarkdownText } from "@/components/markdownText";
import LogResponsesMessageView from "../views/logResponsesMessageView";
import SpeechView from "../views/speechView";
import TranscriptionView from "../views/transcriptionView";
import VideoView from "../views/videoView";
import { CodeEditor } from "@/components/ui/codeEditor";

const formatJsonSafe = (str: string | undefined): string => {
	try {
		return JSON.stringify(JSON.parse(str || ""), null, 2);
	} catch {
		return str || "";
	}
};

interface LogDetailSheetProps {
	log: LogEntry | null;
	open: boolean;
	onOpenChange: (open: boolean) => void;
	handleDelete: (log: LogEntry) => void;
}

// Helper to detect passthrough operations
const isPassthroughOperation = (object: string) =>
	object === "passthrough" || object === "passthrough_stream";

// Helper to detect container operations (for hiding irrelevant fields like Model/Tokens)
const isContainerOperation = (object: string) => {
	const containerTypes = [
		"container_create",
		"container_list",
		"container_retrieve",
		"container_delete",
		"container_file_create",
		"container_file_list",
		"container_file_retrieve",
		"container_file_content",
		"container_file_delete",
	];
	return containerTypes.includes(object?.toLowerCase());
};

const isCacheHit = (log: LogEntry) => log.cache_debug?.cache_hit === true || (log.cache_savings ?? 0) > 0;

const getDisplayedPromptTokens = (log: LogEntry) => (isCacheHit(log) ? 0 : (log.token_usage?.prompt_tokens ?? "-"));
const getDisplayedCompletionTokens = (log: LogEntry) => (isCacheHit(log) ? 0 : (log.token_usage?.completion_tokens ?? "-"));
const getDisplayedTotalTokens = (log: LogEntry) => (isCacheHit(log) ? 0 : (log.token_usage?.total_tokens ?? "-"));
const getDisplayedCost = (log: LogEntry) => {
	if (log.cost != null) {
		return `$${parseFloat(log.cost.toFixed(6))}`;
	}
	return isCacheHit(log) ? "$0" : "-";
};

const GUARDRAIL_STAGE_BADGE_CLASS: Record<string, string> = {
	input: "bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-200",
	output: "bg-violet-100 text-violet-800 dark:bg-violet-950 dark:text-violet-200",
	action: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200",
	mcp: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200",
	rag: "bg-fuchsia-100 text-fuchsia-800 dark:bg-fuchsia-950 dark:text-fuchsia-200",
};

const GUARDRAIL_DECISION_BADGE_CLASS: Record<string, string> = {
	allow: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200",
	monitor: "bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-200",
	block: "bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-200",
	redact: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200",
	sandbox: "bg-violet-100 text-violet-800 dark:bg-violet-950 dark:text-violet-200",
};

const GUARDRAIL_SEVERITY_BADGE_CLASS: Record<string, string> = {
	critical: "bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-200",
	high: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-200",
	medium: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200",
	low: "bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-200",
	info: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200",
};

const HIDDEN_LOG_METADATA_KEYS = new Set(["isAsyncRequest", "latency_breakdown_ms"]);

// Human-readable labels and colors for latency breakdown phases
const LATENCY_PHASE_CONFIG: Record<string, { label: string; color: string; order: number }> = {
	cache_lookup_direct: { label: "Cache (Direct)", color: "bg-sky-500", order: 0 },
	cache_lookup_semantic: { label: "Cache (Semantic)", color: "bg-cyan-500", order: 1 },
	coalescing_wait: { label: "Cache (Coalesced wait)", color: "bg-teal-500", order: 2 },
	guardrail_input: { label: "Guardrail (Input)", color: "bg-amber-500", order: 3 },
	guardrail_mcp: { label: "Guardrail (MCP)", color: "bg-orange-500", order: 4 },
	provider: { label: "Provider", color: "bg-indigo-500", order: 5 },
	guardrail_output: { label: "Guardrail (Output)", color: "bg-amber-600", order: 6 },
	logging_enqueue: { label: "Logging", color: "bg-slate-400", order: 7 },
	platform_overhead: { label: "Platform Overhead", color: "bg-slate-500", order: 8 },
};

function LatencyBreakdown({ breakdown }: { breakdown: Record<string, number> }) {
	const totalWall = breakdown.total_wall || 0;
	if (totalWall <= 0) return null;

	// Build sorted phase list, excluding meta keys AND every per-plugin
	// row. We surface ONE summed "Platform Overhead" line below - it
	// rolls up the gateway's internal phases (plugin_chain_pre,
	// plugin_pre_<name>, plugin_chain_post, etc.) plus the backend's
	// already-computed `platform_overhead` residual. The user only
	// needs to see "the gateway added this much"; per-plugin numbers
	// belong in trace-level diagnostics, not the per-request panel.
	const isPluginPhase = (key: string) => key === "plugin_chain_pre" || key === "plugin_chain_post" || key.startsWith("plugin_pre_") || key.startsWith("plugin_post_");
	const phases = Object.entries(breakdown)
		.filter(([key, val]) => key !== "total_wall" && key !== "platform_overhead" && !isPluginPhase(key) && val > 0)
		.sort((a, b) => (LATENCY_PHASE_CONFIG[a[0]]?.order ?? 99) - (LATENCY_PHASE_CONFIG[b[0]]?.order ?? 99));

	// Trust the backend's `platform_overhead` - it's already computed as
	// totalWall − provider − sum(every tracked phase) and clamped to ≥0
	// (see plugins/logging/main.go::stampLatencyBreakdown). Adding the
	// plugin-chain phases on top here was a double-count: plugin_chain_pre /
	// plugin_pre_* are part of `trackedNonProviderMs` on the backend, so
	// they're already subtracted from total_wall. The previous formula
	// produced overheads > wall time (e.g. wall=4ms, overhead=7ms = 175%
	// on the dashboard).
	//
	// We still cap at `totalWall − providerAndPhases` so a rounding race
	// between server-side accounting and per-phase floats never displays
	// a negative or over-100% value.
	const visiblePhaseSum = phases.reduce((acc, [, val]) => acc + val, 0);
	const provider = breakdown.provider ?? 0;
	const overheadFromBackend = breakdown.platform_overhead ?? 0;
	const overheadClampMax = Math.max(0, totalWall - provider - visiblePhaseSum);
	const platformOverhead = Math.min(overheadFromBackend, overheadClampMax);

	return (
		<div className="space-y-3">
			{/* Stacked horizontal bar */}
			<div className="flex h-5 w-full overflow-hidden rounded-md" title={`Total: ${totalWall.toLocaleString()}ms`}>
				{phases.map(([key, value]) => {
					const pct = (value / totalWall) * 100;
					if (pct < 0.5) return null;
					const config = LATENCY_PHASE_CONFIG[key];
					return (
						<div
							key={key}
							className={`${config?.color ?? "bg-gray-400"} transition-all`}
							style={{ width: `${pct}%` }}
							title={`${config?.label ?? key}: ${value.toLocaleString()}ms (${pct.toFixed(1)}%)`}
						/>
					);
				})}
			</div>
			{/* Legend + values */}
			<div className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-xs sm:grid-cols-3">
				{phases.map(([key, value]) => {
					const config = LATENCY_PHASE_CONFIG[key];
					const pct = ((value / totalWall) * 100).toFixed(1);
					return (
						<div key={key} className="flex items-center gap-2">
							<span className={`${config?.color ?? "bg-gray-400"} inline-block h-2.5 w-2.5 rounded-sm`} />
							<span className="text-muted-foreground">{config?.label ?? key}</span>
							<span className="ml-auto font-medium tabular-nums">{value.toLocaleString()}ms</span>
							<span className="text-muted-foreground tabular-nums">({pct}%)</span>
						</div>
					);
				})}
				{platformOverhead > 0 && (
					<div className="flex items-center gap-2">
						<span className="bg-slate-500 inline-block h-2.5 w-2.5 rounded-sm" />
						<span className="text-muted-foreground">Platform Overhead</span>
						<span className="ml-auto font-medium tabular-nums">{platformOverhead.toLocaleString()}ms</span>
						<span className="text-muted-foreground tabular-nums">({((platformOverhead / totalWall) * 100).toFixed(1)}%)</span>
					</div>
				)}
				<div className="col-span-full flex items-center gap-2 border-t pt-1.5">
					<span className="text-muted-foreground font-medium">Total Wall Time</span>
					<span className="ml-auto font-semibold tabular-nums">{totalWall.toLocaleString()}ms</span>
				</div>
			</div>
		</div>
	);
}

function TraceSectionLabel({ children }: { children: React.ReactNode }) {
	return (
		<div className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.14em]">{children}</div>
	);
}

function GuardrailTraceCard({ trace }: { trace: GuardrailTrace }) {
	return (
		<div className="space-y-4 rounded-xl bg-muted/30 px-4 py-3.5">
			<div className="flex flex-wrap items-center gap-2">
				<Badge variant="outline" className={(trace.stage ? GUARDRAIL_STAGE_BADGE_CLASS[trace.stage] : undefined) ?? "uppercase"}>
					{trace.stage || "unknown"}
				</Badge>
				<Badge variant="outline" className={GUARDRAIL_DECISION_BADGE_CLASS[trace.decision] ?? "uppercase"}>
					{trace.decision || "unknown"}
				</Badge>
				<span className="text-muted-foreground ml-auto text-xs">
					{moment(trace.created_at).format("YYYY-MM-DD HH:mm:ss A")}
				</span>
			</div>
			<div className="grid grid-cols-1 gap-x-6 gap-y-3 md:grid-cols-3">
				<LogEntryDetailsView className="w-full" label="Actor Type" value={trace.actor_type || "-"} />
				<LogEntryDetailsView
					className="w-full"
					label="Actor ID"
					value={<span className="font-mono text-xs">{trace.actor_id || "-"}</span>}
				/>
				<LogEntryDetailsView className="w-full" label="Provider / Model" value={`${trace.provider || "-"} / ${trace.model || "-"}`} />
			</div>
			{trace.input_summary ? (
				<div className="space-y-1.5">
					<TraceSectionLabel>Input Summary</TraceSectionLabel>
					<MarkdownText content={trace.input_summary} />
				</div>
			) : null}
			{trace.output_summary ? (
				<div className="space-y-1.5">
					<TraceSectionLabel>Output Summary</TraceSectionLabel>
					<MarkdownText content={trace.output_summary} />
				</div>
			) : null}
			{trace.decision_chain && trace.decision_chain.length > 0 ? (
				<div className="space-y-1.5">
					<TraceSectionLabel>Decision Chain</TraceSectionLabel>
					<ul className="text-sm space-y-1 list-disc pl-5 marker:text-muted-foreground">
						{trace.decision_chain.map((entry, index) => (
							<li key={`${trace.id}-decision-${index}`} className="leading-snug">
								{entry}
							</li>
						))}
					</ul>
				</div>
			) : null}
			{trace.metadata && Object.keys(trace.metadata).length > 0 ? (
				<div className="space-y-2">
					<TraceSectionLabel>Trace Metadata</TraceSectionLabel>
					<div className="grid grid-cols-1 gap-x-6 gap-y-3 md:grid-cols-3">
						{Object.entries(trace.metadata).map(([key, value]) => (
							<LogEntryDetailsView
								key={`${trace.id}-meta-${key}`}
								className="w-full"
								label={key}
								value={formatTraceMetadataValue(value)}
							/>
						))}
					</div>
				</div>
			) : null}
		</div>
	);
}

function formatTraceMetadataValue(value: unknown): React.ReactNode {
	if (value === null || value === undefined || value === "") return "-";
	if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
	if (Array.isArray(value)) {
		return value.length === 0 ? "-" : value.map((v) => formatTraceMetadataScalar(v)).join(", ");
	}
	try {
		return <span className="font-mono text-xs">{JSON.stringify(value)}</span>;
	} catch {
		return String(value);
	}
}

function formatTraceMetadataScalar(value: unknown): string {
	if (value === null || value === undefined) return "";
	if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
	try {
		return JSON.stringify(value);
	} catch {
		return String(value);
	}
}

function GuardrailFindingCard({ finding }: { finding: GuardrailFinding }) {
	return (
		<div className="space-y-3 rounded-xl bg-muted/30 px-4 py-3">
			<div className="flex flex-wrap items-center gap-2">
				<Badge variant="outline" className={GUARDRAIL_STAGE_BADGE_CLASS[finding.stage] ?? "uppercase"}>
					{finding.stage || "unknown"}
				</Badge>
				<Badge variant="outline" className={GUARDRAIL_SEVERITY_BADGE_CLASS[finding.severity] ?? "uppercase"}>
					{finding.severity || "unknown"}
				</Badge>
				<Badge variant="outline" className={GUARDRAIL_DECISION_BADGE_CLASS[finding.outcome] ?? "uppercase"}>
					{finding.outcome || "unknown"}
				</Badge>
				<span className="text-muted-foreground text-xs">{moment(finding.created_at).format("YYYY-MM-DD HH:mm:ss A")}</span>
			</div>
			<div className="grid grid-cols-1 gap-3 md:grid-cols-3">
				<LogEntryDetailsView className="w-full" label="Category" value={finding.category || "-"} />
				<LogEntryDetailsView className="w-full" label="Policy ID" value={finding.policy_id || "-"} />
				<LogEntryDetailsView className="w-full" label="Confidence" value={Number.isFinite(finding.confidence) ? finding.confidence.toFixed(2) : "-"} />
			</div>
			<div className="space-y-1">
				<div className="text-muted-foreground text-xs uppercase">Summary</div>
				<div className="text-sm whitespace-pre-wrap">{finding.summary || "-"}</div>
			</div>
			{finding.details && Object.keys(finding.details).length > 0 ? (
				<CollapsibleBox title="Finding Details" onCopy={() => JSON.stringify(finding.details, null, 2)}>
					<CodeEditor
						className="z-0 w-full"
						shouldAdjustInitialHeight={true}
						maxHeight={320}
						wrap={true}
						code={JSON.stringify(finding.details, null, 2)}
						lang="json"
						readonly={true}
						options={{ scrollBeyondLastLine: false, lineNumbers: "off", alwaysConsumeMouseWheel: false }}
					/>
				</CollapsibleBox>
			) : null}
		</div>
	);
}

export function LogDetailSheet({ log, open, onOpenChange, handleDelete }: LogDetailSheetProps) {
	const requestID = log?.id;
	const [fetchLog, { data: fullLog, isFetching }] = useLazyGetLogByIdQuery();
	const {
		data: guardrailFindings = [],
		isFetching: isGuardrailFindingsFetching,
	} = useGetGuardrailFindingsQuery(requestID ? { request_id: requestID, limit: 50 } : undefined, {
		skip: !open || !requestID,
	});
	const {
		data: guardrailTraces = [],
		isFetching: isGuardrailTracesFetching,
	} = useGetGuardrailTracesQuery(requestID ? { request_id: requestID, limit: 20 } : undefined, {
		skip: !open || !requestID,
	});

	useEffect(() => {
		if (open && log?.id) {
			fetchLog(log.id);
		}
	}, [open, log?.id, fetchLog]);

	if (!log) return null;

	// Show a loader until the full log data is fetched from the dedicated single-log endpoint.
	const isFullDataReady = fullLog?.id === log.id && !isFetching;
	const displayLog = isFullDataReady ? fullLog : log;

	const isContainer = isContainerOperation(displayLog.object);
	const isPassthrough = isPassthroughOperation(displayLog.object);
	const passthroughParams = isPassthrough
		? (displayLog.params as {
			method?: string;
			path?: string;
			raw_query?: string;
			status_code?: number;
		})
		: null;

	// Extract audio format from request params
	// Format can be in params.audio?.format or params.extra_params?.audio?.format
	const audioFormat = (displayLog.params as any)?.audio?.format || (displayLog.params as any)?.extra_params?.audio?.format || undefined;
	const rawRequest = displayLog.raw_request;
	const rawResponse = displayLog.raw_response;
	const passthroughRequestBody = displayLog.passthrough_request_body;
	const passthroughResponseBody = displayLog.passthrough_response_body;
	const videoOutput = displayLog.video_generation_output || displayLog.video_retrieve_output || displayLog.video_download_output;
	const videoListOutput = displayLog.video_list_output;
	const isGuardrailEvidenceFetching = isGuardrailFindingsFetching || isGuardrailTracesFetching;
	const hasGuardrailDetails =
		displayLog.cache_debug?.guardrail_reused === true ||
		guardrailTraces.length > 0 ||
		guardrailFindings.length > 0 ||
		isGuardrailEvidenceFetching;
	const guardrailStageValues = Array.from(
		new Set(
			[...guardrailTraces.map((trace) => trace.stage), ...guardrailFindings.map((finding) => finding.stage)]
				.filter((stage): stage is string => Boolean(stage)),
		),
	);
	const guardrailDecisionValues = Array.from(new Set(guardrailTraces.map((trace) => trace.decision).filter(Boolean)));

	return (
		<Sheet open={open} onOpenChange={onOpenChange}>
			<SheetContent className="flex w-full flex-col gap-4 overflow-x-hidden p-8 sm:max-w-[60%]">
				{!isFullDataReady ? (
					<div className="flex h-full items-center justify-center">
						<Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
					</div>
				) : (
				<>
				<SheetHeader className="flex flex-row items-center px-0">
					<div className="flex w-full items-center justify-between">
						<SheetTitle className="flex w-fit items-center gap-2 font-medium">
							{displayLog.id && (
								<p className="text-md max-w-full truncate">
									Request ID:{" "}
									<code
										className="text-normal cursor-pointer"
										onClick={() => {
											navigator.clipboard
												.writeText(displayLog.id)
												.then(() => toast.success("Request ID copied"))
												.catch(() => toast.error("Failed to copy"));
										}}
									>
										{displayLog.id}
									</code>
								</p>
							)}
							<Badge variant="outline" className={`${StatusColors[displayLog.status as Status]} uppercase`}>
								{displayLog.status}
							</Badge>
							{displayLog.metadata?.isAsyncRequest ? (
								<Badge variant="outline" className="bg-teal-100 text-teal-800 uppercase dark:bg-teal-900 dark:text-teal-200">
									Async
								</Badge>
							) : null}
							{(displayLog.is_large_payload_request || displayLog.is_large_payload_response) && (
								<Badge
									variant="outline"
									className="border-amber-300 bg-amber-50 text-amber-700 dark:border-amber-600 dark:bg-amber-950 dark:text-amber-400"
								>
									Large Payload
								</Badge>
							)}
						</SheetTitle>
					</div>
					<AlertDialog>
						<DropdownMenu>
							<DropdownMenuTrigger asChild>
								<Button variant="ghost" size="icon">
									<MoreVertical className="h-3 w-3" />
								</Button>
							</DropdownMenuTrigger>
							<DropdownMenuContent align="end">
								<DropdownMenuItem onClick={() => copyRequestBody(displayLog)} data-testid="logdetails-copy-request-body-button">
									<Clipboard className="h-4 w-4" />
									Copy request body
								</DropdownMenuItem>
								<AlertDialogTrigger asChild>
									<DropdownMenuItem variant="destructive">
										<Trash2 className="h-4 w-4" />
										Delete log
									</DropdownMenuItem>
								</AlertDialogTrigger>
							</DropdownMenuContent>
						</DropdownMenu>
						<AlertDialogContent>
							<AlertDialogHeader>
								<AlertDialogTitle>Are you sure you want to delete this log?</AlertDialogTitle>
								<AlertDialogDescription>This action cannot be undone. This will permanently delete the log entry.</AlertDialogDescription>
							</AlertDialogHeader>
							<AlertDialogFooter>
								<AlertDialogCancel>Cancel</AlertDialogCancel>
								<AlertDialogAction
									onClick={() => {
										handleDelete(displayLog);
										onOpenChange(false);
									}}
								>
									Delete
								</AlertDialogAction>
							</AlertDialogFooter>
						</AlertDialogContent>
					</AlertDialog>
				</SheetHeader>
				<div className="-mt-6 space-y-5 rounded-2xl border border-border/60 bg-card/60 px-6 py-5 shadow-[0_1px_2px_rgba(11,42,49,0.04),0_8px_18px_-12px_rgba(11,42,49,0.10)] backdrop-blur-md">
					<div className="space-y-4">
						<BlockHeader title="Timings" />
						<div className="grid w-full grid-cols-3 items-center justify-between gap-4">
							<LogEntryDetailsView
								className="w-full"
								label="Start Timestamp"
								value={moment(displayLog.timestamp).format("YYYY-MM-DD HH:mm:ss A")}
							/>
							<LogEntryDetailsView
								className="w-full"
								label="End Timestamp"
								value={moment(displayLog.timestamp)
									.add(displayLog.latency || 0, "ms")
									.format("YYYY-MM-DD HH:mm:ss A")}
							/>
							<LogEntryDetailsView
								className="w-full"
								label="Latency"
								value={isNaN(displayLog.latency || 0) ? "NA" : <div>{(displayLog.latency || 0)?.toFixed(2)}ms</div>}
							/>
						</div>
						{displayLog.metadata?.latency_breakdown_ms && (() => {
							try {
								const raw = displayLog.metadata.latency_breakdown_ms;
								const breakdown: Record<string, number> = typeof raw === "string" ? JSON.parse(raw) : raw;
								if (breakdown && typeof breakdown === "object" && breakdown.total_wall > 0) {
									return (
										<div className="mt-4 space-y-2">
											<div className="text-muted-foreground text-xs font-medium uppercase tracking-wide">Latency Breakdown</div>
											<LatencyBreakdown breakdown={breakdown} />
										</div>
									);
								}
							} catch {
								// skip if metadata isn't valid JSON
							}
							return null;
						})()}
					</div>
					<DottedSeparator />
					<div className="space-y-4">
						<BlockHeader title="Request Details" />
						<div className="grid w-full grid-cols-3 items-start justify-between gap-4">
							<LogEntryDetailsView
								className="w-full"
								label="Provider"
								value={
									<Badge variant="secondary" className={`uppercase`}>
										<RenderProviderIcon provider={displayLog.provider as ProviderIconType} size="sm" />
										{displayLog.provider}
									</Badge>
								}
							/>
							{!isContainer && <LogEntryDetailsView className="w-full" label="Model" value={displayLog.model} />}
							<LogEntryDetailsView
								className="w-full"
								label="Type"
								value={
									<div
										className={`${RequestTypeColors[displayLog.object as keyof typeof RequestTypeColors] ?? "bg-gray-100 text-gray-800"
											} rounded-sm px-3 py-1`}
									>
										{RequestTypeLabels[displayLog.object as keyof typeof RequestTypeLabels] ?? displayLog.object ?? "unknown"}
									</div>
								}
							/>
							{displayLog.selected_key && <LogEntryDetailsView className="w-full" label="Selected Key" value={displayLog.selected_key.name} />}
							{displayLog.number_of_retries > 0 && (
								<LogEntryDetailsView className="w-full" label="Number of Retries" value={displayLog.number_of_retries} />
							)}
							{displayLog.fallback_index > 0 && <LogEntryDetailsView className="w-full" label="Fallback Index" value={displayLog.fallback_index} />}
							{displayLog.virtual_key && <LogEntryDetailsView className="w-full" label="Virtual Key" value={displayLog.virtual_key.name} />}
							{displayLog.routing_engines_used && displayLog.routing_engines_used.length > 0 && (
								<LogEntryDetailsView
									className="w-full"
									label="Routing Engines Used"
									value={
										<div className="flex flex-wrap gap-2">
											{displayLog.routing_engines_used.map((engine) => (
												<Badge
													key={engine}
													className={RoutingEngineUsedColors[engine as keyof typeof RoutingEngineUsedColors] ?? "bg-gray-100 text-gray-800"}
												>
													<div className="flex items-center gap-2">
														{RoutingEngineUsedIcons[engine as keyof typeof RoutingEngineUsedIcons]?.()}
														<span>{RoutingEngineUsedLabels[engine as keyof typeof RoutingEngineUsedLabels] ?? engine}</span>
													</div>
												</Badge>
											))}
										</div>
									}
								/>
							)}
							{displayLog.routing_rule && <LogEntryDetailsView className="w-full" label="Routing Rule" value={displayLog.routing_rule.name} />}

							{/* Display audio params if present */}
							{(displayLog.params as any)?.audio && (
								<>
									{(displayLog.params as any).audio.format && (
										<LogEntryDetailsView className="w-full" label="Audio Format" value={(displayLog.params as any).audio.format} />
									)}
									{(displayLog.params as any).audio.voice && (
										<LogEntryDetailsView className="w-full" label="Audio Voice" value={(displayLog.params as any).audio.voice} />
									)}
								</>
							)}

							{/* Display passthrough params (method, path, raw_query, status_code) */}
							{passthroughParams && (
								<>
									{passthroughParams.method && (
										<LogEntryDetailsView className="w-full" label="Method" value={passthroughParams.method} />
									)}
									{passthroughParams.path && (
										<LogEntryDetailsView className="w-full" label="Path" value={passthroughParams.path} />
									)}
									{passthroughParams.raw_query && (
										<LogEntryDetailsView className="w-full" label="Query" value={passthroughParams.raw_query} />
									)}
									{(passthroughParams.status_code ?? 0) !== 0 && (
										<LogEntryDetailsView
											className="w-full"
											label="Status Code"
											value={passthroughParams.status_code}
										/>
									)}
								</>
							)}

							{displayLog.params &&
								Object.keys(displayLog.params).length > 0 &&
								Object.entries(displayLog.params)
									.filter(([key]) => {
										const passthroughKeys = ["method", "path", "raw_query", "status_code"];
										return (
											key !== "tools" &&
											key !== "instructions" &&
											key !== "audio" &&
											!(isPassthrough && passthroughKeys.includes(key))
										);
									})
									.filter(([_, value]) => typeof value === "boolean" || typeof value === "number" || typeof value === "string")
									.map(([key, value]) => <LogEntryDetailsView key={key} className="w-full" label={key} value={value} />)}
						</div>
					</div>
					{displayLog.status === "success" && !isContainer && !isPassthrough && (
						<>
							<DottedSeparator />
							<div className="space-y-4">
								<BlockHeader title="Tokens" />
								<div className="grid w-full grid-cols-3 items-center justify-between gap-4">
									<LogEntryDetailsView className="w-full" label="Input Tokens" value={getDisplayedPromptTokens(displayLog)} />
									<LogEntryDetailsView className="w-full" label="Output Tokens" value={getDisplayedCompletionTokens(displayLog)} />
									<LogEntryDetailsView className="w-full" label="Total Tokens" value={getDisplayedTotalTokens(displayLog)} />
									<LogEntryDetailsView className="w-full" label="Cost" value={getDisplayedCost(displayLog)} />
									{displayLog.token_usage?.prompt_tokens_details && (
										<>
											{(displayLog.token_usage.prompt_tokens_details.cached_read_tokens) && (
												<LogEntryDetailsView
													className="w-full"
													label="Cache Read Tokens"
													value={
														(displayLog.token_usage.prompt_tokens_details.cached_read_tokens ?? 0)
													}
												/>
											)}
											{(displayLog.token_usage.prompt_tokens_details.cached_write_tokens) && (
												<LogEntryDetailsView
													className="w-full"
													label="Cache Write Tokens"
													value={
														(displayLog.token_usage.prompt_tokens_details.cached_write_tokens ?? 0)
													}
												/>
											)}
											{typeof displayLog.prompt_cache_savings === "number" && displayLog.prompt_cache_savings !== 0 && (
												<LogEntryDetailsView
													className="w-full"
													label="Prompt Cache Saved"
													value={
														<span
															className={
																displayLog.prompt_cache_savings > 0
																	? "text-emerald-600 dark:text-emerald-400"
																	: "text-rose-600 dark:text-rose-400"
															}
														>
															{`$${displayLog.prompt_cache_savings.toFixed(4)}`}
														</span>
													}
												/>
											)}
											{displayLog.token_usage.prompt_tokens_details.audio_tokens && (
												<LogEntryDetailsView
													className="w-full"
													label="Input Audio Tokens"
													value={displayLog.token_usage.prompt_tokens_details.audio_tokens || "-"}
												/>
											)}
										</>
									)}
									{displayLog.token_usage?.completion_tokens_details && (
										<>
											{displayLog.token_usage.completion_tokens_details.reasoning_tokens && (
												<LogEntryDetailsView
													className="w-full"
													label="Reasoning Tokens"
													value={displayLog.token_usage.completion_tokens_details.reasoning_tokens || "-"}
												/>
											)}
											{displayLog.token_usage.completion_tokens_details.audio_tokens && (
												<LogEntryDetailsView
													className="w-full"
													label="Output Audio Tokens"
													value={displayLog.token_usage.completion_tokens_details.audio_tokens || "-"}
												/>
											)}
											{displayLog.token_usage.completion_tokens_details.accepted_prediction_tokens && (
												<LogEntryDetailsView
													className="w-full"
													label="Accepted Prediction Tokens"
													value={displayLog.token_usage.completion_tokens_details.accepted_prediction_tokens || "-"}
												/>
											)}
											{displayLog.token_usage.completion_tokens_details.rejected_prediction_tokens && (
												<LogEntryDetailsView
													className="w-full"
													label="Rejected Prediction Tokens"
													value={displayLog.token_usage.completion_tokens_details.rejected_prediction_tokens || "-"}
												/>
											)}
										</>
									)}
								</div>
							</div>
							{(() => {
								const params = displayLog.params as any;
								const reasoning = params?.reasoning;
								if (!reasoning || typeof reasoning !== "object" || Object.keys(reasoning).length === 0) {
									return null;
								}
								return (
									<>
										<DottedSeparator />
										<div className="space-y-4">
											<BlockHeader title="Reasoning Parameters" />
											<div className="grid w-full grid-cols-3 items-center justify-between gap-4">
												{reasoning.effort && (
													<LogEntryDetailsView
														className="w-full"
														label="Effort"
														value={
															<Badge variant="secondary" className="uppercase">
																{reasoning.effort}
															</Badge>
														}
													/>
												)}
												{reasoning.summary && (
													<LogEntryDetailsView
														className="w-full"
														label="Summary"
														value={
															<Badge variant="secondary" className="uppercase">
																{reasoning.summary}
															</Badge>
														}
													/>
												)}
												{reasoning.generate_summary && (
													<LogEntryDetailsView
														className="w-full"
														label="Generate Summary"
														value={
															<Badge variant="secondary" className="uppercase">
																{reasoning.generate_summary}
															</Badge>
														}
													/>
												)}
												{reasoning.max_tokens && <LogEntryDetailsView className="w-full" label="Max Tokens" value={reasoning.max_tokens} />}
											</div>
										</div>
									</>
								);
							})()}
							{displayLog.cache_debug && (
								<>
									<DottedSeparator />
									<div className="space-y-4">
										<BlockHeader title={`Caching Details (${displayLog.cache_debug.cache_hit ? "Hit" : "Miss"})`} />
										<div className="grid w-full grid-cols-3 items-center justify-between gap-4">
											{displayLog.cache_debug.cache_hit ? (
												<>
													<LogEntryDetailsView
														className="w-full"
														label="Cache Type"
														value={
															<Badge variant="secondary" className={`uppercase`}>
																{displayLog.cache_debug.hit_type}
															</Badge>
														}
													/>
													{displayLog.cache_debug.guardrail_reused ? (
														<LogEntryDetailsView
															className="w-full"
															label="Guardrail Runtime"
															value={<Badge variant="outline" className="bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200">Reused from Cache</Badge>}
														/>
													) : null}
													{displayLog.cache_debug.guardrail_cache_source ? (
														<LogEntryDetailsView className="w-full" label="Guardrail Cache Source" value={displayLog.cache_debug.guardrail_cache_source} />
													) : null}
													{/* <LogEntryDetailsView className="w-full" label="Cache ID" value={displayLog.cache_debug.cache_id} /> */}
													{displayLog.cache_debug.hit_type === "semantic" && (
														<>
															{displayLog.cache_debug.provider_used && (
																<LogEntryDetailsView
																	className="w-full"
																	label="Embedding Provider"
																	value={
																		<Badge variant="secondary" className={`uppercase`}>
																			{displayLog.cache_debug.provider_used}
																		</Badge>
																	}
																/>
															)}
															{displayLog.cache_debug.model_used && (
																<LogEntryDetailsView className="w-full" label="Embedding Model" value={displayLog.cache_debug.model_used} />
															)}
															{displayLog.cache_debug.threshold && (
																<LogEntryDetailsView className="w-full" label="Threshold" value={displayLog.cache_debug.threshold || "-"} />
															)}
															{displayLog.cache_debug.similarity && (
																<LogEntryDetailsView
																	className="w-full"
																	label="Similarity Score"
																	value={displayLog.cache_debug.similarity?.toFixed(2) || "-"}
																/>
															)}
															{displayLog.cache_debug.input_tokens && (
																<LogEntryDetailsView
																	className="w-full"
																	label="Embedding Input Tokens"
																	value={displayLog.cache_debug.input_tokens}
																/>
															)}
														</>
													)}
												</>
											) : (
												<>
													{displayLog.cache_debug.provider_used && (
														<LogEntryDetailsView
															className="w-full"
															label="Embedding Provider"
															value={
																<Badge variant="secondary" className={`uppercase`}>
																	{displayLog.cache_debug.provider_used}
																</Badge>
															}
														/>
													)}
													{displayLog.cache_debug.model_used && (
														<LogEntryDetailsView className="w-full" label="Embedding Model" value={displayLog.cache_debug.model_used} />
													)}
													{displayLog.cache_debug.input_tokens && (
														<LogEntryDetailsView className="w-full" label="Embedding Input Tokens" value={displayLog.cache_debug.input_tokens} />
													)}
													{displayLog.cache_debug.semantic_suppressed_reason && (
														<LogEntryDetailsView
															className="w-full"
															label="Semantic Reuse Suppressed"
															value={displayLog.cache_debug.semantic_suppressed_reason}
														/>
													)}
												</>
											)}
										</div>
									</div>
								</>
							)}
							{hasGuardrailDetails && (
								<>
									<DottedSeparator />
									<div className="space-y-4">
										<BlockHeader title="Guardrail Details" />
										{isGuardrailEvidenceFetching ? (
											<div className="flex items-center gap-2 text-sm text-muted-foreground">
												<Loader2 className="h-4 w-4 animate-spin" />
												Loading guardrail evidence...
											</div>
										) : null}
										<div className="grid w-full grid-cols-3 items-start justify-between gap-4">
											<LogEntryDetailsView className="w-full" label="Traces" value={guardrailTraces.length} />
											<LogEntryDetailsView className="w-full" label="Findings" value={guardrailFindings.length} />
											{displayLog.cache_debug?.guardrail_reused ? (
												<LogEntryDetailsView
													className="w-full"
													label="Runtime Path"
													value={<Badge variant="outline" className="bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200">Direct Cache Reuse</Badge>}
												/>
											) : (
												<LogEntryDetailsView
													className="w-full"
													label="Runtime Path"
													value={<Badge variant="outline" className="uppercase">{guardrailTraces.length > 0 || guardrailFindings.length > 0 ? "Executed" : "No Guardrail Evidence"}</Badge>}
												/>
											)}
											{guardrailStageValues.length > 0 ? (
												<LogEntryDetailsView
													className="w-full"
													label="Stages"
													value={
														<div className="flex flex-wrap gap-2">
															{guardrailStageValues.map((stage) => (
																<Badge key={stage} variant="outline" className={GUARDRAIL_STAGE_BADGE_CLASS[stage] ?? "uppercase"}>
																	{stage}
																</Badge>
															))}
														</div>
													}
												/>
											) : null}
											{guardrailDecisionValues.length > 0 ? (
												<LogEntryDetailsView
													className="w-full"
													label="Decisions"
													value={
														<div className="flex flex-wrap gap-2">
															{guardrailDecisionValues.map((decision) => (
																<Badge key={decision} variant="outline" className={GUARDRAIL_DECISION_BADGE_CLASS[decision] ?? "uppercase"}>
																	{decision}
																</Badge>
															))}
														</div>
													}
												/>
											) : null}
										</div>
										{guardrailTraces.length > 0 ? (
											<CollapsibleBox title={`Guardrail Traces (${guardrailTraces.length})`} onCopy={() => JSON.stringify(guardrailTraces, null, 2)}>
												<div className="space-y-3 px-1 py-2">
													{guardrailTraces.map((trace) => (
														<GuardrailTraceCard key={trace.id} trace={trace} />
													))}
												</div>
											</CollapsibleBox>
										) : null}
										{guardrailFindings.length > 0 ? (
											<CollapsibleBox title={`Guardrail Findings (${guardrailFindings.length})`} onCopy={() => JSON.stringify(guardrailFindings, null, 2)}>
												<div className="space-y-3 px-1 py-2">
													{guardrailFindings.map((finding) => (
														<GuardrailFindingCard key={finding.id} finding={finding} />
													))}
												</div>
											</CollapsibleBox>
										) : null}
									</div>
								</>
							)}
							{displayLog.metadata && Object.keys(displayLog.metadata).filter((key) => !HIDDEN_LOG_METADATA_KEYS.has(key)).length > 0 && (
								<>
									<DottedSeparator />
									<div className="space-y-4">
										<BlockHeader title="Metadata" />
										<div className="grid w-full grid-cols-3 items-start justify-between gap-4">
											{Object.entries(displayLog.metadata)
												.filter(([key]) => !HIDDEN_LOG_METADATA_KEYS.has(key))
												.map(([key, value]) => (
													<LogEntryDetailsView key={key} className="w-full" label={key} value={String(value)} />
												))}
										</div>
									</div>
								</>
							)}
						</>
					)}
				</div>
				{displayLog.routing_engine_logs && (
					<CollapsibleBox title="Routing Decision Logs" onCopy={() => displayLog.routing_engine_logs || ""}>
						<div className="custom-scrollbar max-h-[400px] overflow-y-auto px-6 py-2 font-mono text-xs break-words whitespace-pre-wrap">
							{displayLog.routing_engine_logs}
						</div>
					</CollapsibleBox>
				)}
				{displayLog.params?.instructions && (
					<CollapsibleBox title="Instructions" onCopy={() => displayLog.params?.instructions || ""}>
						<div className="custom-scrollbar max-h-[400px] overflow-y-auto px-6 py-2 font-mono text-xs break-words whitespace-pre-wrap">
							{displayLog.params.instructions}
						</div>
					</CollapsibleBox>
				)}

				{/* Speech and Transcription Views */}
				{(displayLog.speech_input || displayLog.speech_output) && (
					<SpeechView speechInput={displayLog.speech_input} speechOutput={displayLog.speech_output} isStreaming={displayLog.stream} />
				)}

				{(displayLog.transcription_input || displayLog.transcription_output) && (
					<TranscriptionView
						transcriptionInput={displayLog.transcription_input}
						transcriptionOutput={displayLog.transcription_output}
						isStreaming={displayLog.stream}
					/>
				)}

				{(displayLog.image_generation_input || displayLog.image_generation_output) && (
					<ImageView imageInput={displayLog.image_generation_input} imageOutput={displayLog.image_generation_output} requestType={displayLog.object} />
				)}

				{(displayLog.video_generation_input || videoOutput || videoListOutput) && (
					<VideoView
						videoInput={displayLog.video_generation_input}
						videoOutput={videoOutput}
						videoListOutput={videoListOutput}
						requestType={displayLog.object}
					/>
				)}

				{displayLog.list_models_output && (
					<CollapsibleBox
						title={`List Models Output (${displayLog.list_models_output.length})`}
						onCopy={() => JSON.stringify(displayLog.list_models_output, null, 2)}
					>
						<CodeEditor
							className="z-0 w-full"
							shouldAdjustInitialHeight={true}
							maxHeight={450}
							wrap={true}
							code={JSON.stringify(displayLog.list_models_output, null, 2)}
							lang="json"
							readonly={true}
							options={{ scrollBeyondLastLine: false, lineNumbers: "off", alwaysConsumeMouseWheel: false }}
						/>
					</CollapsibleBox>
				)}

				{/* Passthrough request body */}
				{isPassthrough && passthroughRequestBody && (() => {
					return (
						<CollapsibleBox title="Request Body" onCopy={() => {
							try {
								return JSON.stringify(JSON.parse(passthroughRequestBody || ""), null, 2);
							} catch {
								return passthroughRequestBody || "";
							}
						}}>
							<CodeEditor
								className="z-0 w-full"
								shouldAdjustInitialHeight={true}
								maxHeight={450}
								wrap={true}
								code={(() => {
									try {
										return JSON.stringify(JSON.parse(passthroughRequestBody || ""), null, 2);
									} catch {
										return passthroughRequestBody || "";
									}
								})()}
								lang="json"
								readonly={true}
								options={{ scrollBeyondLastLine: false, lineNumbers: "off", alwaysConsumeMouseWheel: false }}
							/>
						</CollapsibleBox>
					);
				})()}

				{/* Show conversation history for chat/text completions */}
				{displayLog.input_history && displayLog.input_history.length > 1 && (
					<>
						<div className="mt-4 w-full text-left text-sm font-medium">Conversation History</div>
						{displayLog.input_history.slice(0, -1).map((message, index) => (
							<LogChatMessageView key={index} message={message} audioFormat={audioFormat} />
						))}
					</>
				)}

				{/* Show input for chat/text completions */}
				{displayLog.input_history && displayLog.input_history.length > 0 && (
					<>
						<div className="mt-4 w-full text-left text-sm font-medium">Input</div>
						<LogChatMessageView message={displayLog.input_history[displayLog.input_history.length - 1]} audioFormat={audioFormat} />
					</>
				)}

				{/* Show input history for responses API */}
				{displayLog.responses_input_history && displayLog.responses_input_history.length > 0 && (
					<>
						<div className="mt-4 w-full text-left text-sm font-medium">Input</div>
						<LogResponsesMessageView messages={displayLog.responses_input_history} />
					</>
				)}

				{displayLog.is_large_payload_request && !displayLog.input_history?.length && !displayLog.responses_input_history?.length && (
					<div className="mt-4 rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:border-amber-800 dark:bg-amber-950/50 dark:text-amber-300">
						Large payload request - input content was streamed directly to the provider and is not available for display.
						{displayLog.raw_request && " A truncated preview is available in the Raw Request section below."}
					</div>
				)}

				{displayLog.is_large_payload_response && !displayLog.output_message && !displayLog.responses_output?.length && displayLog.status !== "processing" && (
					<div className="mt-4 rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:border-amber-800 dark:bg-amber-950/50 dark:text-amber-300">
						Large payload response - response content was streamed directly to the client and is not available for display.
						{displayLog.raw_response && " A truncated preview is available in the Raw Response section below."}
					</div>
				)}

				{displayLog.status !== "processing" && (
					<>
						{displayLog.output_message && !displayLog.error_details?.error.message && (
							<>
								<div className="mt-4 flex w-full items-center gap-2">
									<div className="text-sm font-medium">Response</div>
								</div>
								<LogChatMessageView message={displayLog.output_message} audioFormat={audioFormat} />
							</>
						)}
						{displayLog.responses_output && displayLog.responses_output.length > 0 && !displayLog.error_details?.error.message && (
							<>
								<div className="mt-4 w-full text-left text-sm font-medium">Response</div>
								<LogResponsesMessageView messages={displayLog.responses_output} />
							</>
						)}
						{displayLog.embedding_output && displayLog.embedding_output.length > 0 && !displayLog.error_details?.error.message && (
							<>
								<div className="mt-4 w-full text-left text-sm font-medium">Embedding</div>
								<LogChatMessageView
									message={{
										role: "assistant",
										content: JSON.stringify(
											displayLog.embedding_output.map((embedding) => embedding.embedding),
											null,
											2,
										),
									}}
								/>
							</>
						)}
						{displayLog.rerank_output && !displayLog.error_details?.error.message && (
							<>
								<CollapsibleBox
									title={`Rerank Output (${displayLog.rerank_output.length})`}
									onCopy={() => JSON.stringify(displayLog.rerank_output, null, 2)}
								>
									<CodeEditor
										className="z-0 w-full"
										shouldAdjustInitialHeight={true}
										maxHeight={450}
										wrap={true}
										code={JSON.stringify(displayLog.rerank_output, null, 2)}
										lang="json"
										readonly={true}
										options={{ scrollBeyondLastLine: false, lineNumbers: "off", alwaysConsumeMouseWheel: false }}
									/>
								</CollapsibleBox>
							</>
						)}
						{/* Passthrough response body */}
						{isPassthrough && passthroughResponseBody && (
							<CollapsibleBox
								title="Response Body"
								onCopy={() => {
									try {
										return JSON.stringify(JSON.parse(passthroughResponseBody || ""), null, 2);
									} catch {
										return passthroughResponseBody || "";
									}
								}}
							>
								<CodeEditor
									className="z-0 w-full"
									shouldAdjustInitialHeight={true}
									maxHeight={450}
									wrap={true}
									code={(() => {
										try {
											return JSON.stringify(JSON.parse(passthroughResponseBody || ""), null, 2);
										} catch {
											return passthroughResponseBody || "";
										}
									})()}
									lang="json"
									readonly={true}
									options={{ scrollBeyondLastLine: false, lineNumbers: "off", alwaysConsumeMouseWheel: false }}
								/>
							</CollapsibleBox>
						)}
						{rawRequest && (
							<>
								<div className="mt-4 w-full text-left text-sm font-medium">
									Raw Request sent to <span className="font-medium capitalize">{displayLog.provider}</span>
									{displayLog.is_large_payload_request && (
										<span className="ml-2 text-xs font-normal text-amber-600 dark:text-amber-400">(truncated preview)</span>
									)}
								</div>
								<CollapsibleBox
									title={displayLog.is_large_payload_request ? "Raw Request (Truncated)" : "Raw Request"}
									onCopy={() => formatJsonSafe(rawRequest)}
								>
									<CodeEditor
										className="z-0 w-full"
										shouldAdjustInitialHeight={true}
										maxHeight={450}
										wrap={true}
										code={formatJsonSafe(rawRequest)}
										lang="json"
										readonly={true}
										options={{ scrollBeyondLastLine: false, lineNumbers: "off", alwaysConsumeMouseWheel: false }}
									/>
								</CollapsibleBox>
							</>
						)}
						{rawResponse && (
							<>
								<div className="mt-4 w-full text-left text-sm font-medium">
									Raw Response from <span className="font-medium capitalize">{displayLog.provider}</span>
									{displayLog.is_large_payload_response && (
										<span className="ml-2 text-xs font-normal text-amber-600 dark:text-amber-400">(truncated preview)</span>
									)}
								</div>
								<CollapsibleBox
									title={displayLog.is_large_payload_response ? "Raw Response (Truncated)" : "Raw Response"}
									onCopy={() => formatJsonSafe(rawResponse)}
								>
									<CodeEditor
										className="z-0 w-full"
										shouldAdjustInitialHeight={true}
										maxHeight={450}
										wrap={true}
										code={formatJsonSafe(rawResponse)}
										lang="json"
										readonly={true}
										options={{ scrollBeyondLastLine: false, lineNumbers: "off", alwaysConsumeMouseWheel: false }}
									/>
								</CollapsibleBox>
							</>
						)}
						{displayLog.error_details?.error.message && (
							<>
								<div className="mt-4 w-full text-left text-sm font-medium">Error</div>
								<CollapsibleBox title="Error" onCopy={() => displayLog.error_details?.error.message || ""}>
									<div className="custom-scrollbar max-h-[400px] overflow-y-auto px-6 py-2 font-mono text-xs break-words whitespace-pre-wrap">
										{displayLog.error_details.error.message}
									</div>
								</CollapsibleBox>
							</>
						)}
						{displayLog.error_details?.error.error && (
							<>
								<div className="mt-4 w-full text-left text-sm font-medium">Error Details</div>
								<CollapsibleBox
									title="Details"
									onCopy={() =>
										typeof displayLog.error_details?.error.error === "string"
											? displayLog.error_details.error.error
											: JSON.stringify(displayLog.error_details?.error.error, null, 2)
									}
								>
									<div className="custom-scrollbar max-h-[400px] overflow-y-auto px-6 py-2 font-mono text-xs break-words whitespace-pre-wrap">
										{typeof displayLog.error_details?.error.error === "string"
											? displayLog.error_details.error.error
											: JSON.stringify(displayLog.error_details?.error.error, null, 2)}
									</div>
								</CollapsibleBox>
							</>
						)}
					</>
				)}
				</>
				)}
			</SheetContent>
		</Sheet>
	);
}

// Normalize log.object to canonical underscore form (handles dotted backend names like chat.completion, audio.speech)
const normalizeObjectForCopy = (object: string | undefined): string => {
	const normalized = (object?.toLowerCase() || "").replace(/\./g, "_").replace(/_chunk$/, "_stream");
	const mapping: Record<string, string> = {
		response: "responses",
		response_completion_stream: "responses_stream",
		audio_speech: "speech",
		audio_speech_stream: "speech_stream",
		audio_transcription: "transcription",
		audio_transcription_stream: "transcription_stream",
	};
	return mapping[normalized] ?? normalized;
};

const copyRequestBody = async (log: LogEntry) => {
	try {
		// Check if request is for responses, chat, speech, text completion, or embedding (exclude transcriptions)
		const object = normalizeObjectForCopy(log.object);
		const isChat = object === "chat_completion" || object === "chat_completion_stream";
		const isResponses = object === "responses" || object === "responses_stream";
		const isSpeech = object === "speech" || object === "speech_stream";
		const isTextCompletion = object === "text_completion" || object === "text_completion_stream";
		const isEmbedding = object === "embedding";
		const isTranscription = object === "transcription" || object === "transcription_stream";

		// Skip if transcription
		if (isTranscription) {
			toast.error("Copy request body is not available for transcription requests");
			return;
		}

		// Skip if not a supported request type
		if (!isChat && !isResponses && !isSpeech && !isTextCompletion && !isEmbedding) {
			toast.error("Copy request body is only available for chat, responses, speech, text completion, and embedding requests");
			return;
		}

		// Helper function to extract text content from ChatMessage
		const extractTextFromMessage = (message: any): string => {
			if (!message || !message.content) {
				return "";
			}
			if (typeof message.content === "string") {
				return message.content;
			}
			if (Array.isArray(message.content)) {
				return message.content
					.filter((block: any) => block && block.type === "text" && block.text)
					.map((block: any) => block.text || "")
					.join("");
			}
			return "";
		};

		// Helper function to extract texts from ChatMessage content blocks (for embeddings)
		const extractTextsFromMessage = (message: any): string[] => {
			if (!message || !message.content) {
				return [];
			}
			if (typeof message.content === "string") {
				return message.content ? [message.content] : [];
			}
			if (Array.isArray(message.content)) {
				return message.content.filter((block: any) => block && block.type === "text" && block.text).map((block: any) => block.text);
			}
			return [];
		};

		// Build request body following OpenAI schema
		const requestBody: any = {
			model: log.provider && log.model ? `${log.provider}/${log.model}` : log.model || "",
		};

		// Add messages/input/prompt based on request type
		if (isChat && log.input_history && log.input_history.length > 0) {
			requestBody.messages = log.input_history;
		} else if (isResponses && log.responses_input_history && log.responses_input_history.length > 0) {
			requestBody.input = log.responses_input_history;
		} else if (isSpeech && log.speech_input) {
			requestBody.input = log.speech_input.input;
		} else if (isTextCompletion && log.input_history && log.input_history.length > 0) {
			// For text completions, extract prompt from input_history
			const firstMessage = log.input_history[0];
			const prompt = extractTextFromMessage(firstMessage);
			if (prompt) {
				requestBody.prompt = prompt;
			}
		} else if (isEmbedding && log.input_history && log.input_history.length > 0) {
			// For embeddings, extract all texts from input_history
			const texts: string[] = [];
			for (const message of log.input_history) {
				const messageTexts = extractTextsFromMessage(message);
				texts.push(...messageTexts);
			}
			if (texts.length > 0) {
				// Use single string if only one text, otherwise use array
				requestBody.input = texts.length === 1 ? texts[0] : texts;
			}
		}

		// Add params (excluding tools and instructions as they're handled separately in OpenAI schema)
		if (log.params) {
			const paramsCopy = { ...log.params };
			// Remove tools and instructions from params as they're typically top-level in OpenAI schema
			// Keep all other params (temperature, max_tokens, voice, etc.)
			delete paramsCopy.tools;
			delete paramsCopy.instructions;

			// Merge remaining params into request body
			Object.assign(requestBody, paramsCopy);
		}

		// Add tools if they exist (for chat and responses) - OpenAI schema has tools at top level
		if ((isChat || isResponses) && log.params?.tools && Array.isArray(log.params.tools) && log.params.tools.length > 0) {
			requestBody.tools = log.params.tools;
		}

		// Add instructions if they exist (for responses) - OpenAI schema has instructions at top level
		if (isResponses && log.params?.instructions) {
			requestBody.instructions = log.params.instructions;
		}

		const requestBodyJson = JSON.stringify(requestBody, null, 2);
		navigator.clipboard
			.writeText(requestBodyJson)
			.then(() => {
				toast.success("Request body copied to clipboard");
			})
			.catch((error) => {
				toast.error("Failed to copy request body");
			});
	} catch (error) {
		toast.error("Failed to copy request body");
	}
};
