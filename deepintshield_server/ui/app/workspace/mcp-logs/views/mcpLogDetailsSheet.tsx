"use client";

import BlockHeader from "@/app/workspace/logs/views/blockHeader";
import CollapsibleBox from "@/app/workspace/logs/views/collapsibleBox";
import LogEntryDetailsView from "@/app/workspace/logs/views/logEntryDetailsView";
import { MarkdownText } from "@/components/markdownText";
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
import { CodeEditor } from "@/components/ui/codeEditor";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdownMenu";
import { DottedSeparator } from "@/components/ui/separator";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Status, StatusColors, Statuses } from "@/lib/constants/logs";
import { useGetGuardrailFindingsQuery, useGetGuardrailTracesQuery } from "@/lib/store";
import type { GuardrailFinding, GuardrailTrace } from "@/lib/types/guardrails";
import type { MCPToolLogEntry } from "@/lib/types/logs";
import { Loader2, MoreVertical, Trash2 } from "lucide-react";
import moment from "moment";
import { useMemo, useState } from "react";
import { toast } from "sonner";

interface MCPLogDetailSheetProps {
	log: MCPToolLogEntry | null;
	open: boolean;
	onOpenChange: (open: boolean) => void;
	handleDelete: (log: MCPToolLogEntry) => Promise<void>;
}

// Hidden from the generic Metadata grid because they're rendered specially elsewhere.
const HIDDEN_LOG_METADATA_KEYS = new Set(["isAsyncRequest", "latency_breakdown_ms"]);

// Mirrors the AI Logs latency phase config so MCP logs render the same breakdown bar.
const LATENCY_PHASE_CONFIG: Record<string, { label: string; color: string; order: number }> = {
	cache_lookup_direct: { label: "Cache (Direct)", color: "bg-sky-500", order: 0 },
	cache_lookup_semantic: { label: "Cache (Semantic)", color: "bg-cyan-500", order: 1 },
	guardrail_input: { label: "Guardrail (Input)", color: "bg-amber-500", order: 2 },
	guardrail_mcp: { label: "Guardrail (MCP)", color: "bg-orange-500", order: 3 },
	mcp_tool_call: { label: "MCP Tool", color: "bg-indigo-500", order: 4 },
	provider: { label: "Provider", color: "bg-indigo-500", order: 4 },
	guardrail_output: { label: "Guardrail (Output)", color: "bg-amber-600", order: 5 },
	logging_enqueue: { label: "Logging", color: "bg-slate-400", order: 6 },
	platform_overhead: { label: "Platform Overhead", color: "bg-slate-500", order: 7 },
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
	deny: "bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-200",
	redact: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200",
	allow_with_redaction: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200",
	sandbox: "bg-violet-100 text-violet-800 dark:bg-violet-950 dark:text-violet-200",
};

const GUARDRAIL_SEVERITY_BADGE_CLASS: Record<string, string> = {
	critical: "bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-200",
	high: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-200",
	medium: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200",
	low: "bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-200",
	info: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200",
};

const getValidatedStatus = (status: string): Status => {
	if (Statuses.includes(status as Status)) {
		return status as Status;
	}
	return "processing";
};

function LatencyBreakdown({ breakdown }: { breakdown: Record<string, number> }) {
	const totalWall = breakdown.total_wall || 0;
	if (totalWall <= 0) return null;

	const phases = Object.entries(breakdown)
		.filter(([key, val]) => key !== "total_wall" && key !== "platform_overhead" && typeof val === "number" && val > 0)
		.sort((a, b) => (LATENCY_PHASE_CONFIG[a[0]]?.order ?? 99) - (LATENCY_PHASE_CONFIG[b[0]]?.order ?? 99));

	const platformOverhead = breakdown.platform_overhead ?? 0;

	return (
		<div className="space-y-3">
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

function parseLatencyBreakdown(metadata: Record<string, string> | undefined): Record<string, number> | null {
	if (!metadata) return null;
	const raw = metadata.latency_breakdown_ms;
	if (raw === undefined || raw === null) return null;
	try {
		const parsed = typeof raw === "string" ? JSON.parse(raw) : raw;
		if (parsed && typeof parsed === "object" && typeof (parsed as Record<string, number>).total_wall === "number") {
			return parsed as Record<string, number>;
		}
	} catch {
		// fall through
	}
	return null;
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
				<LogEntryDetailsView
					className="w-full"
					label="Confidence"
					value={Number.isFinite(finding.confidence) ? finding.confidence.toFixed(2) : "-"}
				/>
			</div>
			<div className="space-y-1">
				<div className="text-muted-foreground text-xs uppercase">Summary</div>
				<div className="text-sm whitespace-pre-wrap">{finding.summary || "-"}</div>
			</div>
		</div>
	);
}

export function MCPLogDetailSheet({ log, open, onOpenChange, handleDelete }: MCPLogDetailSheetProps) {
	const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);

	// MCP guardrail traces are persisted against the gateway request ID, which is the MCP log's
	// own `id`. For agent-mode tool calls the parent LLM request ID is also kept on the log; we
	// merge both result sets so the drawer shows evidence from either path.
	const traceQueryId = log?.id;
	const fallbackTraceQueryId = log?.llm_request_id && log.llm_request_id !== log.id ? log.llm_request_id : undefined;

	const { data: primaryTraces = [], isFetching: isPrimaryTracesFetching } = useGetGuardrailTracesQuery(
		traceQueryId ? { request_id: traceQueryId, limit: 20 } : undefined,
		{ skip: !open || !traceQueryId },
	);
	const { data: secondaryTraces = [], isFetching: isSecondaryTracesFetching } = useGetGuardrailTracesQuery(
		fallbackTraceQueryId ? { request_id: fallbackTraceQueryId, limit: 20 } : undefined,
		{ skip: !open || !fallbackTraceQueryId },
	);
	const { data: primaryFindings = [], isFetching: isPrimaryFindingsFetching } = useGetGuardrailFindingsQuery(
		traceQueryId ? { request_id: traceQueryId, limit: 50 } : undefined,
		{ skip: !open || !traceQueryId },
	);
	const { data: secondaryFindings = [], isFetching: isSecondaryFindingsFetching } = useGetGuardrailFindingsQuery(
		fallbackTraceQueryId ? { request_id: fallbackTraceQueryId, limit: 50 } : undefined,
		{ skip: !open || !fallbackTraceQueryId },
	);

	const guardrailTraces = useMemo(() => [...primaryTraces, ...secondaryTraces], [primaryTraces, secondaryTraces]);
	const guardrailFindings = useMemo(() => [...primaryFindings, ...secondaryFindings], [primaryFindings, secondaryFindings]);
	const isGuardrailEvidenceFetching =
		isPrimaryTracesFetching || isSecondaryTracesFetching || isPrimaryFindingsFetching || isSecondaryFindingsFetching;

	const guardrailStageValues = useMemo(() => {
		const set = new Set<string>();
		for (const t of guardrailTraces) if (t.stage) set.add(t.stage);
		return Array.from(set);
	}, [guardrailTraces]);
	const guardrailDecisionValues = useMemo(() => {
		const set = new Set<string>();
		for (const t of guardrailTraces) if (t.decision) set.add(t.decision);
		return Array.from(set);
	}, [guardrailTraces]);

	if (!log) return null;

	const validatedStatus = getValidatedStatus(log.status);
	const latencyBreakdown = parseLatencyBreakdown(log.metadata);
	const isCostValid = typeof log.cost === "number" && Number.isFinite(log.cost);
	const visibleMetadataEntries = log.metadata
		? Object.entries(log.metadata).filter(([key]) => !HIDDEN_LOG_METADATA_KEYS.has(key))
		: [];
	const hasGuardrailEvidence = guardrailTraces.length > 0 || guardrailFindings.length > 0 || !!log.guardrail_status;
	const hasCacheData = log.cache_hit !== undefined && log.cache_hit !== null;

	return (
		<Sheet open={open} onOpenChange={onOpenChange}>
			<SheetContent className="flex w-full flex-col gap-4 overflow-x-hidden p-8 sm:max-w-[60%]">
				<SheetHeader className="flex flex-row items-center px-0">
					<div className="flex w-full items-center justify-between">
						<SheetTitle className="flex w-fit items-center gap-2 font-medium">
							{log.id && <p className="text-md max-w-full truncate">Request ID: {log.id}</p>}
							<Badge variant="outline" className={`${StatusColors[validatedStatus]} uppercase`}>
								{log.status}
							</Badge>
						</SheetTitle>
					</div>
					<AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
						<DropdownMenu>
							<DropdownMenuTrigger asChild>
								<Button variant="ghost" size="icon">
									<MoreVertical className="h-3 w-3" />
								</Button>
							</DropdownMenuTrigger>
							<DropdownMenuContent align="end">
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
									onClick={async (e) => {
										e.preventDefault();
										try {
											await handleDelete(log);
											setDeleteDialogOpen(false);
											onOpenChange(false);
										} catch (err) {
											const errorMessage = err instanceof Error ? err.message : "Failed to delete log";
											toast.error(errorMessage);
										}
									}}
								>
									Delete
								</AlertDialogAction>
							</AlertDialogFooter>
						</AlertDialogContent>
					</AlertDialog>
				</SheetHeader>

				<div className="space-y-5 rounded-2xl border border-border/60 bg-card/60 px-6 py-5 shadow-[0_1px_2px_rgba(11,42,49,0.04),0_8px_18px_-12px_rgba(11,42,49,0.10)] backdrop-blur-md">
					{/* Timings */}
					<div className="space-y-4">
						<BlockHeader title="Timings" />
						<div className="grid w-full grid-cols-3 items-center justify-between gap-4">
							<LogEntryDetailsView
								className="w-full"
								label="Start Timestamp"
								value={moment(log.timestamp).format("YYYY-MM-DD HH:mm:ss A")}
							/>
							<LogEntryDetailsView
								className="w-full"
								label="End Timestamp"
								value={moment(log.timestamp).add(log.latency || 0, "ms").format("YYYY-MM-DD HH:mm:ss A")}
							/>
							<LogEntryDetailsView
								className="w-full"
								label="Latency"
								value={typeof log.latency === "number" ? `${log.latency.toFixed(2)}ms` : "NA"}
							/>
						</div>
						{latencyBreakdown && (
							<div className="mt-4 space-y-2">
								<div className="text-muted-foreground text-xs font-medium uppercase tracking-wide">Latency Breakdown</div>
								<LatencyBreakdown breakdown={latencyBreakdown} />
							</div>
						)}
					</div>

					<DottedSeparator />

					{/* Request Details */}
					<div className="space-y-4">
						<BlockHeader title="Request Details" />
						<div className="grid w-full grid-cols-3 items-start justify-between gap-4">
							<LogEntryDetailsView
								className="w-full"
								label="Type"
								value={
									<Badge variant="outline" className="bg-violet-100 text-violet-800 dark:bg-violet-950 dark:text-violet-200">
										Tool Call
									</Badge>
								}
							/>
							<LogEntryDetailsView
								className="w-full"
								label="Status"
								value={
									<Badge variant="outline" className={`${StatusColors[validatedStatus]} uppercase`}>
										{log.status}
									</Badge>
								}
							/>
							<LogEntryDetailsView
								className="w-full"
								label="Tool Name"
								value={<span className="font-mono text-sm">{log.tool_name}</span>}
							/>
							<LogEntryDetailsView
								className="w-full"
								label="Server"
								value={
									log.server_label ? (
										<Badge variant="secondary" className="font-mono">
											{log.server_label}
										</Badge>
									) : (
										"-"
									)
								}
							/>
							{(log.virtual_key || log.virtual_key_name) && (
								<LogEntryDetailsView
									className="w-full"
									label="Virtual Key"
									value={log.virtual_key?.name ?? log.virtual_key_name ?? "-"}
								/>
							)}
							{log.virtual_key?.team?.name && (
								<LogEntryDetailsView className="w-full" label="Team" value={log.virtual_key.team.name} />
							)}
							{log.virtual_key_id && (
								<LogEntryDetailsView
									className="w-full"
									label="Virtual Key ID"
									value={<span className="font-mono text-xs">{log.virtual_key_id}</span>}
								/>
							)}
							{log.llm_request_id && (
								<LogEntryDetailsView
									className="col-span-3 w-full"
									label="LLM Request ID"
									value={<span className="font-mono text-xs">{log.llm_request_id}</span>}
								/>
							)}
						</div>
					</div>

					{isCostValid && (
						<>
							<DottedSeparator />
							<div className="space-y-4">
								<BlockHeader title="Cost" />
								<div className="grid w-full grid-cols-3 items-center justify-between gap-4">
									<LogEntryDetailsView className="w-full" label="Cost" value={`$${log.cost!.toFixed(4)}`} />
								</div>
							</div>
						</>
					)}

					{hasCacheData && (
						<>
							<DottedSeparator />
							<div className="space-y-4">
								<BlockHeader title={`Caching Details (${log.cache_hit ? "Hit" : "Miss"})`} />
								<div className="grid w-full grid-cols-3 items-center justify-between gap-4">
									<LogEntryDetailsView
										className="w-full"
										label="Result"
										value={
											<Badge
												variant="outline"
												className={
													log.cache_hit
														? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200"
														: "uppercase"
												}
											>
												{log.cache_hit ? "Hit" : "Miss"}
											</Badge>
										}
									/>
									<LogEntryDetailsView className="w-full" label="Scope" value="Virtual Key" />
								</div>
							</div>
						</>
					)}

					{hasGuardrailEvidence && (
						<>
							<DottedSeparator />
							<div className="space-y-4">
								<BlockHeader title="Guardrail Details" />
								{isGuardrailEvidenceFetching && (
									<div className="flex items-center gap-2 text-sm text-muted-foreground">
										<Loader2 className="h-4 w-4 animate-spin" />
										Loading guardrail evidence...
									</div>
								)}
								<div className="grid w-full grid-cols-3 items-start justify-between gap-4">
									<LogEntryDetailsView
										className="w-full"
										label="Status"
										value={
											log.guardrail_status ? (
												<Badge
													variant="outline"
													className={GUARDRAIL_DECISION_BADGE_CLASS[log.guardrail_status] ?? "uppercase"}
												>
													{log.guardrail_status}
												</Badge>
											) : (
												"-"
											)
										}
									/>
									<LogEntryDetailsView className="w-full" label="Traces" value={guardrailTraces.length} />
									<LogEntryDetailsView className="w-full" label="Findings" value={guardrailFindings.length} />
									{guardrailStageValues.length > 0 && (
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
									)}
									{guardrailDecisionValues.length > 0 && (
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
									)}
								</div>
								{guardrailTraces.length > 0 && (
									<CollapsibleBox
										title={`Guardrail Traces (${guardrailTraces.length})`}
										onCopy={() => JSON.stringify(guardrailTraces, null, 2)}
									>
										<div className="space-y-3 px-1 py-2">
											{guardrailTraces.map((trace) => (
												<GuardrailTraceCard key={trace.id} trace={trace} />
											))}
										</div>
									</CollapsibleBox>
								)}
								{guardrailFindings.length > 0 && (
									<CollapsibleBox
										title={`Guardrail Findings (${guardrailFindings.length})`}
										onCopy={() => JSON.stringify(guardrailFindings, null, 2)}
									>
										<div className="space-y-3 px-1 py-2">
											{guardrailFindings.map((finding) => (
												<GuardrailFindingCard key={finding.id} finding={finding} />
											))}
										</div>
									</CollapsibleBox>
								)}
							</div>
						</>
					)}

					{visibleMetadataEntries.length > 0 && (
						<>
							<DottedSeparator />
							<div className="space-y-4">
								<BlockHeader title="Metadata" />
								<div className="grid w-full grid-cols-3 items-start justify-between gap-4">
									{visibleMetadataEntries.map(([key, value]) => (
										<LogEntryDetailsView key={key} className="w-full" label={key} value={String(value)} />
									))}
								</div>
							</div>
						</>
					)}
				</div>

				{/* Arguments */}
				{log.arguments && (
					<div className="w-full rounded-sm border">
						<div className="border-b px-6 py-2 text-sm font-medium">Arguments</div>
						<CodeEditor
							className="z-0 w-full"
							shouldAdjustInitialHeight={true}
							maxHeight={250}
							wrap={true}
							code={typeof log.arguments === "string" ? log.arguments : JSON.stringify(log.arguments as Record<string, unknown>, null, 2)}
							lang="json"
							readonly={true}
							options={{ scrollBeyondLastLine: false, collapsibleBlocks: true, lineNumbers: "off", alwaysConsumeMouseWheel: false }}
						/>
					</div>
				)}

				{/* Result */}
				{log.result && log.status !== "processing" && (
					<div className="w-full rounded-sm border">
						<div className="border-b px-6 py-2 text-sm font-medium">Result</div>
						<CodeEditor
							className="z-0 w-full"
							shouldAdjustInitialHeight={true}
							maxHeight={350}
							wrap={true}
							code={typeof log.result === "string" ? log.result : JSON.stringify(log.result, null, 2)}
							lang="json"
							readonly={true}
							options={{ scrollBeyondLastLine: false, collapsibleBlocks: true, lineNumbers: "off", alwaysConsumeMouseWheel: false }}
						/>
					</div>
				)}

				{/* Error Details */}
				{log.error_details && (
					<div className="border-destructive/50 w-full rounded-sm border">
						<div className="border-destructive/50 text-destructive border-b px-6 py-2 text-sm font-medium">Error Details</div>
						<CodeEditor
							className="z-0 w-full"
							shouldAdjustInitialHeight={true}
							maxHeight={250}
							wrap={true}
							code={JSON.stringify(log.error_details, null, 2)}
							lang="json"
							readonly={true}
							options={{ scrollBeyondLastLine: false, collapsibleBlocks: true, lineNumbers: "off", alwaysConsumeMouseWheel: false }}
						/>
					</div>
				)}
			</SheetContent>
		</Sheet>
	);
}
