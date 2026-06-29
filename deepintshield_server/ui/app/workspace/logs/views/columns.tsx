"use client";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ProviderIconType, RenderProviderIcon } from "@/lib/constants/icons";
import { ProviderName, RequestTypeColors, RequestTypeLabels, Status, StatusBarColors } from "@/lib/constants/logs";
import type { VirtualKey } from "@/lib/types/governance";
import { LogEntry, ResponsesMessageContentBlock } from "@/lib/types/logs";
import { ColumnDef } from "@tanstack/react-table";
import { ArrowUpDown, Trash2 } from "lucide-react";
import moment from "moment";

function formatMetadataValue(value: unknown): string {
	if (value === null || value === undefined || value === "") {
		return "-";
	}
	if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
		return String(value);
	}
	try {
		return JSON.stringify(value);
	} catch {
		return String(value);
	}
}

function toTitleCase(value: string): string {
	return value
		.split(/[_\s-]+/)
		.filter(Boolean)
		.map((part) => part.charAt(0).toUpperCase() + part.slice(1))
		.join(" ");
}

function getGuardrailStatusLabel(log: LogEntry): string {
	const normalized = log.guardrail_status?.trim().toLowerCase();
	if (normalized) {
		switch (normalized) {
			case "allow":
				return "Allow";
			case "deny":
				return "Deny";
			case "allow_with_redaction":
				return "Redacted";
			case "sandbox":
				return "Sandbox";
			case "warn":
				return "Warn";
			case "approval":
			case "approval_required":
				return "Approval";
			default:
				return toTitleCase(normalized);
		}
	}

	if (log.cache_debug?.guardrail_reused === true) {
		return "Reused";
	}

	return "-";
}

function getMessage(log?: LogEntry) {
	if (log?.object === "list_models") {
		return "N/A";
	}
	if (log?.input_history && log.input_history.length > 0) {
		let userMessageContent = log.input_history[log.input_history.length - 1].content;
		if (userMessageContent == undefined) {
			return "";
		}
		if (typeof userMessageContent === "string") {
			return userMessageContent;
		}
		let lastTextContentBlock = "";
		for (const block of userMessageContent) {
			if (block.type === "text" && block.text) {
				lastTextContentBlock = block.text;
			}
		}
		return lastTextContentBlock;
	} else if (log?.responses_input_history && log.responses_input_history.length > 0) {
		let lastMessage = log.responses_input_history[log.responses_input_history.length - 1];
		let lastMessageContent = lastMessage.content;
		if (typeof lastMessageContent === "string") {
			return lastMessageContent;
		}
		let lastTextContentBlock = "";
		for (const block of (lastMessageContent ?? []) as ResponsesMessageContentBlock[]) {
			if (block.text && block.text !== "") {
				lastTextContentBlock = block.text;
			}
		}
		// If no content found in content field, check output field for Responses API
		if (!lastTextContentBlock && lastMessage.output) {
			// Handle output field - it could be a string, an array of content blocks, or a computer tool call output data
			if (typeof lastMessage.output === "string") {
				return lastMessage.output;
			} else if (Array.isArray(lastMessage.output)) {
				return lastMessage.output.map((block) => block.text).join("\n");
			} else if (lastMessage.output.type && lastMessage.output.type === "computer_screenshot") {
				return lastMessage.output.image_url;
			}
		}
		return lastTextContentBlock ?? "";
	} else if (log?.speech_input) {
		return log.speech_input.input;
	} else if (log?.transcription_input) {
		return "Audio file";
	} else if (log?.image_generation_input?.prompt) {
		return log.image_generation_input.prompt;
	}
	const obj = log?.object as string | undefined;
	if (obj === "image_edit" || obj === "image_edit_stream" || obj === "image_variation") {
		return "Image file";
	}
	return "";
}

function getTeamName(log: LogEntry, virtualKeysById: Record<string, VirtualKey>) {
	const directTeamName = log.virtual_key?.team?.name;
	if (directTeamName) {
		return directTeamName;
	}

	if (!log.virtual_key_id) {
		return "";
	}

	return virtualKeysById[log.virtual_key_id]?.team?.name ?? "";
}

function isCacheHit(log: LogEntry) {
	if (log.cache_debug?.cache_hit === true) {
		return true;
	}
	return (log.cache_savings ?? 0) > 0;
}

function hasCacheData(log: LogEntry) {
	return log.cache_debug !== undefined || log.cache_savings !== undefined;
}

export const createColumns = (
	onDelete: (log: LogEntry) => void,
	hasDeleteAccess = true,
	metadataKeys: string[] = [],
	virtualKeysById: Record<string, VirtualKey> = {},
	isAgenticLogs = false,
): ColumnDef<LogEntry>[] => {
	const baseColumns: ColumnDef<LogEntry>[] = [
	{
		accessorKey: "status",
		header: "",
		size: 8,
		maxSize: 8,
		cell: ({ row }) => {
			const status = row.original.status as Status;
			return <div className={`h-full min-h-[24px] w-1 rounded-sm ${StatusBarColors[status]}`} />;
		},
	},
	{
		accessorKey: "timestamp",
		header: ({ column }) => (
			<Button variant="ghost" className="h-7 px-1 text-xs" onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}>
				Time
				<ArrowUpDown className="ml-1 h-3 w-3" />
			</Button>
		),
		size: 150,
		cell: ({ row }) => {
			const timestamp = row.original.timestamp;
			return <div className="whitespace-nowrap text-xs">{moment(timestamp).format("YYYY-MM-DD HH:mm:ss")}</div>;
		},
	},
	{
		id: "request_type",
		header: "Type",
		size: 90,
		cell: ({ row }) => {
			return (
				<Badge variant="outline" className={`${RequestTypeColors[row.original.object as keyof typeof RequestTypeColors]} text-[10px]`}>
					{RequestTypeLabels[row.original.object as keyof typeof RequestTypeLabels]}
				</Badge>
			);
		},
	},
	{
		accessorKey: "input",
		header: "Message",
		size: 240,
		cell: ({ row }) => {
			const input = getMessage(row.original);
			const isLargePayload = row.original.is_large_payload_request || row.original.is_large_payload_response;
			return (
				<div className="flex items-center gap-1.5">
					{isLargePayload && (
						<span className="shrink-0 rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-medium text-amber-700 dark:bg-amber-900/50 dark:text-amber-400" title="Large payload - streamed directly to provider">
							LP
						</span>
					)}
					<div className="max-w-[220px] truncate font-mono text-xs font-normal" title={input || "-"}>
						{input || (isLargePayload
						? `Large payload ${row.original.is_large_payload_request && row.original.is_large_payload_response ? "request & response" : row.original.is_large_payload_request ? "request" : "response"}`
						: "-")}
					</div>
				</div>
			);
		},
	},
	{
		accessorKey: "provider",
		header: "Provider",
		size: 110,
		cell: ({ row }) => {
			const provider = row.original.provider as ProviderName;
			return (
				<Badge variant="secondary" className={`font-mono text-[10px] uppercase`}>
					<RenderProviderIcon provider={provider as ProviderIconType} size="sm" />
					{provider}
				</Badge>
			);
		},
	},
	{
		id: "team",
		header: "Team",
		size: 110,
		cell: ({ row }) => {
			const teamName = getTeamName(row.original, virtualKeysById);
			return <div className="max-w-[100px] truncate font-mono text-xs font-normal">{teamName || "-"}</div>;
		},
	},
	{
		accessorKey: "model",
		header: "Model",
		size: 110,
		cell: ({ row }) => <div className="max-w-[100px] truncate font-mono text-xs font-normal">{row.original.model || "N/A"}</div>,
	},
	{
		accessorKey: "latency",
		header: ({ column }) => (
			<Button variant="ghost" className="h-7 px-1 text-xs" onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}>
				Latency
				<ArrowUpDown className="ml-1 h-3 w-3" />
			</Button>
		),
		size: 90,
		cell: ({ row }) => {
			const latency = row.original.latency;
			return (
				<div className="whitespace-nowrap font-mono text-xs">
					{latency === undefined || latency === null ? "N/A" : `${latency.toLocaleString()}ms`}
				</div>
			);
		},
	},
	{
		id: "cache_status",
		header: "Cache",
		size: 70,
		cell: ({ row }) => {
			if (!hasCacheData(row.original)) {
				return <div className="font-mono text-xs">-</div>;
			}
			return <div className="font-mono text-xs">{isCacheHit(row.original) ? "Hit" : "Miss"}</div>;
		},
	},
	{
		id: "guardrail_status",
		header: "Guardrail",
		size: 90,
		cell: ({ row }) => {
			return <div className="font-mono text-xs">{getGuardrailStatusLabel(row.original)}</div>;
		},
	},
	{
		// Which engine produced the findings - joined from guardrail_findings
		// on the server. "AI Model" when category endings are *_model only,
		// "Policy" for regex/card-only, "Mixed" when both fired, "-" when
		// no findings were recorded (cache hit / no policy attached / fast
		// path skip).
		id: "guardrail_source",
		header: "Engine",
		size: 90,
		cell: ({ row }) => {
			const source = row.original.guardrail_source?.trim().toLowerCase() ?? "";
			let label = "-";
			let badgeClass = "text-muted-foreground";
			switch (source) {
				case "ai_model":
					label = "AI Model";
					badgeClass = "text-indigo-600 dark:text-indigo-400";
					break;
				case "policy":
					label = "Policy";
					badgeClass = "text-amber-600 dark:text-amber-400";
					break;
				case "mixed":
					label = "Mixed";
					badgeClass = "text-violet-600 dark:text-violet-400";
					break;
			}
			return <div className={`font-mono text-xs ${badgeClass}`}>{label}</div>;
		},
	},
	{
		// Per-stage guardrail latency, surfaced from the metadata
		// `latency_breakdown_ms` map the logging plugin writes. Shows the
		// sum of input + output + mcp guard phases. "-" when the row was
		// a guard-skipped fast path (no policies, cache hit, etc.).
		id: "guardrail_latency",
		header: "Guard ms",
		size: 80,
		cell: ({ row }) => {
			const meta = row.original.metadata as Record<string, unknown> | undefined;
			const raw = meta?.latency_breakdown_ms;
			let breakdown: Record<string, number> | null = null;
			try {
				breakdown = typeof raw === "string" ? JSON.parse(raw) : (raw as Record<string, number> | null);
			} catch {
				breakdown = null;
			}
			if (!breakdown) {
				return <div className="font-mono text-xs text-muted-foreground">-</div>;
			}
			const total =
				(breakdown.guardrail_input ?? 0) +
				(breakdown.guardrail_output ?? 0) +
				(breakdown.guardrail_mcp ?? 0);
			if (total <= 0) {
				return <div className="font-mono text-xs text-muted-foreground">-</div>;
			}
			return <div className="font-mono text-xs">{total.toLocaleString()}ms</div>;
		},
	},
	{
		accessorKey: "tokens",
		header: ({ column }) => (
			<Button variant="ghost" className="h-7 px-1 text-xs" onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}>
				Tokens
				<ArrowUpDown className="ml-1 h-3 w-3" />
			</Button>
		),
		size: 120,
		cell: ({ row }) => {
			if (isCacheHit(row.original)) {
				return <div className="font-mono text-xs">0</div>;
			}
			const tokenUsage = row.original.token_usage;
			if (!tokenUsage) {
				return <div className="font-mono text-xs">N/A</div>;
			}
			return (
				<div className="font-mono text-xs whitespace-nowrap">
					{tokenUsage.total_tokens.toLocaleString()}
					{tokenUsage.completion_tokens != null && tokenUsage.prompt_tokens != null
						? ` (${tokenUsage.prompt_tokens.toLocaleString()}+${tokenUsage.completion_tokens.toLocaleString()})`
						: ""}
				</div>
			);
		},
	},
	{
		accessorKey: "cost",
		header: ({ column }) => (
			<Button variant="ghost" className="h-7 px-1 text-xs" onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}>
				Cost
				<ArrowUpDown className="ml-1 h-3 w-3" />
			</Button>
		),
		size: 80,
		cell: ({ row }) => {
			const cacheHit = isCacheHit(row.original);
			if (row.original.cost === undefined || row.original.cost === null) {
				return <div className="font-mono text-xs">{cacheHit ? "0.0000" : "N/A"}</div>;
			}
			return <div className="font-mono text-xs">{row.original.cost?.toFixed(4)}</div>;
		},
	},
	];

	// Generate dynamic metadata columns
	const metadataColumns: ColumnDef<LogEntry>[] = metadataKeys
		.filter((key) => key !== "latency_breakdown_ms")
		.map((key) => ({
		id: `metadata_${key}`,
		header: key.charAt(0).toUpperCase() + key.slice(1),
		size: 120,
		cell: ({ row }) => {
			const value = row.original.metadata?.[key];
			return <div className="max-w-[110px] truncate font-mono text-xs">{formatMetadataValue(value)}</div>;
		},
	}));

	// Agentic Logs reuse this same table but represent tool / PDP decisions,
	// not LLM calls. Those rows carry no real provider (it's the constant
	// "agentic"), no cache classification, no tokens / cost, and no
	// separate guardrail engine (the PDP IS the guardrail, so
	// guardrail_source / guardrail_latency are always empty). Drop those
	// columns there so the view isn't padded with permanently-empty
	// cells. (Model is kept - for agentic rows it holds the tool name.
	// The standalone `latency` column is also kept - for PDP rows it is
	// the decision latency.) AI Logs keep the full column set because
	// every column carries data for an LLM call.
	const AGENTIC_HIDDEN_COLUMNS = new Set([
		"provider",
		"cache_status",
		"tokens",
		"cost",
		"guardrail_source",
		"guardrail_latency",
	]);
	const scopedBaseColumns = isAgenticLogs
		? baseColumns.filter((column) => {
				const key = column.id ?? ("accessorKey" in column ? String(column.accessorKey) : "");
				return !AGENTIC_HIDDEN_COLUMNS.has(key);
			})
		: baseColumns;

	// AI Logs are an immutable audit trail (it now also surfaces the
	// hash-chained agentic decisions) - no per-row delete action. Deletion is
	// disabled server-side too (see deleteLogs).
	return [...scopedBaseColumns, ...metadataColumns];
};
