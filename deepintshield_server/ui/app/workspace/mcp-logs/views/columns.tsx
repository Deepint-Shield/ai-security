"use client";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Status, StatusBarColors, StatusColors, Statuses } from "@/lib/constants/logs";
import type { MCPToolLogEntry } from "@/lib/types/logs";
import { ColumnDef } from "@tanstack/react-table";
import { ArrowUpDown, Trash2 } from "lucide-react";
import moment from "moment";

const getValidatedStatus = (status: string): Status => {
	if (Statuses.includes(status as Status)) {
		return status as Status;
	}
	return "processing";
};

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

function getArgumentsPreview(log: MCPToolLogEntry): string {
	const args = log.arguments;
	if (args === null || args === undefined) return "";
	if (typeof args === "string") return args;
	try {
		return JSON.stringify(args);
	} catch {
		return "";
	}
}

function toTitleCase(value: string): string {
	return value
		.split(/[_\s-]+/)
		.filter(Boolean)
		.map((part) => part.charAt(0).toUpperCase() + part.slice(1))
		.join(" ");
}

function getGuardrailStatusLabel(log: MCPToolLogEntry): string {
	const normalized = log.guardrail_status?.trim().toLowerCase();
	if (!normalized) return "-";
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

export const createMCPColumns = (
	handleDelete: (log: MCPToolLogEntry) => Promise<void>,
	hasDeleteAccess: boolean,
	metadataKeys: string[] = [],
): ColumnDef<MCPToolLogEntry>[] => {
	const baseColumns: ColumnDef<MCPToolLogEntry>[] = [
		{
			accessorKey: "status",
			header: "",
			size: 8,
			maxSize: 8,
			cell: ({ row }) => {
				const status = getValidatedStatus(row.original.status);
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
			cell: () => (
				<Badge variant="outline" className="bg-violet-100 text-violet-800 dark:bg-violet-950 dark:text-violet-200 text-[10px]">
					Tool Call
				</Badge>
			),
		},
		{
			id: "arguments_preview",
			header: "Arguments",
			size: 220,
			cell: ({ row }) => {
				const preview = getArgumentsPreview(row.original);
				return (
					<div className="max-w-[200px] truncate font-mono text-xs font-normal" title={preview || "-"}>
						{preview || "-"}
					</div>
				);
			},
		},
		{
			accessorKey: "tool_name",
			header: "Tool Name",
			size: 160,
			cell: ({ row }) => {
				const toolName = row.getValue("tool_name") as string;
				return <span className="block max-w-[140px] truncate font-mono text-xs">{toolName}</span>;
			},
		},
		{
			accessorKey: "server_label",
			header: "Server",
			size: 110,
			cell: ({ row }) => {
				const serverLabel = row.getValue("server_label") as string;
				return serverLabel ? (
					<Badge variant="secondary" className="font-mono text-[10px]">
						{serverLabel}
					</Badge>
				) : (
					<span className="text-muted-foreground">-</span>
				);
			},
		},
		{
			id: "virtual_key",
			header: "Virtual Key",
			size: 120,
			cell: ({ row }) => {
				const name = row.original.virtual_key?.name ?? row.original.virtual_key_name;
				return <div className="max-w-[110px] truncate font-mono text-xs">{name || "-"}</div>;
			},
		},
		{
			id: "team",
			header: "Team",
			size: 110,
			cell: ({ row }) => {
				const teamName = row.original.virtual_key?.team?.name;
				return <div className="max-w-[100px] truncate font-mono text-xs">{teamName || "-"}</div>;
			},
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
				const hit = row.original.cache_hit;
				if (hit === undefined || hit === null) {
					return <div className="font-mono text-xs">-</div>;
				}
				return <div className="font-mono text-xs">{hit ? "Hit" : "Miss"}</div>;
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
			// Which engine evaluated the MCP tool call - mirrors the column added
			// to AI Logs. "AI Model" / "Policy" / "Mixed" / "-" sourced from the
			// guardrail_source join (decisions → policy bindings → provider type).
			id: "guardrail_source",
			header: "Engine",
			size: 90,
			cell: ({ row }) => {
				const source = row.original.guardrail_source?.trim().toLowerCase() ?? "";
				let label = "-";
				let className = "text-muted-foreground";
				switch (source) {
					case "ai_model":
						label = "AI Model";
						className = "text-indigo-600 dark:text-indigo-400";
						break;
					case "policy":
						label = "Policy";
						className = "text-amber-600 dark:text-amber-400";
						break;
					case "mixed":
						label = "Mixed";
						className = "text-violet-600 dark:text-violet-400";
						break;
				}
				return <div className={`font-mono text-xs ${className}`}>{label}</div>;
			},
		},
		{
			// MCP-stage guard latency, parsed from latency_breakdown_ms on
			// metadata the same way the AI Logs column does it. MCP tool calls
			// run through the guardrails plugin's StageMCP path so guardrail_mcp
			// is the canonical phase here; sum input + mcp for a unified view.
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
			id: "log_status",
			header: "Status",
			size: 90,
			cell: ({ row }) => {
				const status = getValidatedStatus(row.original.status);
				return (
					<Badge variant="outline" className={`${StatusColors[status]} font-mono text-[10px] uppercase`}>
						{row.original.status}
					</Badge>
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
				const cost = row.original.cost;
				const isValidNumber = typeof cost === "number" && Number.isFinite(cost);
				return <div className="font-mono text-xs">{isValidNumber ? cost.toFixed(4) : "N/A"}</div>;
			},
		},
	];

	// MCP Activity rows are PDP-bridged tool executions. Several columns
	// the table was copied from AI Logs carry no real data on this route:
	//
	//   - request_type   constant "Tool Call" badge - redundant with the
	//                    page header + dedicated Tool Name column
	//   - cache_status   PDP-bridged decisions don't carry a cache_hit
	//                    flag; only true upstream executions populate it,
	//                    so the column is always "-" on the agentic path
	//   - cost           always 0 for PDP rows (zero-data-retention; the
	//                    real per-call cost only exists when the upstream
	//                    MCP actually executes and returns billing meta)
	//
	// Filter them out here so operators only see columns that ever carry
	// information. When real upstream executions land in the future we
	// can revisit - the easy path is to re-enable cache_status + cost
	// conditionally on row content.
	const MCP_HIDDEN_COLUMNS = new Set(["request_type", "cache_status", "cost"]);
	const scopedBaseColumns = baseColumns.filter((column) => {
		const key = column.id ?? ("accessorKey" in column ? String(column.accessorKey) : "");
		return !MCP_HIDDEN_COLUMNS.has(key);
	});

	// Dynamic metadata columns (mirror AI Logs)
	const metadataColumns: ColumnDef<MCPToolLogEntry>[] = metadataKeys
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

	const actionsColumn: ColumnDef<MCPToolLogEntry> = {
		id: "actions",
		cell: ({ row }) => {
			const log = row.original;
			return (
				<Button
					variant="outline"
					size="icon"
					onClick={() => void handleDelete(log)}
					disabled={!hasDeleteAccess}
					aria-label="Delete log"
				>
					<Trash2 />
				</Button>
			);
		},
	};

	return [...scopedBaseColumns, ...metadataColumns, actionsColumn];
};
