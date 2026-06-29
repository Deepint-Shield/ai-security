"use client";

import { LogsVolumeChart } from "@/app/workspace/logs/views/logsVolumeChart";
import FullPageLoader from "@/components/fullPageLoader";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useWebSocket } from "@/hooks/useWebSocket";
import { useAppSelector } from "@/lib/store/hooks";
import { selectActiveWorkspaceId } from "@/lib/store/slices/activeScopeSlice";
import {
	getErrorMessage,
	useDeleteMCPLogsMutation,
	useLazyGetMCPHistogramQuery,
	useLazyGetMCPLogsQuery,
	useLazyGetMCPLogsStatsQuery,
} from "@/lib/store";
import type { MCPHistogramResponse, MCPToolLogEntry, MCPToolLogFilters, MCPToolLogStats, Pagination } from "@/lib/types/logs";
import { dateUtils } from "@/lib/types/logs";
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib";
import { AlertCircle, Bot, CheckCircle, Clock, DollarSign, Hand, Hash, Zap } from "lucide-react";
import { parseAsArrayOf, parseAsBoolean, parseAsInteger, parseAsString, useQueryStates } from "nuqs";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createMCPColumns } from "./views/columns";
import { MCPEmptyState } from "./views/emptyState";
import { MCPLogDetailSheet } from "./views/mcpLogDetailsSheet";
import { MCPLogsDataTable } from "./views/mcpLogsTable";

export default function MCPLogsPage() {
	const [logs, setLogs] = useState<MCPToolLogEntry[]>([]);
	const [totalItems, setTotalItems] = useState(0);
	const [stats, setStats] = useState<MCPToolLogStats | null>(null);
	const [initialLoading, setInitialLoading] = useState(true);
	const [fetchingLogs, setFetchingLogs] = useState(false);
	const [fetchingStats, setFetchingStats] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [showEmptyState, setShowEmptyState] = useState(false);
	const [selectedLog, setSelectedLog] = useState<MCPToolLogEntry | null>(null);
	const [modeFilter, setModeFilter] = useState<"all" | "manual" | "agent">("all");

	const hasDeleteAccess = useRbac(RbacResource.Logs, RbacOperation.Delete);

	const [triggerGetLogs] = useLazyGetMCPLogsQuery();
	const [triggerGetStats] = useLazyGetMCPLogsStatsQuery();
	const [triggerGetHistogram] = useLazyGetMCPHistogramQuery();
	const [deleteLogs] = useDeleteMCPLogsMutation();

	const [histogram, setHistogram] = useState<MCPHistogramResponse | null>(null);
	const [fetchingHistogram, setFetchingHistogram] = useState(false);
	const [chartOpen, setChartOpen] = useState(true);
	const [isZoomed, setIsZoomed] = useState(false);

	// Track if user has manually modified the time range
	const userModifiedTimeRange = useRef<boolean>(false);

	// Capture initial defaults on mount to detect shared URLs with custom time ranges
	const initialDefaults = useRef(dateUtils.getDefaultTimeRange());

	// Memoize default time range to prevent recalculation on every render
	// This is crucial to avoid triggering re-fetches when the sheet opens/closes
	const defaultTimeRange = useMemo(() => dateUtils.getDefaultTimeRange(), []);

	// Get fresh default time range for refresh logic
	const getDefaultTimeRange = () => dateUtils.getDefaultTimeRange();

	// URL state management
	const [urlState, setUrlState] = useQueryStates(
		{
			tool_names: parseAsArrayOf(parseAsString).withDefault([]),
			server_labels: parseAsArrayOf(parseAsString).withDefault([]),
			status: parseAsArrayOf(parseAsString).withDefault([]),
			virtual_key_ids: parseAsArrayOf(parseAsString).withDefault([]),
			content_search: parseAsString.withDefault(""),
			start_time: parseAsInteger.withDefault(defaultTimeRange.startTime),
			end_time: parseAsInteger.withDefault(defaultTimeRange.endTime),
			limit: parseAsInteger.withDefault(50),
			offset: parseAsInteger.withDefault(0),
			sort_by: parseAsString.withDefault("timestamp"),
			order: parseAsString.withDefault("desc"),
			live_enabled: parseAsBoolean.withDefault(true),
		},
		{
			history: "push",
			shallow: false,
		},
	);

	// Refresh time range defaults on page focus/visibility
	useEffect(() => {
		const refreshDefaultsIfStale = () => {
			// Skip refresh if user has manually modified the time range
			if (userModifiedTimeRange.current) {
				return;
			}

			// Check if current time range matches the initial defaults (within tolerance)
			const startTimeDiff = Math.abs(urlState.start_time - initialDefaults.current.startTime);
			const endTimeDiff = Math.abs(urlState.end_time - initialDefaults.current.endTime);
			const tolerance = 5; // 5 seconds tolerance for slight timing differences

			// Only refresh if current values match the initial defaults
			// This preserves shared URLs with custom time ranges
			if (startTimeDiff <= tolerance && endTimeDiff <= tolerance) {
				const defaults = getDefaultTimeRange();
				const currentEndDiff = Math.abs(urlState.end_time - defaults.endTime);
				// If end time is more than 5 minutes old, refresh both
				if (currentEndDiff > 300) {
					setUrlState({
						start_time: defaults.startTime,
						end_time: defaults.endTime,
					});
					// Update baseline so subsequent focus events compare against refreshed defaults
					initialDefaults.current.startTime = defaults.startTime;
					initialDefaults.current.endTime = defaults.endTime;
				}
			}
		};

		const handleVisibilityChange = () => {
			if (!document.hidden) {
				refreshDefaultsIfStale();
			}
		};

		const handleFocus = () => {
			refreshDefaultsIfStale();
		};

		document.addEventListener("visibilitychange", handleVisibilityChange);
		window.addEventListener("focus", handleFocus);
		return () => {
			document.removeEventListener("visibilitychange", handleVisibilityChange);
			window.removeEventListener("focus", handleFocus);
		};
	}, [urlState.start_time, urlState.end_time, setUrlState]);

	// Convert URL state to filters and pagination
	const filters: MCPToolLogFilters = useMemo(
		() => ({
			tool_names: urlState.tool_names,
			server_labels: urlState.server_labels,
			status: urlState.status,
			virtual_key_ids: urlState.virtual_key_ids,
			content_search: urlState.content_search,
			start_time: dateUtils.toISOString(urlState.start_time),
			end_time: dateUtils.toISOString(urlState.end_time),
		}),
		// Only re-derive filters when filter-related URL params change (not pagination)
		// eslint-disable-next-line react-hooks/exhaustive-deps
		[
			urlState.tool_names,
			urlState.server_labels,
			urlState.status,
			urlState.virtual_key_ids,
			urlState.content_search,
			urlState.start_time,
			urlState.end_time,
		],
	);

	const pagination: Pagination = useMemo(
		() => ({
			limit: urlState.limit,
			offset: urlState.offset,
			sort_by: urlState.sort_by as "timestamp" | "latency",
			order: urlState.order as "asc" | "desc",
		}),
		[urlState.limit, urlState.offset, urlState.sort_by, urlState.order],
	);

	const liveEnabled = urlState.live_enabled;

	// Helper to update filters in URL
	const setFilters = useCallback(
		(newFilters: MCPToolLogFilters) => {
			// Mark time range as user-modified if start_time or end_time is being set
			if (newFilters.start_time !== undefined || newFilters.end_time !== undefined) {
				userModifiedTimeRange.current = true;
			}

			setUrlState({
				tool_names: newFilters.tool_names || [],
				server_labels: newFilters.server_labels || [],
				status: newFilters.status || [],
				virtual_key_ids: newFilters.virtual_key_ids || [],
				content_search: newFilters.content_search || "",
				start_time: newFilters.start_time ? dateUtils.toUnixTimestamp(new Date(newFilters.start_time)) : undefined,
				end_time: newFilters.end_time ? dateUtils.toUnixTimestamp(new Date(newFilters.end_time)) : undefined,
				offset: 0,
			});
		},
		[setUrlState],
	);

	// Helper to update pagination in URL
	const setPagination = useCallback(
		(newPagination: Pagination) => {
			setUrlState({
				limit: newPagination.limit,
				offset: newPagination.offset,
				sort_by: newPagination.sort_by,
				order: newPagination.order,
			});
		},
		[setUrlState],
	);

	const handleDelete = useCallback(
		async (log: MCPToolLogEntry) => {
			// Guard against unauthorized delete attempts
			if (!hasDeleteAccess) {
				throw new Error("No delete access");
			}

			try {
				await deleteLogs({ ids: [log.id] }).unwrap();
				setLogs((prevLogs) => prevLogs.filter((l) => l.id !== log.id));
				setTotalItems((prev) => prev - 1);
			} catch (err) {
				const errorMessage = getErrorMessage(err);
				setError(errorMessage);
				throw new Error(errorMessage);
			}
		},
		[deleteLogs, hasDeleteAccess],
	);

	// Active workspace gates inbound WS payloads - server broadcasts are
	// tenant-scoped, not workspace-scoped, so we drop sibling-workspace
	// events client-side to prevent the same cross-workspace flash that
	// shows up on the AI Logs page.
	const activeWorkspaceId = useAppSelector(selectActiveWorkspaceId);

	// Ref to track latest state for WebSocket callbacks
	const latest = useRef({ logs, filters, pagination, showEmptyState, liveEnabled, activeWorkspaceId });
	useEffect(() => {
		latest.current = { logs, filters, pagination, showEmptyState, liveEnabled, activeWorkspaceId };
	}, [logs, filters, pagination, showEmptyState, liveEnabled, activeWorkspaceId]);

	// Helper to check if a log matches current filters
	const matchesFilters = (log: MCPToolLogEntry, filters: MCPToolLogFilters, applyTimeFilters = true): boolean => {
		if (filters.tool_names?.length && !filters.tool_names.includes(log.tool_name)) {
			return false;
		}
		if (filters.server_labels?.length && (!log.server_label || !filters.server_labels.includes(log.server_label))) {
			return false;
		}
		if (filters.status?.length && !filters.status.includes(log.status)) {
			return false;
		}
		if (filters.virtual_key_ids?.length && (!log.virtual_key_id || !filters.virtual_key_ids.includes(log.virtual_key_id))) {
			return false;
		}
		if (filters.start_time && new Date(log.timestamp) < new Date(filters.start_time)) {
			return false;
		}
		if (applyTimeFilters && filters.end_time && new Date(log.timestamp) > new Date(filters.end_time)) {
			return false;
		}
		return true;
	};

	// Handle WebSocket log messages
	const handleMCPLogMessage = useCallback((log: MCPToolLogEntry, operation: "create" | "update") => {
		const { logs, filters, pagination, showEmptyState, liveEnabled, activeWorkspaceId } = latest.current;

		// Workspace gate - see comment on the AI Logs page; drop payloads
		// belonging to a sibling workspace. Legacy rows without workspace_id
		// pass through so historical data stays visible.
		const logWs = (log as MCPToolLogEntry & { workspace_id?: string | null }).workspace_id;
		if (activeWorkspaceId && logWs && logWs !== activeWorkspaceId) {
			return;
		}

		// Exit empty state if we now have logs
		if (showEmptyState) {
			setShowEmptyState(false);
		}

		if (operation === "create") {
			// Only prepend new log if on first page and sorted by timestamp desc
			if (pagination.offset === 0 && pagination.sort_by === "timestamp" && pagination.order === "desc") {
				if (!matchesFilters(log, filters, !liveEnabled)) {
					return;
				}

				setLogs((prevLogs: MCPToolLogEntry[]) => {
					// Prevent duplicates
					if (prevLogs.some((existingLog) => existingLog.id === log.id)) {
						return prevLogs;
					}

					const updatedLogs = [log, ...prevLogs];
					if (updatedLogs.length > pagination.limit) {
						updatedLogs.pop();
					}
					return updatedLogs;
				});

				// Update selected log if it matches
				setSelectedLog((prevSelectedLog) => {
					if (prevSelectedLog && prevSelectedLog.id === log.id) {
						return log;
					}
					return prevSelectedLog;
				});

				setTotalItems((prev: number) => prev + 1);
			}
		} else if (operation === "update") {
			const logExists = logs.some((existingLog) => existingLog.id === log.id);

			if (!logExists) {
				// Fallback: if log doesn't exist, treat as create
				if (pagination.offset === 0 && pagination.sort_by === "timestamp" && pagination.order === "desc") {
					if (matchesFilters(log, filters, !liveEnabled)) {
						setLogs((prevLogs: MCPToolLogEntry[]) => {
							if (prevLogs.some((existingLog) => existingLog.id === log.id)) {
								return prevLogs.map((existingLog) => (existingLog.id === log.id ? log : existingLog));
							}

							const updatedLogs = [log, ...prevLogs];
							if (updatedLogs.length > pagination.limit) {
								updatedLogs.pop();
							}
							return updatedLogs;
						});
					}
				}
			} else {
				// Update existing log
				setLogs((prevLogs: MCPToolLogEntry[]) => {
					return prevLogs.map((existingLog) => (existingLog.id === log.id ? log : existingLog));
				});

				// Update selected log if it matches
				setSelectedLog((prevSelectedLog) => {
					if (prevSelectedLog && prevSelectedLog.id === log.id) {
						return log;
					}
					return prevSelectedLog;
				});

				// Update stats for completed requests
				if (log.status === "success" || log.status === "error") {
					setStats((prevStats) => {
						if (!prevStats) return prevStats;

						const newStats = { ...prevStats };
						const completed_executions = prevStats.total_executions + 1;
						newStats.total_executions = completed_executions;

						// Update success rate
						const successCount = (prevStats.success_rate / 100) * prevStats.total_executions;
						const newSuccessCount = log.status === "success" ? successCount + 1 : successCount;
						newStats.success_rate = (newSuccessCount / completed_executions) * 100;

						// Update average latency
						if (log.latency) {
							const totalLatency = prevStats.average_latency * prevStats.total_executions;
							newStats.average_latency = (totalLatency + log.latency) / completed_executions;
						}

						// Update total cost
						newStats.total_cost = (Number(newStats.total_cost) || 0) + Number(log.cost ?? 0);

						return newStats;
					});
				}
			}
		}
	}, []);

	const { isConnected: isSocketConnected, subscribe } = useWebSocket();

	// Subscribe to MCP log messages - only when live updates are enabled
	useEffect(() => {
		if (!liveEnabled) {
			return;
		}

		const unsubscribe = subscribe("mcp_log", (data) => {
			const { payload, operation } = data;
			handleMCPLogMessage(payload, operation);
		});

		return unsubscribe;
	}, [handleMCPLogMessage, subscribe, liveEnabled]);

	// Fetch logs
	const fetchLogs = useCallback(async () => {
		setFetchingLogs(true);
		setError(null);
		try {
			const result = await triggerGetLogs({ filters, pagination }).unwrap();
			setLogs(result.logs || []);
			setTotalItems(result.stats?.total_executions || 0);

			if (initialLoading) {
				setShowEmptyState(result.has_logs === false);
			}
		} catch (err) {
			setError(getErrorMessage(err));
			setLogs([]);
			setTotalItems(0);
			setShowEmptyState(true);
		} finally {
			setFetchingLogs(false);
		}
	}, [filters, pagination, triggerGetLogs, initialLoading]);

	const fetchStats = useCallback(async () => {
		setFetchingStats(true);
		try {
			const result = await triggerGetStats({ filters }).unwrap();
			setStats(result);
		} catch (err) {
			console.error("Failed to fetch stats:", err);
		} finally {
			setFetchingStats(false);
		}
	}, [filters, triggerGetStats]);

	const fetchHistogram = useCallback(async () => {
		setFetchingHistogram(true);
		try {
			const result = await triggerGetHistogram({ filters }).unwrap();
			setHistogram(result);
		} catch (err) {
			console.error("Failed to fetch MCP histogram:", err);
		} finally {
			setFetchingHistogram(false);
		}
	}, [filters, triggerGetHistogram]);

	// Helper to toggle live updates
	const handleLiveToggle = useCallback(
		(enabled: boolean) => {
			setUrlState({ live_enabled: enabled });
			// When re-enabling, refetch logs to get latest data
			if (enabled) {
				fetchLogs();
			}
		},
		[setUrlState, fetchLogs],
	);

	// Initial load
	useEffect(() => {
		const initialLoad = async () => {
			await fetchLogs();
			fetchStats();
			fetchHistogram();
			setInitialLoading(false);
		};
		initialLoad();
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, []);

	// Fetch logs when filters or pagination change
	useEffect(() => {
		if (!initialLoading) {
			fetchLogs();
		}
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [filters, pagination, initialLoading]);

	// Fetch stats + histogram when filters change
	useEffect(() => {
		if (!initialLoading) {
			fetchStats();
			fetchHistogram();
		}
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [filters, initialLoading]);

	// Derive a cache-hit rate from the loaded page. The stats endpoint doesn't aggregate this
	// today, so we surface it from what's on-screen - same approach used for metadata keys.
	const cacheHitRateValue = useMemo(() => {
		let total = 0;
		let hits = 0;
		for (const log of logs) {
			if (log.cache_hit === undefined || log.cache_hit === null) continue;
			total += 1;
			if (log.cache_hit) hits += 1;
		}
		if (total === 0) return "-";
		return `${((hits / total) * 100).toFixed(1)}%`;
	}, [logs]);

	// Manual = client called POST /v1/mcp/tool/execute directly with a tool_call payload (no LLM context server-side).
	// Agent  = tool was auto-executed inside the gateway's /openai completion loop, so the log is linked to its LLM request.
	const getExecutionMode = useCallback((log: MCPToolLogEntry): "manual" | "agent" => {
		if (log.llm_request_id) return "agent";
		const meta = log.metadata ?? {};
		const explicit = (meta.execution_mode || meta.mode || meta.invocation || "").toString().toLowerCase();
		if (explicit === "agent" || explicit === "auto" || explicit === "auto_execute" || explicit === "auto-execute") return "agent";
		return "manual";
	}, []);

	const modeBreakdown = useMemo(() => {
		const empty = { count: 0, success: 0, error: 0, latencySum: 0, latencyN: 0, cost: 0 };
		const acc = { manual: { ...empty }, agent: { ...empty } };
		for (const log of logs) {
			const mode = getExecutionMode(log);
			const bucket = acc[mode];
			bucket.count += 1;
			if (log.status === "success") bucket.success += 1;
			else if (log.status === "error") bucket.error += 1;
			if (typeof log.latency === "number") {
				bucket.latencySum += log.latency;
				bucket.latencyN += 1;
			}
			bucket.cost += Number(log.cost ?? 0);
		}
		const summarize = (b: typeof empty) => ({
			count: b.count,
			successRate: b.count > 0 ? (b.success / b.count) * 100 : 0,
			avgLatency: b.latencyN > 0 ? b.latencySum / b.latencyN : 0,
			cost: b.cost,
			error: b.error,
		});
		return { manual: summarize(acc.manual), agent: summarize(acc.agent) };
	}, [logs, getExecutionMode]);

	const statCards = useMemo(
		() => [
			{
				title: "Executions",
				value: fetchingStats ? <Skeleton className="h-8 w-20" /> : stats?.total_executions.toLocaleString() || "-",
				icon: <Hash className="size-4" />,
			},
			{
				title: "Manual",
				value: modeBreakdown.manual.count.toLocaleString(),
				icon: <Hand className="size-4" />,
			},
			{
				title: "Agent",
				value: modeBreakdown.agent.count.toLocaleString(),
				icon: <Bot className="size-4" />,
			},
			{
				title: "Success Rate",
				value: fetchingStats ? <Skeleton className="h-8 w-16" /> : stats ? `${stats.success_rate.toFixed(2)}%` : "-",
				icon: <CheckCircle className="size-4" />,
			},
			{
				title: "Avg Latency",
				value: fetchingStats ? <Skeleton className="h-8 w-20" /> : stats ? `${stats.average_latency.toFixed(2)}ms` : "-",
				icon: <Clock className="size-4" />,
			},
			{
				title: "Cache Hit Rate",
				value: cacheHitRateValue,
				icon: <Zap className="size-4" />,
			},
			{
				title: "Total Cost",
				value: fetchingStats ? <Skeleton className="h-8 w-20" /> : stats ? `$${(stats.total_cost ?? 0).toFixed(4)}` : "-",
				icon: <DollarSign className="size-4" />,
			},
		],
		[stats, fetchingStats, cacheHitRateValue, modeBreakdown.manual.count, modeBreakdown.agent.count],
	);

	const filteredLogs = useMemo(() => {
		if (modeFilter === "all") return logs;
		return logs.filter((log) => getExecutionMode(log) === modeFilter);
	}, [logs, modeFilter, getExecutionMode]);

	// Derive metadata keys from currently loaded logs (MCP filterdata API doesn't expose metadata_keys yet).
	const metadataKeys = useMemo(() => {
		const keys = new Set<string>();
		for (const log of logs) {
			if (!log.metadata) continue;
			for (const k of Object.keys(log.metadata)) {
				if (k !== "latency_breakdown_ms") keys.add(k);
			}
		}
		return Array.from(keys).sort();
	}, [logs]);

	const columns = useMemo(
		() => createMCPColumns(handleDelete, hasDeleteAccess, metadataKeys),
		[handleDelete, hasDeleteAccess, metadataKeys],
	);

	// Chart zoom-to-range support: mirrors AI Logs' chart drag-to-zoom behavior.
	const handleChartTimeRangeChange = useCallback(
		(startTime: number, endTime: number) => {
			userModifiedTimeRange.current = true;
			setUrlState({ start_time: startTime, end_time: endTime });
			setIsZoomed(true);
		},
		[setUrlState],
	);
	const handleChartResetZoom = useCallback(() => {
		const defaults = getDefaultTimeRange();
		userModifiedTimeRange.current = false;
		setUrlState({ start_time: defaults.startTime, end_time: defaults.endTime });
		setIsZoomed(false);
	}, [setUrlState]);

	return (
		// Fit-to-window viewport - mirrors AI Logs (workspace/logs/page.tsx).
		// 100dvh − header height locks the page to the visible window so the
		// data table grows/shrinks with the browser, paginating inside its
		// own scroll instead of overflowing the page.
		<div className="h-[calc(100dvh-3.3rem)] max-h-[calc(100dvh-1.5rem)] bg-transparent">
			{initialLoading ? (
				<FullPageLoader />
			) : showEmptyState ? (
				<MCPEmptyState
					error={error}
					statusIndicator={
						isSocketConnected && (
							<div className="inline-flex items-center rounded-full border border-green-200 bg-green-50 px-3 py-1 text-xs font-medium text-green-700 sm:px-4 sm:text-sm">
								<span className="relative mr-2 flex h-2 w-2 sm:mr-3">
									<span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-500 opacity-75"></span>
									<span className="relative inline-flex h-2 w-2 rounded-full bg-green-600"></span>
								</span>
								<span>Listening for tool executions...</span>
							</div>
						)
					}
				/>
			) : (
				<div className="workspace-page-shell flex h-full flex-col">
					<div className="flex flex-1 flex-col gap-2 overflow-hidden">
						{/* Quick Stats - same treatment as AI Logs */}
						<div className="grid shrink-0 grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-7">
							{statCards.map((card) => (
								<Card
									key={card.title}
									className="group rounded-2xl py-3 transition-colors hover:border-primary/30"
								>
									<CardContent className="flex items-start justify-between gap-3 px-4">
										<div className="w-full min-w-0 space-y-1">
											<div className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.14em]">{card.title}</div>
											<div className="text-foreground truncate font-mono text-xl font-semibold leading-none tracking-tight sm:text-2xl">
												{card.value}
											</div>
										</div>
										<span className="text-primary inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-primary/10 border border-primary/15 shadow-[inset_0_1px_0_rgba(255,255,255,0.18)] transition-transform group-hover:scale-105">
											{card.icon}
										</span>
									</CardContent>
								</Card>
							))}
						</div>

						{/* Volume Chart - same component as AI Logs (MCPHistogramResponse is structurally identical) */}
						<div className="shrink-0">
							<LogsVolumeChart
								data={histogram}
								loading={fetchingHistogram}
								onTimeRangeChange={handleChartTimeRangeChange}
								onResetZoom={handleChartResetZoom}
								isZoomed={isZoomed}
								startTime={urlState.start_time}
								endTime={urlState.end_time}
								isOpen={chartOpen}
								onOpenChange={setChartOpen}
							/>
						</div>

						{/* Mode segmented control */}
						<Tabs value={modeFilter} onValueChange={(v) => setModeFilter(v as "all" | "manual" | "agent")} className="shrink-0">
							<TabsList>
								<TabsTrigger value="all" data-testid="mcp-mode-tab-all">All ({logs.length})</TabsTrigger>
								<TabsTrigger value="manual" data-testid="mcp-mode-tab-manual">
									<Hand className="size-3.5" /> Manual ({modeBreakdown.manual.count})
								</TabsTrigger>
								<TabsTrigger value="agent" data-testid="mcp-mode-tab-agent">
									<Bot className="size-3.5" /> Agent ({modeBreakdown.agent.count})
								</TabsTrigger>
							</TabsList>
						</Tabs>

						{/* {modeFilter !== "all" ? (
							<p className="text-muted-foreground text-xs">
								Filter applies to the current page of {logs.length} loaded logs. Aggregated server-side stats above remain unfiltered.
							</p>
						) : null} */}

						{/* Error Alert */}
						{error && (
							<Alert variant="destructive" className="shrink-0">
								<AlertCircle className="h-4 w-4" />
								<AlertDescription>{error}</AlertDescription>
							</Alert>
						)}

						<div className="min-h-0 flex-1">
						<MCPLogsDataTable
							columns={columns}
							data={filteredLogs}
							totalItems={totalItems}
							loading={fetchingLogs}
							filters={filters}
							pagination={pagination}
							onFiltersChange={setFilters}
							onPaginationChange={setPagination}
							onRowClick={(row, columnId) => {
								if (columnId === "actions") return;
								setSelectedLog(row);
							}}
							isSocketConnected={isSocketConnected}
							liveEnabled={liveEnabled}
							onLiveToggle={handleLiveToggle}
							fetchLogs={fetchLogs}
							fetchStats={fetchStats}
						/>
						</div>
					</div>

					{/* Log Detail Sheet */}
					<MCPLogDetailSheet
						log={selectedLog}
						open={selectedLog !== null}
						onOpenChange={(open) => !open && setSelectedLog(null)}
						handleDelete={handleDelete}
					/>
				</div>
			)}
		</div>
	);
}

