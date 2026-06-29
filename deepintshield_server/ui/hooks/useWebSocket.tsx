"use client";

import { useAppSelector } from "@/lib/store/hooks";
import { selectActiveWorkspaceId } from "@/lib/store/slices/activeScopeSlice";
import { getApiBaseUrl } from "@/lib/utils/port";
import { getWebSocketUrl } from "@/lib/utils/port";
import React, { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";

type MessageHandler = (data: any) => void;

interface WebSocketContextType {
	isConnected: boolean;
	ws: React.RefObject<WebSocket | null>;
	subscribe: (channel: string, handler: MessageHandler) => () => void;
	send: (data: any) => void;
}

const WebSocketContext = createContext<WebSocketContextType | null>(null);

interface WebSocketProviderProps {
	children: ReactNode;
	path?: string;
}

// Global reference to maintain state across component remounts
let globalWsRef: WebSocket | null = null;
const messageHandlers = new Map<string, Set<MessageHandler>>();

export function WebSocketProvider({ children, path = "/ws" }: WebSocketProviderProps) {
	const wsRef = useRef<WebSocket | null>(globalWsRef);
	const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
	const pingTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
	const retryCountRef = useRef(0);
	const [isConnected, setIsConnected] = useState(false);

	// The WebSocket connection is pinned to the workspace it was opened in.
	// The server uses this to gate per-workspace broadcasts (live AI Logs +
	// MCP Activity) so events from sibling workspaces never reach this tab.
	// On switch we tear the socket down and reconnect with the new value.
	const activeWorkspaceId = useAppSelector(selectActiveWorkspaceId);

	const subscribe = useCallback<(channel: string, handler: MessageHandler) => () => void>((channel, handler) => {
		if (!messageHandlers.has(channel)) {
			messageHandlers.set(channel, new Set());
		}
		messageHandlers.get(channel)!.add(handler);

		// Return unsubscribe function
		return () => {
			const handlers = messageHandlers.get(channel);
			if (handlers) {
				handlers.delete(handler);
				if (handlers.size === 0) {
					messageHandlers.delete(channel);
				}
			}
		};
	}, []);

	const send = (data: any) => {
		if (wsRef.current?.readyState === WebSocket.OPEN) {
			try {
				wsRef.current.send(typeof data === "string" ? data : JSON.stringify(data));
			} catch (error) {
				console.error("Error sending message:", error);
			}
		}
	};

	// connectRef holds the latest `connect` function so the visibility /
	// focus / online listeners (registered once below) can always call
	// the freshest closure. Without this they'd be stale on rerender.
	const connectRef = useRef<() => Promise<void>>(async () => {});

	useEffect(() => {
		const connect = async () => {
			if (wsRef.current?.readyState === WebSocket.OPEN) {
				return;
			}
			// Cold-start gate: defer the FIRST connect until Redux has
			// hydrated activeWorkspaceId. Without this the socket opens
			// with no ?workspace_id=, the server falls back to tenant-wide
			// broadcasts (legacy path), and dev-ws events flash into the
			// prod-ws live feed for the rest of the session. The dedicated
			// activeWorkspaceId-change effect below will trigger reconnect
			// once hydration completes.
			if (!activeWorkspaceId) {
				return;
			}

			const wsUrl = getWebSocketUrl(path);
			// Obtain a short-lived, single-use ticket for WS auth instead of putting the session token in the URL.
			let wsUrlWithAuth = wsUrl;
			try {
				const resp = await fetch(`${getApiBaseUrl()}/session/ws-ticket`, {
					method: "POST",
					credentials: "include",
				});
				if (resp.ok) {
					const { ticket } = await resp.json();
					if (ticket) {
						const parsed = new URL(wsUrl);
						parsed.searchParams.set("ticket", ticket);
						if (activeWorkspaceId) {
							parsed.searchParams.set("workspace_id", activeWorkspaceId);
						}
						wsUrlWithAuth = parsed.toString();
					}
				}
			} catch {
				// If ticket fetch fails, attempt connection without auth param (cookie fallback)
			}
			// Even if the ticket flow failed, still propagate the workspace
			// so the server's per-workspace broadcast filter can pin this
			// connection - auth survives via the session cookie.
			if (wsUrlWithAuth === wsUrl && activeWorkspaceId) {
				const parsed = new URL(wsUrl);
				parsed.searchParams.set("workspace_id", activeWorkspaceId);
				wsUrlWithAuth = parsed.toString();
			}
			const ws = new WebSocket(wsUrlWithAuth);
			wsRef.current = ws;
			globalWsRef = ws;

			ws.onopen = () => {
				setIsConnected(true);
				retryCountRef.current = 0; // Reset retry count on successful connection

				// Clear any pending reconnection attempts
				if (reconnectTimeoutRef.current) {
					clearTimeout(reconnectTimeoutRef.current);
					reconnectTimeoutRef.current = null;
				}

				// Start heartbeat/ping to keep connection alive
				if (pingTimerRef.current) {
					clearInterval(pingTimerRef.current);
				}
				pingTimerRef.current = setInterval(() => {
					if (ws.readyState === WebSocket.OPEN) {
						try {
							ws.send("ping");
						} catch (error) {
							console.error("Error sending ping:", error);
						}
					}
				}, 25000); // Ping every 25 seconds
			};

			ws.onmessage = (event) => {
				try {
					const data = JSON.parse(event.data);
					const messageType = data.type || "default";

					// Notify all subscribers for this message type
					const handlers = messageHandlers.get(messageType);
					if (handlers) {
						handlers.forEach((handler) => handler(data));
					}

					// Also notify wildcard subscribers
					const wildcardHandlers = messageHandlers.get("*");
					if (wildcardHandlers) {
						wildcardHandlers.forEach((handler) => handler(data));
					}
				} catch (error) {
					console.error("Error parsing message:", error);
				}
			};

			ws.onclose = () => {
				setIsConnected(false);

				// Clear ping timer
				if (pingTimerRef.current) {
					clearInterval(pingTimerRef.current);
					pingTimerRef.current = null;
				}

				// Exponential backoff: 0.5s, 1s, 2s, 4s, 8s, 16s, 32s (max)
				retryCountRef.current = Math.min(retryCountRef.current + 1, 6);
				const delay = Math.pow(2, retryCountRef.current) * 500;

				// Go through connectRef so the reconnect picks up the LATEST
				// closure - workspace switches replace `connect` with a new
				// closure that includes the new activeWorkspaceId. Calling
				// the captured `connect` here would reconnect with whatever
				// workspace was active at the time this socket was opened.
				reconnectTimeoutRef.current = setTimeout(() => {
					void connectRef.current();
				}, delay);
			};

			ws.onerror = (error) => {
				setIsConnected(false);
				ws.close();
			};
		};

		connect();
		connectRef.current = connect;

		// Trigger an immediate reconnect when the tab regains focus,
		// the OS comes back online, or the browser fires `visibilitychange`
		// transitioning to visible. The default exponential backoff caps
		// at 32s between retries; without these listeners the "Not
		// connected" banner could linger up to 32 seconds after the user
		// returns to the tab even though the network is fine. We also
		// reset retryCount so the next attempt fires immediately rather
		// than waiting on the back-off clock.
		const triggerImmediateReconnect = () => {
			if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) return;
			if (reconnectTimeoutRef.current) {
				clearTimeout(reconnectTimeoutRef.current);
				reconnectTimeoutRef.current = null;
			}
			retryCountRef.current = 0;
			void connectRef.current();
		};

		const handleVisibilityChange = () => {
			if (typeof document !== "undefined" && document.visibilityState === "visible") {
				triggerImmediateReconnect();
			}
		};
		const handleOnline = () => triggerImmediateReconnect();
		const handleFocus = () => triggerImmediateReconnect();

		if (typeof document !== "undefined") {
			document.addEventListener("visibilitychange", handleVisibilityChange);
		}
		if (typeof window !== "undefined") {
			window.addEventListener("online", handleOnline);
			window.addEventListener("focus", handleFocus);
		}

		// Cleanup function
		return () => {
			// Don't close the WebSocket on unmount since it's global
			if (reconnectTimeoutRef.current) {
				clearTimeout(reconnectTimeoutRef.current);
				reconnectTimeoutRef.current = null;
			}
			if (pingTimerRef.current) {
				clearInterval(pingTimerRef.current);
				pingTimerRef.current = null;
			}
			if (typeof document !== "undefined") {
				document.removeEventListener("visibilitychange", handleVisibilityChange);
			}
			if (typeof window !== "undefined") {
				window.removeEventListener("online", handleOnline);
				window.removeEventListener("focus", handleFocus);
			}
		};
	}, [path, activeWorkspaceId]);

	// Workspace switch: the existing useEffect cleanup above tears down the
	// listeners but intentionally leaves the global socket open so other
	// tabs/components don't drop signal. On a workspace change we need the
	// socket itself to reconnect with the new ?workspace_id so the server
	// can re-pin its broadcast filter. Force-close here; the cleanup's
	// dependency on activeWorkspaceId will then re-run the connect path.
	const prevWorkspaceRef = useRef(activeWorkspaceId);
	useEffect(() => {
		if (prevWorkspaceRef.current === activeWorkspaceId) return;
		prevWorkspaceRef.current = activeWorkspaceId;
		if (wsRef.current && wsRef.current.readyState <= WebSocket.OPEN) {
			try {
				wsRef.current.close(1000, "workspace switch");
			} catch {
				// Best effort - the onclose handler will trigger reconnect.
			}
		}
	}, [activeWorkspaceId]);

	return <WebSocketContext.Provider value={{ isConnected, ws: wsRef, subscribe, send }}>{children}</WebSocketContext.Provider>;
}

export function useWebSocket() {
	const context = useContext(WebSocketContext);
	if (!context) {
		throw new Error("useWebSocket must be used within a WebSocketProvider");
	}
	return context;
}
