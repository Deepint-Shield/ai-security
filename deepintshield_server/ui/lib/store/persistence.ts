// RTK Query localStorage persistence.
//
// Mounts to a warm cache across full browser reloads, hard refreshes, and tab
// restores by snapshotting the api slice to localStorage on every state change
// (debounced 1.5 s) and replaying it on the next boot.
//
// Why not redux-persist? We don't need its full reducer-rehydration machinery
// - RTK Query has internal state machines (subscription refcounts, timer
// handles, in-flight promises) that don't survive serialization. The safe API
// is `baseApi.util.upsertQueryData(endpoint, args, data)`, which inserts the
// result into the cache as if a network request had just landed, without
// touching the rest of the state. Hydrating through that surface means we
// never violate an RTK Query invariant.
//
// What gets persisted: only `fulfilled` queries. Pending requests would just
// re-fire on the next page; rejected requests aren't useful to replay. Each
// entry stores only `endpointName`, `originalArgs`, and `data` - the smallest
// blob needed to call upsertQueryData.
//
// Eviction strategy:
//   * 24 h max age (anything older is dropped on read - the user has been
//     gone long enough that the data is almost certainly stale anyway, and
//     the layer-1 RTK Query background refetch will land fresh data within
//     a few ms of the page mounting).
//   * Quota-exceeded → wipe the whole entry rather than partial-write, so
//     the next read doesn't choke on a corrupted JSON.
//   * Scope change (active org / workspace) → wipe immediately so a tenant
//     switch doesn't leak the previous tenant's cached data. Mirrored on
//     the server side by the X-Active-Tenant-Id header.

import type { Store } from "@reduxjs/toolkit";

const STORAGE_KEY = "dis-rtk-cache-v1";
const MAX_AGE_MS = 24 * 60 * 60 * 1000;
const WRITE_DEBOUNCE_MS = 1500;

// Match the reducerPath of baseApi without forcing a circular import.
const API_REDUCER_PATH = "api";

type PersistableEntry = {
	endpointName: string;
	originalArgs: unknown;
	data: unknown;
};

type Snapshot = {
	ts: number;
	queries: Record<string, PersistableEntry>;
};

function safeReadSnapshot(): Snapshot | null {
	if (typeof window === "undefined") return null;
	let raw: string | null = null;
	try {
		raw = window.localStorage.getItem(STORAGE_KEY);
	} catch {
		// localStorage can throw in private-browsing / disabled-cookies modes.
		// Treat as no cache - the network layer will fetch fresh.
		return null;
	}
	if (!raw) return null;
	try {
		const parsed = JSON.parse(raw) as Snapshot;
		if (!parsed || typeof parsed !== "object" || !parsed.queries) return null;
		if (!Number.isFinite(parsed.ts) || Date.now() - parsed.ts > MAX_AGE_MS) {
			try {
				window.localStorage.removeItem(STORAGE_KEY);
			} catch {}
			return null;
		}
		return parsed;
	} catch {
		// Corrupt JSON - wipe so future reads succeed.
		try {
			window.localStorage.removeItem(STORAGE_KEY);
		} catch {}
		return null;
	}
}

/**
 * Replay the persisted snapshot into the live RTK Query cache. Safe to call
 * multiple times - `upsertQueryData` is idempotent. Returns the number of
 * entries restored (for diagnostics / dev console).
 *
 * Pass the baseApi.util as `apiUtil` so this module stays free of a circular
 * import. Caller does:
 *
 *     import { baseApi } from "./apis/baseApi";
 *     hydrateCachedQueries(store, baseApi.util);
 */
export function hydrateCachedQueries(
	store: Store,
	apiUtil: { upsertQueryData: (endpoint: string, args: unknown, data: unknown) => unknown },
): number {
	const snap = safeReadSnapshot();
	if (!snap) return 0;
	let restored = 0;
	for (const entry of Object.values(snap.queries)) {
		if (!entry || !entry.endpointName || entry.data === undefined) continue;
		try {
			store.dispatch(apiUtil.upsertQueryData(entry.endpointName, entry.originalArgs, entry.data) as never);
			restored++;
		} catch {
			// A single bad entry shouldn't tank the whole rehydration -
			// skip it and continue. The network layer will repopulate on demand.
		}
	}
	return restored;
}

/**
 * Subscribe to store changes and snapshot the api slice to localStorage.
 * Debounced so a burst of upserts (e.g. dashboard mounting with 12 charts)
 * results in a single write. Returns an unsubscribe function.
 */
export function startCachePersistence(store: Store): () => void {
	if (typeof window === "undefined") return () => {};

	let timer: ReturnType<typeof setTimeout> | null = null;

	const writeNow = () => {
		const state = store.getState() as Record<string, unknown>;
		const apiSlice = state?.[API_REDUCER_PATH] as { queries?: Record<string, unknown> } | undefined;
		const queries = apiSlice?.queries ?? {};
		const persistable: Record<string, PersistableEntry> = {};
		for (const [key, raw] of Object.entries(queries)) {
			const entry = raw as { status?: string; endpointName?: string; originalArgs?: unknown; data?: unknown };
			if (!entry || entry.status !== "fulfilled" || entry.data === undefined || !entry.endpointName) {
				continue;
			}
			persistable[key] = {
				endpointName: entry.endpointName,
				originalArgs: entry.originalArgs,
				data: entry.data,
			};
		}
		const payload: Snapshot = { ts: Date.now(), queries: persistable };
		try {
			window.localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
		} catch {
			// QuotaExceededError or storage disabled - drop everything; we'd
			// rather have a smaller cache than a corrupt one.
			try {
				window.localStorage.removeItem(STORAGE_KEY);
			} catch {}
		}
	};

	return store.subscribe(() => {
		if (timer) clearTimeout(timer);
		timer = setTimeout(writeNow, WRITE_DEBOUNCE_MS);
	});
}

/**
 * Wipe the persisted cache. Called on tenant / workspace switch so a prior
 * scope's data never leaks into the next session, and on explicit logout.
 */
export function clearPersistedCache(): void {
	if (typeof window === "undefined") return;
	try {
		window.localStorage.removeItem(STORAGE_KEY);
	} catch {}
}
