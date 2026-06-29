import { configureStore, createListenerMiddleware, isAnyOf } from "@reduxjs/toolkit";
import { baseApi } from "./apis/baseApi";
import { activeScopeReducer, appReducer, pluginReducer, providerReducer } from "./slices";
import {
	hydrateActiveScope,
	setActiveOrg,
	setActiveScope,
	setActiveWorkspace,
} from "./slices/activeScopeSlice";

// Import enterprise types for TypeScript
type EnterpriseState = {} & import("@enterprise/lib/store/slices").EnterpriseState;

// Get enterprise reducers if they are available
let enterpriseReducers = {};
try {
	const enterprise = require("@enterprise/lib/store/slices");
	// Use the explicit reducers map from enterprise slices
	if (enterprise.reducers) {
		enterpriseReducers = enterprise.reducers;
	}
} catch (e) {
	// Enterprise reducers not available, continue without them
}

// Inject enterprise APIs if they are available
try {
	const enterpriseApis = require("@enterprise/lib/store/apis");
	// Access the apis array to ensure all API modules are loaded
	// APIs are already injected into baseApi via injectEndpoints
	if (enterpriseApis.apis) {
		// Just accessing the array ensures all APIs are loaded
		baseApi.injectEndpoints(enterpriseApis.apis);
	}
} catch (e) {
	// Enterprise APIs not available, continue without them
}

// Listener that resets the RTK Query cache whenever the user picks a
// different tenant or workspace. Every cached query (logs, virtual keys,
// guardrails, MCP, model registry, members, prompts, audit, …) refetches
// against the new scope so the UI reflects the chosen tenant + workspace
// uniformly. We compare the stored scope before/after so dispatches that
// don't actually change the active IDs (e.g. hydration from persisted
// localStorage that matches what's already in state) are no-ops.
const scopeChangeListener = createListenerMiddleware();

scopeChangeListener.startListening({
	matcher: isAnyOf(setActiveOrg, setActiveWorkspace, setActiveScope, hydrateActiveScope),
	effect: async (_action, listenerApi) => {
		const previous = listenerApi.getOriginalState() as {
			activeScope?: { activeOrgId?: string | null; activeWorkspaceId?: string | null };
		};
		const current = listenerApi.getState() as {
			activeScope?: { activeOrgId?: string | null; activeWorkspaceId?: string | null };
		};
		const prevOrg = previous?.activeScope?.activeOrgId ?? null;
		const prevWs = previous?.activeScope?.activeWorkspaceId ?? null;
		const nextOrg = current?.activeScope?.activeOrgId ?? null;
		const nextWs = current?.activeScope?.activeWorkspaceId ?? null;
		if (prevOrg === nextOrg && prevWs === nextWs) return;
		listenerApi.dispatch(baseApi.util.resetApiState());
		// Also wipe the localStorage cache so the next page boot doesn't
		// hydrate the previous scope's data. The new scope's data will
		// repopulate on demand and re-snapshot via startCachePersistence.
		if (typeof window !== "undefined") {
			try {
				window.localStorage.removeItem("dis-rtk-cache-v1");
			} catch {}
		}
	},
});

export const store = configureStore({
	reducer: {
		// RTK Query API
		[baseApi.reducerPath]: baseApi.reducer,
		// App state slice
		app: appReducer,
		// Provider state slice
		provider: providerReducer,
		// Plugin state slice
		plugin: pluginReducer,
		// Active org + workspace selection
		activeScope: activeScopeReducer,
		// Enterprise reducers (if available)
		...enterpriseReducers,
	},
	middleware: (getDefaultMiddleware) =>
		getDefaultMiddleware({
			serializableCheck: {
				// Ignore these action types for RTK Query
				ignoredActions: [
					"persist/PERSIST",
					"persist/REHYDRATE",
					"api/executeQuery/pending",
					"api/executeQuery/fulfilled",
					"api/executeQuery/rejected",
					"api/executeMutation/pending",
					"api/executeMutation/fulfilled",
					"api/executeMutation/rejected",
				],
				// Ignore these field paths in all actions
				ignoredActionsPaths: ["meta.arg", "payload.timestamp"],
				// Ignore these paths in the state
				ignoredPaths: ["api.queries", "api.mutations"],
			},
		})
			.prepend(scopeChangeListener.middleware)
			.concat(baseApi.middleware),
	devTools: process.env.NODE_ENV !== "production",
});

export type RootState = ReturnType<typeof store.getState> & EnterpriseState;
export type AppDispatch = typeof store.dispatch;
