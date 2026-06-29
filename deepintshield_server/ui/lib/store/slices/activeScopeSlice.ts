import { createSlice, type PayloadAction } from "@reduxjs/toolkit";

const STORAGE_PREFIX = "dis_active_scope";
const LEGACY_STORAGE_KEY = "dis_active_scope";

export interface ActiveScopeState {
	activeOrgId: string | null;
	activeWorkspaceId: string | null;
	// User this scope is associated with - used to namespace the localStorage
	// entry so a different user signing in on the same machine doesn't pick
	// up the previous user's last selection.
	userId: string | null;
	// True once hydrateActiveScope has run with a non-null current user, so
	// consumers can distinguish "user hasn't loaded yet" from "no scope".
	hydrated: boolean;
}

interface PersistedShape {
	activeOrgId: string | null;
	activeWorkspaceId: string | null;
}

function storageKeyFor(userId: string): string {
	return `${STORAGE_PREFIX}:${userId}`;
}

export function readPersistedScope(userId: string): PersistedShape {
	if (typeof window === "undefined") return { activeOrgId: null, activeWorkspaceId: null };
	try {
		const raw = window.localStorage.getItem(storageKeyFor(userId));
		if (!raw) return { activeOrgId: null, activeWorkspaceId: null };
		const parsed = JSON.parse(raw) as Partial<PersistedShape>;
		return {
			activeOrgId: typeof parsed.activeOrgId === "string" ? parsed.activeOrgId : null,
			activeWorkspaceId: typeof parsed.activeWorkspaceId === "string" ? parsed.activeWorkspaceId : null,
		};
	} catch {
		return { activeOrgId: null, activeWorkspaceId: null };
	}
}

function writePersisted(userId: string, state: ActiveScopeState) {
	if (typeof window === "undefined") return;
	try {
		const payload: PersistedShape = {
			activeOrgId: state.activeOrgId,
			activeWorkspaceId: state.activeWorkspaceId,
		};
		window.localStorage.setItem(storageKeyFor(userId), JSON.stringify(payload));
	} catch {
		// Quota or private-mode storage error - non-fatal, switching still
		// works for the current tab; we just won't persist across reloads.
	}
}

function clearLegacyKey() {
	if (typeof window === "undefined") return;
	try {
		window.localStorage.removeItem(LEGACY_STORAGE_KEY);
	} catch {
		// see writePersisted
	}
}

const initialState: ActiveScopeState = {
	activeOrgId: null,
	activeWorkspaceId: null,
	userId: null,
	hydrated: false,
};

const activeScopeSlice = createSlice({
	name: "activeScope",
	initialState,
	reducers: {
		setActiveOrg(state, action: PayloadAction<string | null>) {
			state.activeOrgId = action.payload;
			// Org change always invalidates workspace selection - switcher must
			// pick a workspace within the new org before consumers see one.
			state.activeWorkspaceId = null;
			if (state.userId) writePersisted(state.userId, state);
		},
		setActiveWorkspace(state, action: PayloadAction<{ workspaceId: string | null; orgId?: string }>) {
			state.activeWorkspaceId = action.payload.workspaceId;
			if (action.payload.orgId) {
				state.activeOrgId = action.payload.orgId;
			}
			if (state.userId) writePersisted(state.userId, state);
		},
		setActiveScope(state, action: PayloadAction<{ orgId: string | null; workspaceId: string | null }>) {
			state.activeOrgId = action.payload.orgId;
			state.activeWorkspaceId = action.payload.workspaceId;
			state.hydrated = true;
			if (state.userId) writePersisted(state.userId, state);
		},
		// hydrateActiveScope is dispatched once on first load when both the
		// current user and the user's workspace list are available. It locks
		// the slice to the supplied userId, then restores their last pick
		// from localStorage if anything was saved - falling back to the
		// supplied defaults otherwise. Caller is responsible for validating
		// any restored IDs are still accessible to this user.
		hydrateActiveScope(
			state,
			action: PayloadAction<{
				userId: string;
				defaultOrgId: string | null;
				defaultWorkspaceId: string | null;
				restoredOrgId?: string | null;
				restoredWorkspaceId?: string | null;
			}>,
		) {
			const { userId, defaultOrgId, defaultWorkspaceId, restoredOrgId, restoredWorkspaceId } = action.payload;
			// User changed - drop the previous in-memory state so we don't
			// briefly show the wrong scope before the new user's persisted
			// pick is applied.
			if (state.userId !== userId) {
				state.activeOrgId = null;
				state.activeWorkspaceId = null;
			}
			state.userId = userId;
			if (!state.activeOrgId) {
				state.activeOrgId = restoredOrgId ?? defaultOrgId ?? null;
			}
			if (!state.activeWorkspaceId) {
				state.activeWorkspaceId = restoredWorkspaceId ?? defaultWorkspaceId ?? null;
			}
			state.hydrated = true;
			writePersisted(userId, state);
			// Drop the old global key once a user has loaded - it served the
			// pre-per-user version and is no longer authoritative.
			clearLegacyKey();
		},
		clearActiveScope(state) {
			// Clear in-memory + the user's persisted entry. Other users'
			// entries remain so a different account on the same machine
			// keeps its own last pick.
			if (state.userId && typeof window !== "undefined") {
				try {
					window.localStorage.removeItem(storageKeyFor(state.userId));
				} catch {
					// see writePersisted
				}
			}
			state.activeOrgId = null;
			state.activeWorkspaceId = null;
			state.userId = null;
			state.hydrated = false;
		},
	},
});

export const {
	setActiveOrg,
	setActiveWorkspace,
	setActiveScope,
	hydrateActiveScope,
	clearActiveScope,
} = activeScopeSlice.actions;

export default activeScopeSlice.reducer;

// Selectors typed against the local slice shape; consumers pull
// RootState["activeScope"] via useAppSelector.
export const selectActiveOrgId = (state: { activeScope: ActiveScopeState }) => state.activeScope.activeOrgId;
export const selectActiveWorkspaceId = (state: { activeScope: ActiveScopeState }) => state.activeScope.activeWorkspaceId;
export const selectActiveScopeHydrated = (state: { activeScope: ActiveScopeState }) => state.activeScope.hydrated;
