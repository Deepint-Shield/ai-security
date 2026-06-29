"use client";

import { useGetCurrentUserQuery } from "@/lib/store/apis/sessionApi";
import { useCallback, useEffect, useState } from "react";

export type OnboardingStepId = "tenant" | "workspace" | "providers" | "members" | "teams" | "policies" | "keys";

export const ONBOARDING_STEP_ORDER: OnboardingStepId[] = ["tenant", "workspace", "providers", "members", "teams", "policies", "keys"];

// Per-user namespaced. The legacy global key was the same for everyone on a
// given browser, so once any user dismissed the modal nobody else ever saw
// it on first login. Same pattern as dis_active_scope:<userId>.
const STORAGE_KEY_PREFIX = "deepintshield-onboarding-v1";
const LEGACY_STORAGE_KEY = "deepintshield-onboarding-v1";

function storageKeyFor(userId: string | null | undefined): string {
	const trimmed = (userId ?? "").trim();
	if (!trimmed) {
		// Pre-auth callers (e.g. the modal renders during the brief window
		// before /api/session/me resolves) read/write a sentinel key that's
		// migrated into the per-user key the moment we know who the user
		// is. The sentinel sits in its own slot so it doesn't pollute the
		// previous user's saved state.
		return `${STORAGE_KEY_PREFIX}:__pending__`;
	}
	return `${STORAGE_KEY_PREFIX}:${trimmed}`;
}

type StoredState = {
	dismissed: boolean;
	completed: OnboardingStepId[];
	currentStep: OnboardingStepId | null;
	hasSeen: boolean;
};

const DEFAULT_STATE: StoredState = {
	dismissed: false,
	completed: [],
	currentStep: null,
	hasSeen: false,
};

function readState(userId: string | null | undefined): StoredState {
	if (typeof window === "undefined") return DEFAULT_STATE;
	try {
		const raw = window.localStorage.getItem(storageKeyFor(userId));
		if (!raw) return DEFAULT_STATE;
		const parsed = JSON.parse(raw) as Partial<StoredState>;
		return {
			dismissed: !!parsed.dismissed,
			completed: Array.isArray(parsed.completed) ? (parsed.completed.filter((s) => ONBOARDING_STEP_ORDER.includes(s as OnboardingStepId)) as OnboardingStepId[]) : [],
			currentStep: parsed.currentStep && ONBOARDING_STEP_ORDER.includes(parsed.currentStep as OnboardingStepId) ? (parsed.currentStep as OnboardingStepId) : null,
			hasSeen: !!parsed.hasSeen,
		};
	} catch {
		return DEFAULT_STATE;
	}
}

function writeState(userId: string | null | undefined, state: StoredState) {
	if (typeof window === "undefined") return;
	try {
		window.localStorage.setItem(storageKeyFor(userId), JSON.stringify(state));
	} catch {
		// localStorage may be unavailable (private mode, quota); the modal still works in-memory.
	}
}

// One-shot migration: the previous version stored under a single global key,
// which is why "Getting Started" stopped showing up on subsequent fresh
// signups. We move that legacy entry under the current user's namespace
// (preserving their dismissal preference) and drop the global key.
function migrateLegacyKey(userId: string) {
	if (typeof window === "undefined") return;
	try {
		const legacy = window.localStorage.getItem(LEGACY_STORAGE_KEY);
		if (legacy === null) return;
		const target = storageKeyFor(userId);
		// Don't overwrite an existing per-user entry - that user's pick is
		// already authoritative. Only rescue the legacy data when the new
		// key is empty.
		if (window.localStorage.getItem(target) === null) {
			window.localStorage.setItem(target, legacy);
		}
		window.localStorage.removeItem(LEGACY_STORAGE_KEY);
	} catch {
		// non-fatal - the modal will just default to showing
	}
}

// Per-login-session "shown this session" tracker. Lives in sessionStorage
// (NOT localStorage) so it auto-clears on tab close and is cleared on
// logout via clearAuthStorage. The combination is:
//
//   - dismissed (localStorage) - the user ticked "don't show on startup".
//     Persistent across logins. Hard suppression: never auto-opens again
//     for this user, anywhere, until they reset.
//   - shownThisSession (sessionStorage) - the modal already auto-opened
//     once during the current logged-in session. Stops the modal from
//     re-opening on every navigation / RTK refetch / scope switch.
//
// Result: exactly one auto-open per login session unless dismissed=true,
// in which case zero auto-opens. Manual sidebar trigger (openModal) and
// the OPEN_EVENT listener still work in either case.
const SESSION_SHOWN_KEY = "deepintshield-onboarding-shown-session";

function readShownThisSession(): boolean {
	if (typeof window === "undefined") return false;
	try {
		return window.sessionStorage.getItem(SESSION_SHOWN_KEY) === "1";
	} catch {
		return false;
	}
}

function markShownThisSession() {
	if (typeof window === "undefined") return;
	try {
		window.sessionStorage.setItem(SESSION_SHOWN_KEY, "1");
	} catch {
		// non-fatal - at worst the modal re-opens on the next mount this
		// session, which is the legacy behaviour.
	}
}

const OPEN_EVENT = "deepintshield-onboarding-open";

export function useOnboarding() {
	const { data: currentUserData } = useGetCurrentUserQuery();
	const userId = currentUserData?.user?.id ?? null;
	const [state, setState] = useState<StoredState>(DEFAULT_STATE);
	const [open, setOpen] = useState(false);
	const [hydrated, setHydrated] = useState(false);

	useEffect(() => {
		// Migrate the global legacy entry into this user's namespace as soon
		// as we have a user id - otherwise the first user on the machine
		// gets their preference rescued and subsequent users start fresh.
		if (userId) migrateLegacyKey(userId);
		const initial = readState(userId);
		setState(initial);
		setHydrated(true);
		// Auto-open exactly once per logged-in session: skip if the user
		// permanently dismissed (localStorage) OR if we already opened
		// once during this browser session (sessionStorage).
		if (!initial.dismissed && !readShownThisSession()) {
			setOpen(true);
			markShownThisSession();
		}
		const handleOpen = () => setOpen(true);
		window.addEventListener(OPEN_EVENT, handleOpen);
		return () => window.removeEventListener(OPEN_EVENT, handleOpen);
	}, [userId]);

	const persist = useCallback(
		(next: StoredState) => {
			setState(next);
			writeState(userId, next);
		},
		[userId],
	);

	const openModal = useCallback(() => {
		setOpen(true);
		if (typeof window !== "undefined") {
			window.dispatchEvent(new Event(OPEN_EVENT));
		}
	}, []);
	const closeModal = useCallback(() => {
		setOpen(false);
		persist({ ...state, hasSeen: true });
	}, [persist, state]);

	const setDismissed = useCallback(
		(value: boolean) => {
			persist({ ...state, dismissed: value, hasSeen: true });
		},
		[persist, state],
	);

	const markCompleted = useCallback(
		(id: OnboardingStepId) => {
			if (state.completed.includes(id)) return;
			persist({ ...state, completed: [...state.completed, id] });
		},
		[persist, state],
	);

	const toggleCompleted = useCallback(
		(id: OnboardingStepId) => {
			const next = state.completed.includes(id) ? state.completed.filter((s) => s !== id) : [...state.completed, id];
			persist({ ...state, completed: next });
		},
		[persist, state],
	);

	const setCurrentStep = useCallback(
		(id: OnboardingStepId | null) => {
			persist({ ...state, currentStep: id });
		},
		[persist, state],
	);

	const reset = useCallback(() => {
		persist({ ...DEFAULT_STATE });
		setOpen(true);
	}, [persist]);

	return {
		hydrated,
		open,
		dismissed: state.dismissed,
		completed: state.completed,
		currentStep: state.currentStep,
		hasSeen: state.hasSeen,
		openModal,
		closeModal,
		setDismissed,
		markCompleted,
		toggleCompleted,
		setCurrentStep,
		reset,
	};
}
