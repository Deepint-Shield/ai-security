"use client";

import { useEffect, useRef } from "react";
import { useTheme } from "next-themes";

import { useGetCurrentUserQuery, useUpdateCurrentUserMutation } from "@/lib/store/apis/sessionApi";

/**
 * Bridges the per-user `theme_preference` stored on the auth_users row
 * with the local next-themes state.
 *
 * On first session resolve:
 *   - If the user has a saved preference, apply it to next-themes (this
 *     overrides the localStorage default so the theme follows them
 *     across browsers).
 *
 * On subsequent local changes:
 *   - When the user picks a new theme via <ThemeToggle>, write it back
 *     to the server so the next browser they sign into sees it too.
 *
 * Mount this once in the workspace shell (clientLayout). The hook is
 * a no-op when the user isn't authenticated.
 */
export function useThemeSync() {
	const { data, isSuccess } = useGetCurrentUserQuery();
	const [updateCurrentUser] = useUpdateCurrentUserMutation();
	const { theme, setTheme } = useTheme();

	// Tracks whether we've applied the server preference to local state
	// yet. Without this we'd loop: server -> local -> server -> ...
	const initializedRef = useRef(false);
	// Tracks the last value we *sent* to the server, so we don't re-send
	// the same value on every render.
	const lastSyncedRef = useRef<string | null>(null);

	// 1. On first authenticated session, apply server preference to local.
	useEffect(() => {
		if (!isSuccess || !data?.user) return;
		if (initializedRef.current) return;
		const serverPref = data.user.theme_preference ?? null;
		if (serverPref === "light" || serverPref === "dark" || serverPref === "system") {
			if (theme !== serverPref) {
				setTheme(serverPref);
			}
			lastSyncedRef.current = serverPref;
		} else {
			// No saved server preference - current local value (could be
			// the default "dark", or something the user picked before
			// signing in) becomes the truth and gets written back.
			lastSyncedRef.current = theme ?? null;
		}
		initializedRef.current = true;
	}, [isSuccess, data?.user, theme, setTheme]);

	// 2. Push local changes back to the server (debounced via the ref).
	useEffect(() => {
		if (!initializedRef.current) return;
		if (!isSuccess || !data?.user) return;
		if (!theme) return;
		if (theme !== "light" && theme !== "dark" && theme !== "system") return;
		if (lastSyncedRef.current === theme) return;

		// Send only the theme delta - the profile endpoint accepts
		// partial updates because we passed the other fields as their
		// existing values would be required, but the backend just
		// treats theme_preference as optional. We send the current
		// values for the required fields too so validateProfileFields
		// doesn't reject the request.
		const u = data.user;
		updateCurrentUser({
			first_name: u.first_name,
			last_name: u.last_name,
			organization: u.organization,
			industry: u.industry,
			theme_preference: theme,
		})
			.unwrap()
			.catch(() => {
				// Silent - the local theme already changed. We'll retry on
				// the next user-initiated toggle.
			});
		lastSyncedRef.current = theme;
	}, [theme, isSuccess, data?.user, updateCurrentUser]);
}
