"use client";

import { useEffect, useRef, type ReactNode } from "react";
import { Provider } from "react-redux";
import { baseApi } from "./apis/baseApi";
import { hydrateCachedQueries, startCachePersistence } from "./persistence";
import { store } from "./store";

interface ReduxProviderProps {
	children: ReactNode;
}

export function ReduxProvider({ children }: ReduxProviderProps) {
	// One-shot rehydrate + persistence subscription. Runs once on first
	// client mount; the ref-guard guards against StrictMode double-invoke
	// in dev (which would re-hydrate twice and write twice - harmless but
	// noisy). After this, every fulfilled RTK Query result is snapshotted
	// to localStorage (debounced) and replayed on the next page boot.
	const hydratedRef = useRef(false);
	useEffect(() => {
		if (hydratedRef.current) return;
		hydratedRef.current = true;
		// baseApi.util.upsertQueryData is typed by RTK Query with a
		// known-endpoint name (endpointName: never for an api with no
		// statically-declared endpoints), which isn't assignable to the
		// hydration helper's looser (endpoint: string, …) shape. The helper
		// only needs upsertQueryData structurally, so bridge the signature.
		hydrateCachedQueries(store, baseApi.util as unknown as Parameters<typeof hydrateCachedQueries>[1]);
		const unsubscribe = startCachePersistence(store);
		// Wipe the persisted cache on explicit logout (the auth flow already
		// fires this CustomEvent - see clearAuthStorage / dis:auth-clear).
		const onAuthClear = () => {
			try {
				window.localStorage.removeItem("dis-rtk-cache-v1");
			} catch {}
		};
		window.addEventListener("dis:auth-clear", onAuthClear);
		return () => {
			unsubscribe();
			window.removeEventListener("dis:auth-clear", onAuthClear);
		};
	}, []);

	return <Provider store={store}>{children}</Provider>;
}
