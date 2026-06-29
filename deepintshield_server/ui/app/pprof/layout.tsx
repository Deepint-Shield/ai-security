"use client";

import { ThemeProvider } from "@/components/themeProvider";
import { ReduxProvider } from "@/lib/store";
import { isDevelopmentMode } from "@/lib/utils/port";
import { notFound } from "next/navigation";
import { Toaster } from "sonner";

export default function PprofLayout({ children }: { children: React.ReactNode }) {
	// Only allow access in development mode
	if (!isDevelopmentMode()) {
		notFound();
	}

	// pprof is a dev-only profiler dashboard with hand-tuned dark-only
	// styling (zinc-950 surface, zinc-800 dividers). Force-dark so the
	// app theme toggle doesn't leave it half-broken.
	return (
		<ThemeProvider attribute="class" defaultTheme="dark" enableSystem={false} forcedTheme="dark">
			<Toaster />
			<ReduxProvider>
				<div className="min-h-screen bg-zinc-950 text-zinc-100">{children}</div>
			</ReduxProvider>
		</ThemeProvider>
	);
}
