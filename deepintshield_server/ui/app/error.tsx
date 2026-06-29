"use client";

// Global Next.js error boundary. Catches any uncaught render error inside
// /app and renders a recovery UI instead of a blank white page. Next.js
// auto-passes `error` and `reset` props per the App Router contract:
// https://nextjs.org/docs/app/api-reference/file-conventions/error
//
// Page-specific boundaries (ChartErrorBoundary, AudioErrorBoundary) still
// catch first - this is the safety net that runs when none of those caught
// the error.

import Link from "next/link";
import { useEffect } from "react";

export default function GlobalError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
	useEffect(() => {
		// Surface to the browser console so the operator can copy the stack
		// from devtools when filing a bug. The digest is the server-side
		// correlation ID Next.js stamps on production errors.
		// eslint-disable-next-line no-console
		console.error("[GlobalError]", error);
	}, [error]);

	return (
		<main className="h-base flex items-center justify-center p-6">
			<div className="mx-auto w-full max-w-md text-center">
				<p className="text-destructive text-7xl font-bold tracking-tight">!</p>
				<h1 className="text-foreground mt-4 text-2xl font-semibold">Something went wrong</h1>
				<p className="text-muted-foreground mt-2 text-sm">
					This page hit an unexpected error. Try again, or head back to your workspace.
				</p>
				{error?.digest ? (
					<p className="text-muted-foreground/70 mt-2 font-mono text-xs">Reference: {error.digest}</p>
				) : null}
				<div className="mt-6 flex items-center justify-center gap-3">
					<button
						onClick={() => reset()}
						className="bg-primary text-primary-foreground focus-visible:ring-primary inline-flex items-center rounded-md px-4 py-2 text-sm font-medium shadow transition-opacity hover:opacity-90 focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none"
					>
						Try again
					</button>
					<Link
						href="/workspace/logs"
						className="border-border text-foreground hover:bg-muted/60 inline-flex items-center rounded-md border px-4 py-2 text-sm font-medium transition-colors"
					>
						Go home
					</Link>
				</div>
			</div>
		</main>
	);
}
