"use client";

import { DeepIntShieldWordmark } from "@/components/brand/deepIntShieldBrand";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";

// Docs lives outside the workspace shell - no sidebar, no tenant gate, just
// a slim top bar with the wordmark on the left and a single back-to-app
// link on the right. Pages handle their own layout under the bar.
export default function DocsLayout({ children }: { children: React.ReactNode }) {
	return (
		<div className="min-h-screen bg-background text-foreground">
			<header className="sticky top-0 z-30 border-b border-border/60 bg-background/85 backdrop-blur-md">
				<div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-6">
					<Link href="/docs" className="flex items-center gap-3">
						<DeepIntShieldWordmark compact />
						<span className="hidden text-xs font-semibold tracking-[0.18em] text-muted-foreground uppercase sm:inline">
							Documentation
						</span>
					</Link>
					<Link
						href="/workspace/dashboard"
						className="inline-flex items-center gap-1.5 rounded-full border border-border/70 bg-card px-3 py-1.5 text-xs font-medium text-foreground transition-colors hover:border-primary/40 hover:text-primary"
					>
						<ArrowLeft className="h-3.5 w-3.5" />
						Back to App
					</Link>
				</div>
			</header>
			<main className="mx-auto max-w-6xl px-6 py-8">{children}</main>
		</div>
	);
}
