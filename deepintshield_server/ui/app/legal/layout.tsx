import type { Metadata } from "next";
import Image from "next/image";
import Link from "next/link";

import { LEGAL_ENTITY } from "@/lib/legal/versions";

export const metadata: Metadata = {
	title: "Legal - DeepintShield",
};

export default function LegalLayout({ children }: { children: React.ReactNode }) {
	return (
		<div className="min-h-screen bg-background text-foreground">
			<header className="border-b border-border/60 bg-card/40 backdrop-blur">
				<div className="mx-auto flex h-20 max-w-4xl items-center justify-between px-6">
					<Link href="/" className="flex h-full items-center py-2" aria-label="DeepintShield">
						<Image
							src="/deepintshield-logo-dark.png"
							alt="DeepintShield"
							width={64}
							height={64}
							className="h-full w-auto rounded-md object-contain"
							priority
						/>
					</Link>
					<nav className="flex items-center gap-5 text-sm">
						<Link href="/legal/terms" className="text-muted-foreground hover:text-foreground">
							Terms
						</Link>
						<Link href="/legal/privacy" className="text-muted-foreground hover:text-foreground">
							Privacy
						</Link>
					</nav>
				</div>
			</header>
			<main className="mx-auto max-w-3xl break-words px-6 py-10 leading-relaxed [hyphens:auto]">{children}</main>
			<footer className="border-t border-border/60 mt-16">
				<div className="mx-auto max-w-3xl px-6 py-6 text-xs text-muted-foreground">
					{LEGAL_ENTITY.tradeName} ({LEGAL_ENTITY.additionalTradeName}) ·
					GSTIN {LEGAL_ENTITY.gstin} · {LEGAL_ENTITY.address.city}, {LEGAL_ENTITY.address.state}
				</div>
			</footer>
		</div>
	);
}
