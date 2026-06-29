"use client";

import { cn } from "@/lib/utils";
import { DatabaseZap, ScrollText, ShieldCheck, ShieldUser, Telescope } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

const tabs = [
	{
		title: "Overview",
		href: "/workspace/rag-security",
		icon: ShieldCheck,
	},
	{
		title: "Sources",
		href: "/workspace/rag-security/sources",
		icon: DatabaseZap,
	},
	{
		title: "Policies",
		href: "/workspace/rag-security/policies",
		icon: ShieldUser,
	},
	{
		title: "Findings",
		href: "/workspace/rag-security/findings",
		icon: Telescope,
	},
	{
		title: "Traces",
		href: "/workspace/rag-security/traces",
		icon: ScrollText,
	},
];

export function RagSecurityShell({ children }: { children: React.ReactNode }) {
	const pathname = usePathname();

	return (
		<div className="workspace-page-shell-padded flex flex-col gap-6 py-6">
			<div className="flex flex-col gap-2">
				<div className="text-muted-foreground flex items-center gap-2 text-sm">
					<ShieldCheck className="h-4 w-4" />
					<span>RAG Security</span>
				</div>
				<h1 className="text-2xl font-semibold tracking-tight">RAG Security</h1>
				<p className="text-muted-foreground max-w-4xl text-sm">
					Protect retrieval pipelines with chunk-level scanning, source quarantine, runtime filtering, and explainable decision chains before
					grounded answers reach users.
				</p>
			</div>

			<div className="grid w-full grid-cols-2 gap-2 border-b pb-4 md:grid-cols-3 xl:grid-cols-5">
				{tabs.map((tab) => {
					const active = pathname === tab.href;
					const Icon = tab.icon;
					return (
						<Link
							key={tab.href}
							href={tab.href}
							className={cn(
								"inline-flex min-h-11 items-center justify-center gap-2 rounded-xl border px-3 py-2 text-sm text-center transition-colors",
								active
									? "border-primary bg-primary text-primary-foreground"
									: "bg-background text-muted-foreground hover:bg-accent hover:text-accent-foreground",
							)}
						>
							<Icon className="h-4 w-4" />
							{tab.title}
						</Link>
					);
				})}
			</div>

			{children}
		</div>
	);
}
