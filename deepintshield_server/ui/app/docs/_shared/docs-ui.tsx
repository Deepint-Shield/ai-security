"use client";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import GradientHeader from "@/components/ui/gradientHeader";
import { cn } from "@/lib/utils";
import { Check, ChevronLeft, Copy } from "lucide-react";
import Link from "next/link";
import { useCallback, useState } from "react";

export type IconType = React.ComponentType<{ className?: string }>;

export type AccentTone = "primary" | "blue" | "green" | "amber" | "red" | "purple" | "orange";

const accentChip: Record<AccentTone, string> = {
	primary: "bg-primary/12 text-primary",
	blue: "bg-blue-500/12 text-blue-600 dark:text-blue-400",
	green: "bg-emerald-500/12 text-emerald-600 dark:text-emerald-400",
	amber: "bg-amber-500/12 text-amber-600 dark:text-amber-400",
	red: "bg-rose-500/12 text-rose-600 dark:text-rose-400",
	purple: "bg-violet-500/12 text-violet-600 dark:text-violet-400",
	orange: "bg-orange-500/12 text-orange-600 dark:text-orange-400",
};

const accentSurface: Record<AccentTone, string> = {
	primary: "border-primary/20 bg-gradient-to-br from-primary/8 via-primary/4 to-transparent",
	blue: "border-blue-500/20 bg-gradient-to-br from-blue-500/8 via-blue-500/4 to-transparent",
	green: "border-emerald-500/20 bg-gradient-to-br from-emerald-500/8 via-emerald-500/4 to-transparent",
	amber: "border-amber-500/20 bg-gradient-to-br from-amber-500/8 via-amber-500/4 to-transparent",
	red: "border-rose-500/20 bg-gradient-to-br from-rose-500/8 via-rose-500/4 to-transparent",
	purple: "border-violet-500/20 bg-gradient-to-br from-violet-500/8 via-violet-500/4 to-transparent",
	orange: "border-orange-500/20 bg-gradient-to-br from-orange-500/8 via-orange-500/4 to-transparent",
};

export function AccentIcon({
	icon: Icon,
	tone = "primary",
	size = "md",
}: {
	icon: IconType;
	tone?: AccentTone;
	size?: "sm" | "md" | "lg";
}) {
	const dims = size === "sm" ? "h-8 w-8" : size === "lg" ? "h-11 w-11" : "h-10 w-10";
	const inner = size === "sm" ? "h-4 w-4" : size === "lg" ? "h-5 w-5" : "h-[18px] w-[18px]";
	return (
		<span
			className={cn(
				"inline-flex shrink-0 items-center justify-center rounded-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]",
				dims,
				accentChip[tone],
			)}
		>
			<Icon className={inner} />
		</span>
	);
}

export function CopyButton({ text }: { text: string }) {
	const [copied, setCopied] = useState(false);
	const handleCopy = useCallback(() => {
		navigator.clipboard.writeText(text);
		setCopied(true);
		setTimeout(() => setCopied(false), 2000);
	}, [text]);
	return (
		<button
			onClick={handleCopy}
			className="border-border/60 bg-background/70 text-muted-foreground hover:border-primary/40 hover:text-foreground absolute top-2.5 right-2.5 inline-flex h-7 w-7 items-center justify-center rounded-md border backdrop-blur-sm transition-colors"
			title={copied ? "Copied" : "Copy"}
			type="button"
		>
			{copied ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
		</button>
	);
}

export function CodeBlock({ code, language = "python", filename }: { code: string; language?: string; filename?: string }) {
	const label = filename ?? language;
	return (
		<div className="border-border/60 bg-card/40 group relative overflow-hidden rounded-xl border shadow-[0_1px_0_rgba(255,255,255,0.04)_inset]">
			<div className="border-border/50 bg-muted/40 flex items-center justify-between border-b px-3.5 py-2">
				<div className="flex items-center gap-2">
					<div className="flex items-center gap-1.5">
						<span className="h-2.5 w-2.5 rounded-full bg-rose-400/70" />
						<span className="h-2.5 w-2.5 rounded-full bg-amber-400/70" />
						<span className="h-2.5 w-2.5 rounded-full bg-emerald-400/70" />
					</div>
					<span className="text-muted-foreground ml-1.5 text-[10px] font-semibold tracking-[0.18em] uppercase">{label}</span>
				</div>
			</div>
			<div className="relative">
				<CopyButton text={code} />
				<pre className="text-foreground overflow-x-auto px-4 py-4 font-mono text-[12.5px] leading-relaxed whitespace-pre">{code}</pre>
			</div>
		</div>
	);
}

export function InlineCode({ children }: { children: React.ReactNode }) {
	return (
		<code className="border-border/60 bg-muted/60 text-foreground rounded-md border px-1.5 py-0.5 font-mono text-[12px]">{children}</code>
	);
}

export function SectionCard({
	id,
	icon,
	tone = "primary",
	title,
	description,
	badge,
	action,
	children,
}: {
	id?: string;
	icon: IconType;
	tone?: AccentTone;
	title: string;
	description?: React.ReactNode;
	badge?: string;
	action?: React.ReactNode;
	children: React.ReactNode;
}) {
	return (
		<Card id={id} className="scroll-mt-20">
			<CardHeader>
				<div className="flex items-start justify-between gap-3">
					<div className="flex items-start gap-3">
						<AccentIcon icon={icon} tone={tone} />
						<div className="min-w-0">
							<CardTitle className="flex flex-wrap items-center gap-2 text-lg">
								{title}
								{badge && (
									<Badge variant="secondary" className="rounded-full text-[10px] font-semibold tracking-[0.14em] uppercase">
										{badge}
									</Badge>
								)}
							</CardTitle>
							{description && <p className="text-muted-foreground mt-1 text-sm leading-relaxed">{description}</p>}
						</div>
					</div>
					{action}
				</div>
			</CardHeader>
			<CardContent className="space-y-4">{children}</CardContent>
		</Card>
	);
}

export function DocPageHeader({
	eyebrowIcon: EyebrowIcon,
	eyebrow,
	title,
	subtitle,
}: {
	eyebrowIcon: IconType;
	eyebrow: string;
	title: string;
	subtitle?: React.ReactNode;
}) {
	return (
		<div className="space-y-4">
			<Link
				href="/docs"
				className="text-muted-foreground hover:text-foreground inline-flex items-center gap-1 text-xs font-medium tracking-wide transition-colors"
			>
				<ChevronLeft className="h-3.5 w-3.5" />
				Back to Documentation
			</Link>
			<div className="border-primary/20 bg-primary/8 text-primary inline-flex items-center gap-2 rounded-full border px-3.5 py-1.5 text-xs font-semibold tracking-[0.14em] uppercase shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
				<EyebrowIcon className="h-3.5 w-3.5" />
				<span>{eyebrow}</span>
			</div>
			<GradientHeader title={title} />
			{subtitle && <p className="text-muted-foreground max-w-3xl text-base leading-relaxed sm:text-lg">{subtitle}</p>}
		</div>
	);
}

export function TocCard({ items }: { items: { id: string; label: string }[] }) {
	return (
		<Card className={accentSurface.primary}>
			<CardHeader>
				<div className="flex items-center justify-between">
					<CardTitle className="text-[11px] font-semibold tracking-[0.18em] uppercase">On This Page</CardTitle>
					<Badge variant="outline" className="rounded-full text-[10px] font-medium">
						{items.length} sections
					</Badge>
				</div>
			</CardHeader>
			<CardContent>
				<div className="grid gap-1 sm:grid-cols-2 lg:grid-cols-3">
					{items.map((item) => (
						<a
							key={item.id}
							href={`#${item.id}`}
							className="border-border/40 bg-background/40 text-muted-foreground hover:border-primary/40 hover:bg-primary/5 hover:text-foreground group flex items-center gap-2 rounded-lg border px-3 py-2 text-sm transition-all"
						>
							<span className="bg-muted-foreground/40 group-hover:bg-primary h-1.5 w-1.5 rounded-full transition-colors" />
							{item.label}
						</a>
					))}
				</div>
			</CardContent>
		</Card>
	);
}

export function Callout({
	icon,
	tone = "primary",
	title,
	children,
}: {
	icon: IconType;
	tone?: AccentTone;
	title?: string;
	children: React.ReactNode;
}) {
	return (
		<div className={cn("flex items-start gap-3 rounded-xl border p-4", accentSurface[tone])}>
			<AccentIcon icon={icon} tone={tone} size="sm" />
			<div className="flex-1">
				{title && <p className="text-foreground mb-0.5 text-sm font-semibold">{title}</p>}
				<div className="text-muted-foreground text-sm leading-relaxed">{children}</div>
			</div>
		</div>
	);
}

export function BulletList({ items, tone = "primary" }: { items: React.ReactNode[]; tone?: AccentTone }) {
	const dotColor: Record<AccentTone, string> = {
		primary: "bg-primary",
		blue: "bg-blue-500",
		green: "bg-emerald-500",
		amber: "bg-amber-500",
		red: "bg-rose-500",
		purple: "bg-violet-500",
		orange: "bg-orange-500",
	};
	return (
		<ul className="space-y-2">
			{items.map((item, i) => (
				<li key={i} className="text-muted-foreground flex items-start gap-2.5 text-sm leading-relaxed">
					<span className={cn("mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full", dotColor[tone])} />
					<span>{item}</span>
				</li>
			))}
		</ul>
	);
}

export function FieldLabel({ children }: { children: React.ReactNode }) {
	return <p className="text-foreground text-[10px] font-semibold tracking-[0.18em] uppercase">{children}</p>;
}

export function DataTable({ headers, rows }: { headers: string[]; rows: React.ReactNode[][] }) {
	return (
		<div className="border-border/60 bg-card/40 overflow-hidden rounded-xl border shadow-[0_1px_0_rgba(255,255,255,0.04)_inset]">
			<div className="overflow-x-auto">
				<table className="w-full text-sm">
					<thead className="bg-muted/30">
						<tr className="border-border/40 border-b">
							{headers.map((h) => (
								<th key={h} className="text-muted-foreground px-3.5 py-2.5 text-left text-[10px] font-semibold tracking-[0.16em] uppercase">
									{h}
								</th>
							))}
						</tr>
					</thead>
					<tbody>
						{rows.map((row, i) => (
							<tr key={i} className="border-border/30 hover:bg-primary/5 border-b transition-colors last:border-0">
								{row.map((cell, j) => (
									<td key={j} className="px-3.5 py-2.5 align-top">
										{cell}
									</td>
								))}
							</tr>
						))}
					</tbody>
				</table>
			</div>
		</div>
	);
}

export function StatTile({
	icon: Icon,
	label,
	value,
	tone = "primary",
}: {
	icon: IconType;
	label: string;
	value: React.ReactNode;
	tone?: AccentTone;
}) {
	return (
		<div className={cn("flex items-center gap-3 rounded-xl border p-3.5", accentSurface[tone])}>
			<AccentIcon icon={Icon} tone={tone} size="sm" />
			<div className="min-w-0">
				<p className="text-muted-foreground text-[10px] font-semibold tracking-[0.16em] uppercase">{label}</p>
				<p className="text-foreground mt-0.5 text-sm font-medium">{value}</p>
			</div>
		</div>
	);
}

export function StepCard({
	number,
	icon,
	title,
	description,
	children,
}: {
	number: number;
	icon: IconType;
	title: string;
	description?: string;
	children: React.ReactNode;
}) {
	const Icon = icon;
	return (
		<Card className="scroll-mt-20">
			<CardHeader>
				<div className="flex items-start gap-4">
					<div className="relative shrink-0">
						<div className="from-primary to-primary/70 text-primary-foreground flex h-11 w-11 items-center justify-center rounded-full bg-gradient-to-br text-base font-bold shadow-[inset_0_1px_0_rgba(255,255,255,0.25)]">
							{number}
						</div>
					</div>
					<div className="min-w-0">
						<CardTitle className="flex items-center gap-2 text-lg">
							<Icon className="text-primary h-[18px] w-[18px]" />
							{title}
						</CardTitle>
						{description && <p className="text-muted-foreground mt-1 text-sm leading-relaxed">{description}</p>}
					</div>
				</div>
			</CardHeader>
			<CardContent className="ml-[60px] space-y-4">{children}</CardContent>
		</Card>
	);
}

export function PageShell({ children }: { children: React.ReactNode }) {
	return (
		<div className="bg-transparent">
			<div className="workspace-page-shell-padded">
				<div className="space-y-7">{children}</div>
			</div>
		</div>
	);
}
