"use client";

import { cn } from "@/lib/utils";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

// MarkdownText renders chat / log message content as proper formatted
// markdown (headings, bold, lists, code, tables) instead of raw text.
// Used inside the request-details slide-out where assistant replies
// often contain GitHub-flavoured markdown that previously rendered as
// monospace plain text. Components are typed to small Tailwind classes
// so the output sits comfortably inside narrow side-panels without
// pulling in @tailwindcss/typography.
export function MarkdownText({ content, className }: { content: string; className?: string }) {
	return (
		<div className={cn("text-sm leading-relaxed text-foreground space-y-2 break-words", className)}>
			<ReactMarkdown
				remarkPlugins={[remarkGfm]}
				components={{
					h1: ({ children }) => <h1 className="mt-3 text-base font-semibold tracking-tight">{children}</h1>,
					h2: ({ children }) => <h2 className="mt-3 text-sm font-semibold tracking-tight">{children}</h2>,
					h3: ({ children }) => <h3 className="mt-3 text-sm font-semibold tracking-tight">{children}</h3>,
					h4: ({ children }) => <h4 className="mt-2 text-sm font-semibold">{children}</h4>,
					p: ({ children }) => <p className="leading-relaxed">{children}</p>,
					strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
					em: ({ children }) => <em className="italic text-foreground/90">{children}</em>,
					ul: ({ children }) => <ul className="ml-5 list-disc space-y-1 marker:text-muted-foreground">{children}</ul>,
					ol: ({ children }) => <ol className="ml-5 list-decimal space-y-1 marker:text-muted-foreground">{children}</ol>,
					li: ({ children }) => <li className="leading-relaxed">{children}</li>,
					a: ({ href, children }) => (
						<a
							href={href}
							target="_blank"
							rel="noopener noreferrer"
							className="text-primary underline-offset-2 hover:underline"
						>
							{children}
						</a>
					),
					code: ({ children, className: cls, ...rest }) => {
						const isBlock = (cls || "").includes("language-");
						if (isBlock) {
							return (
								<code className="block rounded-lg border border-border/60 bg-muted/40 p-3 font-mono text-xs leading-relaxed overflow-x-auto" {...rest}>
									{children}
								</code>
							);
						}
						return (
							<code className="rounded bg-muted/60 px-1 py-0.5 font-mono text-[0.85em]" {...rest}>
								{children}
							</code>
						);
					},
					pre: ({ children }) => <pre className="my-2">{children}</pre>,
					blockquote: ({ children }) => (
						<blockquote className="border-l-2 border-primary/40 pl-3 text-muted-foreground italic">{children}</blockquote>
					),
					table: ({ children }) => (
						<div className="my-2 overflow-x-auto rounded-lg border border-border/60">
							<table className="w-full border-collapse text-xs">{children}</table>
						</div>
					),
					th: ({ children }) => <th className="bg-muted/40 px-2 py-1.5 text-left font-semibold border-b border-border/60">{children}</th>,
					td: ({ children }) => <td className="px-2 py-1.5 border-b border-border/30">{children}</td>,
					hr: () => <hr className="my-3 border-border/60" />,
				}}
			>
				{content}
			</ReactMarkdown>
		</div>
	);
}
