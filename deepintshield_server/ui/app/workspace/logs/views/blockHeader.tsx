// BlockHeader renders the section title for every group of fields in
// the request-details slide-out (Timings, Request Details, Tokens,
// Caching Details, etc.). Polished treatment: a primary-tinted leading
// dot or supplied icon, an uppercase tracked label for clear hierarchy,
// and a hairline divider that bleeds to the right so the header feels
// "anchored" rather than floating above the rows.
export default function BlockHeader({ title, icon }: { title: string; icon?: React.ReactNode }) {
	return (
		<div className="flex items-center gap-2.5 pb-1">
			{icon ? (
				<span className="text-primary inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-md border border-primary/20 bg-primary/10">
					{icon}
				</span>
			) : (
				<span
					aria-hidden
					className="bg-primary/70 inline-block h-1.5 w-1.5 shrink-0 rounded-full shadow-[0_0_0_3px_rgba(34,211,196,0.10)]"
				/>
			)}
			<div className="text-foreground text-[12px] font-semibold tracking-[0.12em] uppercase">{title}</div>
			<div aria-hidden className="ml-1 h-px flex-1 bg-gradient-to-r from-border/60 to-transparent" />
		</div>
	);
}
