import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";

import { cn } from "@/lib/utils";

const alertVariants = cva(
	"relative grid w-full grid-cols-[0_1fr] items-start gap-y-0.5 rounded-[1.1rem] border px-4 py-3.5 text-sm shadow-[0_16px_34px_-28px_rgba(7,24,30,0.42)] has-[>svg]:grid-cols-[calc(var(--spacing)*4)_1fr] has-[>svg]:gap-x-3 [&>svg]:size-4 [&>svg]:translate-y-0.5 [&>svg]:text-current",
	{
		variants: {
			variant: {
				default: "border-border/70 bg-card/72 text-card-foreground backdrop-blur-xl",
				// Both destructive + info originally only had dark-mode
				// colour values, so the text was unreadable on the light
				// theme (light text on a translucent dark-tinted plate).
				// These two variants now ship a proper light-mode look
				// with `dark:` overrides to preserve the original
				// dark-mode treatment.
				destructive:
					"border-rose-300 bg-rose-50 text-rose-900 [&>svg]:text-rose-600 *:data-[slot=alert-description]:text-rose-800 dark:border-destructive/32 dark:bg-[rgba(114,36,28,0.2)] dark:text-destructive/90 dark:[&>svg]:text-destructive dark:*:data-[slot=alert-description]:text-destructive/78",
				info:
					"border-sky-300 bg-sky-50 text-sky-900 [&>svg]:text-sky-600 *:data-[slot=alert-description]:text-sky-800 dark:border-[#4ca8ff]/22 dark:bg-[rgba(34,95,150,0.18)] dark:text-[#e3f4ff] dark:[&>svg]:text-[#86d0ff] dark:*:data-[slot=alert-description]:text-[#c4e6ff]",
			},
		},
		defaultVariants: {
			variant: "default",
		},
	},
);

function Alert({ className, variant, ...props }: React.ComponentProps<"div"> & VariantProps<typeof alertVariants>) {
	return <div data-slot="alert" role="alert" className={cn(alertVariants({ variant }), className)} {...props} />;
}

function AlertTitle({ className, ...props }: React.ComponentProps<"div">) {
	return (
		<div data-slot="alert-title" className={cn("col-start-2 line-clamp-1 min-h-4 font-medium tracking-tight", className)} {...props} />
	);
}

function AlertDescription({ className, ...props }: React.ComponentProps<"div">) {
	return (
		<div
			data-slot="alert-description"
			className={cn("text-muted-foreground col-start-2 grid justify-items-start gap-1 text-sm [&_p]:leading-relaxed", className)}
			{...props}
		/>
	);
}

export { Alert, AlertDescription, AlertTitle };
