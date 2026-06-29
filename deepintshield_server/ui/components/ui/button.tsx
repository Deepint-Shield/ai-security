import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";

import { cn } from "@/lib/utils";
import { Loader2 } from "lucide-react";

const buttonVariants = cva(
	"inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-md text-sm font-semibold tracking-[0.01em] transition-all duration-150 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg:not([class*='size-'])]:size-4 shrink-0 [&_svg]:shrink-0 outline-none aria-invalid:border-destructive active:scale-[0.99]",
	{
		variants: {
			variant: {
				default:
					"border border-transparent bg-[linear-gradient(135deg,#17c5b5_0%,#86f3cf_100%)] text-[#041317] shadow-[0_16px_30px_-20px_rgba(16,191,174,0.62)] hover:brightness-105",
				destructive:
					"border border-transparent bg-[linear-gradient(135deg,#d7664d_0%,#f59b77_100%)] text-white shadow-[0_16px_30px_-20px_rgba(212,88,66,0.56)] hover:brightness-105",
				outline:
					"border border-border/80 bg-card/58 text-foreground backdrop-blur-md hover:border-primary/30 hover:bg-accent/80 hover:text-accent-foreground",
				secondary:
					"border border-border/70 bg-secondary/76 text-secondary-foreground shadow-[inset_0_1px_0_rgba(255,255,255,0.08)] hover:bg-secondary/92",
				ghost: "text-muted-foreground hover:bg-accent/80 hover:text-foreground",
				link: "text-primary underline-offset-4 hover:underline",
			},
			size: {
				default: "h-9 px-3 py-1.5 has-[>svg]:px-2.5",
				sm: "h-8 gap-1 px-2.5 has-[>svg]:px-2",
				lg: "h-10 px-4 has-[>svg]:px-3.5",
				icon: "size-9",
			},
		},
		defaultVariants: {
			variant: "default",
			size: "default",
		},
	},
);

function Button({
	className,
	variant,
	size,
	asChild = false,
	children,
	isLoading = false,
	dataTestId,
	...props
}: React.ComponentProps<"button"> &
	VariantProps<typeof buttonVariants> & {
		asChild?: boolean;
		isLoading?: boolean;
		dataTestId?: string;
	}) {
	return (
		<BaseButton className={className} variant={variant} size={size} asChild={asChild} dataTestId={dataTestId} {...props}>
			{isLoading ? <Loader2 className="size-4 animate-spin" /> : children}
		</BaseButton>
	);
}

function BaseButton({
	className,
	variant,
	size,
	asChild = false,
	dataTestId,
	...props
}: React.ComponentProps<"button"> &
	VariantProps<typeof buttonVariants> & {
		asChild?: boolean;
		dataTestId?: string;
	}) {
	const Comp = asChild ? Slot : "button";

	return (
		<Comp
			data-slot="button"
			data-testid={dataTestId}
			className={cn(buttonVariants({ variant, size, className }), "cursor-pointer")}
			{...props}
		/>
	);
}

export { Button, buttonVariants };
