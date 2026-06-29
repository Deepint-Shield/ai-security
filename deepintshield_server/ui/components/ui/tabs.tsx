"use client";

import * as TabsPrimitive from "@radix-ui/react-tabs";
import * as React from "react";

import { cn } from "@/lib/utils";

function Tabs({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Root>) {
	return <TabsPrimitive.Root data-slot="tabs" className={cn("flex flex-col gap-2", className)} {...props} />;
}

function TabsList({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.List>) {
	return (
		<TabsPrimitive.List
			data-slot="tabs-list"
			className={cn(
				// Bumped from h-9 → h-11 so the active trigger's shadow +
				// rounded background sit fully inside the list rather than
				// breaching it. Padding p-1 gives the trigger room to
				// breathe; centering the trigger vertically.
				"bg-secondary/72 text-muted-foreground border-border/70 inline-flex h-11 w-fit items-center justify-center rounded-xl border p-1 shadow-[inset_0_1px_0_rgba(255,255,255,0.08)] backdrop-blur-md",
				className,
			)}
			{...props}
		/>
	);
}

function TabsTrigger({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Trigger>) {
	return (
		<TabsPrimitive.Trigger
			data-slot="tabs-trigger"
			className={cn(
				// Active state: softer, theme-aware gradient that holds up
				// in both light and dark; foreground uses --foreground so
				// active labels read clearly on either palette.
				"text-muted-foreground focus-visible:border-ring focus-visible:ring-ring/50 data-[state=active]:border-primary/30 data-[state=active]:text-foreground inline-flex h-full flex-1 cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-transparent px-4 py-1.5 text-sm font-medium whitespace-nowrap transition-[color,box-shadow,background-color] focus-visible:ring-[3px] disabled:pointer-events-none disabled:opacity-50 data-[state=active]:bg-[linear-gradient(135deg,rgba(33,211,196,0.18),rgba(96,169,255,0.12))] data-[state=active]:shadow-[0_8px_16px_-12px_rgba(34,211,196,0.35)] dark:data-[state=active]:shadow-[0_10px_18px_-16px_rgba(34,211,196,0.44)] [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
				className,
			)}
			{...props}
		/>
	);
}

function TabsContent({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Content>) {
	return <TabsPrimitive.Content data-slot="tabs-content" className={cn("flex-1 outline-none", className)} {...props} />;
}

export { Tabs, TabsContent, TabsList, TabsTrigger };
