"use client";

import * as React from "react";
import * as SliderPrimitive from "@radix-ui/react-slider";

import { cn } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "./tooltip";

function Slider({
	className,
	defaultValue,
	value,
	min = 0,
	max = 100,
	thumbTooltipText,
	...props
}: React.ComponentProps<typeof SliderPrimitive.Root> & { thumbTooltipText?: string }) {
	const _values = React.useMemo(
		() => (Array.isArray(value) ? value : Array.isArray(defaultValue) ? defaultValue : [min]),
		[value, defaultValue, min],
	);

	return (
		<SliderPrimitive.Root
			data-slot="slider"
			defaultValue={defaultValue}
			value={value}
			min={min}
			max={max}
			className={cn(
				"relative flex w-full touch-none items-center select-none data-[disabled]:opacity-50 data-[orientation=vertical]:h-full data-[orientation=vertical]:min-h-44 data-[orientation=vertical]:w-auto data-[orientation=vertical]:flex-col",
				className,
			)}
			{...props}
		>
			<SliderPrimitive.Track
				data-slot="slider-track"
				className={cn(
					"bg-muted/55 border-border/70 relative grow overflow-hidden rounded-full border data-[orientation=horizontal]:h-2 data-[orientation=horizontal]:w-full data-[orientation=vertical]:h-full data-[orientation=vertical]:w-2",
				)}
			>
				<SliderPrimitive.Range
					data-slot="slider-range"
					className={cn(
						"via-primary absolute bg-linear-to-r from-[#2cf4e3] to-[#5cb7ff] data-[orientation=horizontal]:h-full data-[orientation=vertical]:w-full",
					)}
				/>
			</SliderPrimitive.Track>
			{Array.from({ length: _values.length }, (_, index) =>
				thumbTooltipText ? (
					<TooltipProvider key={index} delayDuration={100}>
						<Tooltip>
							<TooltipTrigger asChild>
								<SliderPrimitive.Thumb
									data-slot="slider-thumb"
									className="border-primary/70 ring-ring/50 bg-background block size-4 shrink-0 rounded-full border shadow-[0_0_0_3px_rgba(25,211,196,0.14),0_8px_18px_-12px_rgba(7,24,30,0.42)] transition-[color,box-shadow] hover:ring-4 focus-visible:ring-4 focus-visible:outline-hidden disabled:pointer-events-none disabled:opacity-50"
								/>
							</TooltipTrigger>
							<TooltipContent className="text-md w-[300px] font-normal">{thumbTooltipText}</TooltipContent>
						</Tooltip>
					</TooltipProvider>
				) : (
					<SliderPrimitive.Thumb
						data-slot="slider-thumb"
						key={index}
						className="border-primary/70 ring-ring/50 bg-background block size-4 shrink-0 rounded-full border shadow-[0_0_0_3px_rgba(25,211,196,0.14),0_8px_18px_-12px_rgba(7,24,30,0.42)] transition-[color,box-shadow] hover:ring-4 focus-visible:ring-4 focus-visible:outline-hidden disabled:pointer-events-none disabled:opacity-50"
					/>
				),
			)}
		</SliderPrimitive.Root>
	);
}

export { Slider };
