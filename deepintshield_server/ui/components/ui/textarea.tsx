import * as React from "react";
import TextareaAutosize, { type TextareaAutosizeProps } from "react-textarea-autosize";

import { cn } from "@/lib/utils";

function Textarea({ className, ...props }: React.ComponentProps<"textarea">) {
	return (
		<textarea
			data-slot="textarea"
			className={cn(
				"border-border placeholder:text-muted-foreground aria-invalid:border-destructive focus-visible:border-primary bg-input/90 flex field-sizing-content min-h-16 w-full rounded-xl border px-4 py-3 text-base shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] backdrop-blur-md transition-[color,box-shadow,border-color] outline-none disabled:cursor-not-allowed disabled:opacity-50 md:text-sm",
				className,
			)}
			{...props}
		/>
	);
}

function AutoSizeTextarea({ className, ...props }: TextareaAutosizeProps) {
	return (
		<TextareaAutosize
			data-slot="textarea"
			className={cn(
				"border-border placeholder:text-muted-foreground aria-invalid:border-destructive focus-visible:border-primary bg-input/90 flex min-h-16 w-full rounded-xl border px-4 py-3 text-base shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] backdrop-blur-md transition-[color,box-shadow,border-color] outline-none disabled:cursor-not-allowed disabled:opacity-50 md:text-sm",
				className,
			)}
			{...props}
		/>
	);
}

export { Textarea, AutoSizeTextarea };
