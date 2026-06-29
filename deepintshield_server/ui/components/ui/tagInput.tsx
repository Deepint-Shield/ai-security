"use client";

import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { X } from "lucide-react";
import React from "react";

type OmittedInputProps = Omit<React.InputHTMLAttributes<HTMLInputElement>, "value" | "onChange">;

interface TagInputProps extends OmittedInputProps {
	value: string[];
	onValueChange: (value: string[]) => void;
}

export const TagInput = React.forwardRef<HTMLInputElement, TagInputProps>(({ className, value, onValueChange, ...props }, ref) => {
	const [inputValue, setInputValue] = React.useState("");

	const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
		setInputValue(e.target.value);
	};

	const addCurrentTag = () => {
		const newTag = inputValue.trim();
		if (newTag && !value.includes(newTag)) {
			onValueChange([...value, newTag]);
		}
		setInputValue("");
	};

	const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
		if (e.key === "Enter" || e.key === ",") {
			e.preventDefault();
			addCurrentTag();
		} else if (e.key === "Backspace" && inputValue === "" && value.length > 0) {
			onValueChange(value.slice(0, -1));
		}
	};

	const handleBlur = () => {
		addCurrentTag();
	};

	const removeTag = (tagToRemove: string) => {
		onValueChange(value.filter((tag) => tag !== tagToRemove));
	};

	return (
		<div
			className={cn(
				"border-border/70 bg-background/68 flex flex-wrap items-center gap-2 rounded-xl border p-1.5 backdrop-blur-md",
				className,
			)}
		>
			{value.map((tag) => (
				<Badge
					key={tag}
					variant="secondary"
					className="border-primary/20 bg-primary/10 text-primary flex items-center gap-1 rounded-full border"
				>
					{tag}
					<button
						aria-label={`Remove ${tag}`}
						type="button"
						className="ring-offset-background focus:ring-ring cursor-pointer rounded-full outline-none focus:ring-2 focus:ring-offset-2"
						onClick={() => removeTag(tag)}
					>
						<X className="h-3 w-3" />
					</button>
				</Badge>
			))}
			<Input
				ref={ref}
				type="text"
				value={inputValue}
				onChange={handleInputChange}
				onKeyDown={handleKeyDown}
				onBlur={handleBlur}
				className={cn("h-7 min-w-32 flex-1 border-0 bg-transparent px-2 py-0 text-xs shadow-none focus-visible:ring-0")}
				{...props}
			/>
		</div>
	);
});

TagInput.displayName = "TagInput";
