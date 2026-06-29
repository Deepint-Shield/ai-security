import { isValidElement } from "react";
import { cn } from "@/lib/utils";

interface Props {
	className?: string;
	containerClassName?: string;
	isBeta?: boolean;
	valueClassName?: string;
	label: string;
	value: React.ReactNode | null;
	hideExpandable?: boolean;
	orientation?: "horizontal" | "vertical";
	align?: "left" | "right";
}

export default function LogEntryDetailsView(props: Props) {
	if (props.value === null) {
		return null;
	}

	const renderValue = (value: React.ReactNode | null) => {
		if (value === null || value === undefined) {
			return "-";
		}
		if (typeof value === "boolean" || typeof value === "string" || typeof value === "number") {
			return String(value);
		}
		if (isValidElement(value)) {
			return value;
		}
		if (Array.isArray(value)) {
			const isRenderableArray = value.every(
				(item) =>
					item === null ||
					item === undefined ||
					typeof item === "boolean" ||
					typeof item === "string" ||
					typeof item === "number" ||
					isValidElement(item),
			);
			if (isRenderableArray) {
				return value.map((item, index) => (
					<span key={index}>
						{typeof item === "boolean" ? String(item) : item}
					</span>
				));
			}
		}
		try {
			return JSON.stringify(value, null, 2);
		} catch {
			return String(value);
		}
	};

	const orientation = props.orientation || "vertical";
	return (
		<div
			className={cn("items-top flex flex-col gap-2", {
				[`${props.className}`]: props.className !== undefined,
				"items-start": props.align === "left" || props.align === undefined,
				"items-end": props.align === "right",
			})}
		>
			<div className={props.containerClassName}>
				{props.label !== "" && (
					<div className="text-muted-foreground flex shrink-0 flex-row items-center gap-2 pb-1.5 text-[10px] font-semibold tracking-[0.14em] uppercase">
						{props.label.toUpperCase().replace(/_/g, " ")}
					</div>
				)}
				<div
					className={cn("text-md flex text-xs font-medium overflow-ellipsis transition-transform delay-75", {
						"w-full flex-col items-center gap-2": orientation === "horizontal",
						"flex-row items-start gap-2": orientation === "vertical",
						[`${props.valueClassName}`]: props.valueClassName !== undefined,
						"text-end": props.align === "right",
					})}
				>
					<div className="text-foreground flex-1 text-sm font-medium break-all">
						{renderValue(props.value)}
					</div>
				</div>
			</div>
		</div>
	);
}
