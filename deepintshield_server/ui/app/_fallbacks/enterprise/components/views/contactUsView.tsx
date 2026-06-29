"use client";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { ArrowUpRight } from "lucide-react";

interface Props {
	className?: string;
	icon: React.ReactNode;
	title: string;
	description: string;
	readmeLink: string;
	align?: "middle" | "top";
	testIdPrefix?: string;
}

const normalizeDescription = (description: string) =>
	description
		.replace(
			/This feature is a part of the DeepIntShield enterprise license\./g,
			"This capability is available with DeepIntShield advanced controls.",
		)
		.replace(
			/This feature is part of the DeepIntShield enterprise license\./g,
			"This capability is available with DeepIntShield advanced controls.",
		)
		.replace(/DeepIntShield enterprise license/g, "DeepIntShield advanced controls")
		.replace(/DeepIntShield Enterprise/g, "DeepIntShield advanced controls")
		.replace(/DeepIntShield/g, "DeepIntShield");

const appendTrackingParam = (url: string) => `${url}${url.includes("?") ? "&" : "?"}utm_source=deepintshield_ui`;

export default function ContactUsView({ icon, title, description, className, readmeLink, align = "middle", testIdPrefix }: Props) {
	const normalizedDescription = normalizeDescription(description);
	const normalizedReadmeLink = readmeLink.includes("deepintshield.com") ? readmeLink : "https://deepintshield.com";

	return (
		<div className={cn("flex flex-col items-center gap-4 text-center", align === "middle" ? "justify-center" : "justify-start", className)}>
			<div className="text-muted-foreground">{icon}</div>
			<div className="flex flex-col gap-1">
				<h1 className="text-muted-foreground text-xl font-medium">{title}</h1>
				<div className="text-muted-foreground mt-2 max-w-[600px] text-sm font-normal">{normalizedDescription}</div>
				<div className="mx-auto flex flex-row items-center gap-2">
					<Button
						variant="outline"
						aria-label="Read more about this feature (opens in new tab)"
						className="mx-auto mt-6"
						data-testid={testIdPrefix ? `${testIdPrefix}-read-more` : undefined}
						onClick={() => {
							window.open(appendTrackingParam(normalizedReadmeLink), "_blank", "noopener,noreferrer");
						}}
					>
						Learn more <ArrowUpRight className="text-muted-foreground h-3 w-3" />
					</Button>
					<Button
						className="mx-auto mt-6"
						aria-label="Contact the DeepIntShield team (opens in new tab)"
						data-testid={testIdPrefix ? `${testIdPrefix}-book-demo` : undefined}
						onClick={() => {
							window.open("https://deepintshield.com", "_blank", "noopener,noreferrer");
						}}
					>
						Contact team
					</Button>
				</div>
			</div>
		</div>
	);
}
