"use client";

import { Button } from "@/components/ui/button";
import { ArrowUpRight, Shuffle } from "lucide-react";

const ROUTING_RULES_DOCS_URL = "https://deepintshield.com";

interface RoutingRulesEmptyStateProps {
	onAddClick: () => void;
	canCreate?: boolean;
}

export function RoutingRulesEmptyState({ onAddClick, canCreate = true }: RoutingRulesEmptyStateProps) {
	return (
		<div
			className="flex min-h-[80vh] w-full flex-col items-center justify-center gap-4 py-16 text-center"
			data-testid="routing-rules-empty-state"
		>
			<div className="text-muted-foreground">
				<Shuffle className="h-[5.5rem] w-[5.5rem]" strokeWidth={1} />
			</div>
			<div className="flex flex-col gap-1">
				<h1 className="text-muted-foreground text-xl font-medium">Routing rules direct requests using CEL conditions</h1>
				<div className="text-muted-foreground mx-auto mt-2 max-w-[600px] text-sm font-normal">
					Create CEL-based rules to route requests by model, provider, budget, or custom attributes. Control which provider or model handles
					each workload.
				</div>
				<div className="mx-auto mt-6 flex flex-row flex-wrap items-center justify-center gap-2">
					{/* <Button
						variant="outline"
						aria-label="Read more about routing rules (opens in new tab)"
						data-testid="routing-rules-empty-read-more"
						onClick={() => {
							window.open(`${ROUTING_RULES_DOCS_URL}?utm_source=deepintshield_ui`, "_blank", "noopener,noreferrer");
						}}
					>
						Learn more <ArrowUpRight className="text-muted-foreground h-3 w-3" />
					</Button> */}
					<Button
						aria-label="Create your first routing rule"
						data-testid="create-routing-rule-btn"
						onClick={onAddClick}
						disabled={!canCreate}
					>
						New Rule
					</Button>
				</div>
			</div>
		</div>
	);
}
