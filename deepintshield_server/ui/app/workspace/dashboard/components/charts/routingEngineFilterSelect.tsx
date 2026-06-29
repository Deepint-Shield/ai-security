"use client";

import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { RoutingEngineUsedLabels } from "@/lib/constants/logs";

interface RoutingEngineFilterSelectProps {
	engines: string[];
	selectedEngine: string;
	onEngineChange: (engine: string) => void;
	"data-testid"?: string;
}

export function RoutingEngineFilterSelect({
	engines,
	selectedEngine,
	onEngineChange,
	"data-testid": testId,
}: RoutingEngineFilterSelectProps) {
	return (
		<Select value={selectedEngine} onValueChange={onEngineChange}>
			<SelectTrigger className="h-8 w-[128px] text-xs sm:w-[150px]" data-testid={testId}>
				<SelectValue placeholder="All Engines" />
			</SelectTrigger>
			<SelectContent>
				<SelectItem value="all">All Engines</SelectItem>
				{engines.filter(Boolean).map((engine) => {
					const label = (RoutingEngineUsedLabels as Record<string, string>)[engine] ?? engine;
					return (
						<SelectItem key={engine} value={engine} className="text-xs">
							{label}
						</SelectItem>
					);
				})}
			</SelectContent>
		</Select>
	);
}
