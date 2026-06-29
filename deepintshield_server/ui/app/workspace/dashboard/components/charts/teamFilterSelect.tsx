"use client";

import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

interface TeamOption {
	value: string;
	label: string;
}

interface TeamFilterSelectProps {
	teams: TeamOption[];
	selectedTeamId: string;
	onTeamChange: (teamId: string) => void;
	"data-testid"?: string;
}

export function TeamFilterSelect({ teams, selectedTeamId, onTeamChange, "data-testid": testId }: TeamFilterSelectProps) {
	return (
		<Select value={selectedTeamId} onValueChange={onTeamChange}>
			<SelectTrigger className="h-8 w-[128px] text-xs sm:w-[150px]" data-testid={testId}>
				<SelectValue placeholder="All Teams" />
			</SelectTrigger>
			<SelectContent>
				<SelectItem value="all">All Teams</SelectItem>
				{teams.map((team) => (
					<SelectItem key={team.value} value={team.value} className="text-xs">
						{team.label}
					</SelectItem>
				))}
			</SelectContent>
		</Select>
	);
}
