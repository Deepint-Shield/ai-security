import { Button } from "@/components/ui/button";
import { ArrowUpRight, SquareTerminal } from "lucide-react";
import { usePromptContext } from "../context";

export function EmptyState() {
	const { setPromptSheet, canCreate } = usePromptContext();

	return (
		<div className="flex h-full items-center justify-center">
			<div className="flex flex-col items-center gap-3 text-center">
				<span className="bg-muted text-muted-foreground inline-flex h-12 w-12 items-center justify-center rounded-2xl">
					<SquareTerminal className="h-5 w-5" strokeWidth={1.75} />
				</span>
				<div className="space-y-1">
					<p className="text-foreground text-sm font-semibold">No prompt selected</p>
					<p className="text-muted-foreground text-xs">
						{canCreate ? (
							<>
								Select a prompt from the sidebar or{" "}
								<Button
									variant="link"
									className="h-auto p-0 text-xs"
									data-testid="empty-state-create-prompt-link"
									onClick={() => setPromptSheet({ open: true })}
								>
									create a new one
								</Button>
							</>
						) : (
							"Select a prompt from the sidebar"
						)}
					</p>
				</div>
			</div>
		</div>
	);
}

export function PromptsEmptyState() {
	const { setPromptSheet, canCreate } = usePromptContext();

	return (
		<div className="flex min-h-[80vh] w-full flex-col items-center justify-center gap-4 py-16 text-center">
			<div className="text-muted-foreground">
				<SquareTerminal className="h-[5.5rem] w-[5.5rem]" strokeWidth={1} />
			</div>
			<div className="flex flex-col gap-1">
				<h1 className="text-muted-foreground text-xl font-medium">Build, test, and version your prompts</h1>
				<div className="text-muted-foreground mx-auto mt-2 max-w-[600px] text-sm font-normal">
					{canCreate
						? "Create prompts, test them with different models and parameters in the playground, and version your changes for deployment."
						: "View prompts and test them with different models and parameters in the playground."}
				</div>
				<div className="mx-auto mt-6 flex flex-row flex-wrap items-center justify-center gap-2">
					<Button
						variant="outline"
						aria-label="Read more about prompt repository (opens in new tab)"
						data-testid="empty-state-read-more"
						onClick={() => {
							window.open("https://deepintshield.com", "_blank", "noopener,noreferrer");
						}}
					>
						Read more <ArrowUpRight className="text-muted-foreground h-3 w-3" />
					</Button>
					{canCreate && (
						<Button
							aria-label="Create your first prompt"
							data-testid="empty-state-create-prompt"
							onClick={() => setPromptSheet({ open: true })}
						>
							Create Prompt
						</Button>
					)}
				</div>
			</div>
		</div>
	);
}
