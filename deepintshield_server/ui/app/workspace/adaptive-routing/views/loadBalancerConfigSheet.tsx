"use client";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { getErrorMessage, useUpdateVirtualKeyMutation } from "@/lib/store";
import type { KeySelectionStrategy, VirtualKey } from "@/lib/types/governance";
import { useState } from "react";
import { toast } from "sonner";

const strategyDescriptions: Record<KeySelectionStrategy, string> = {
	weighted_random: "Selects keys randomly based on configured weights. Good for proportional traffic distribution.",
	round_robin: "Cycles through keys in order, distributing requests evenly regardless of weights.",
	least_load: "Routes to the key with the fewest active requests. Best for balancing load dynamically.",
};

interface LoadBalancerConfigSheetProps {
	virtualKey: VirtualKey;
	open: boolean;
	onClose: () => void;
}

export default function LoadBalancerConfigSheet({ virtualKey, open, onClose }: LoadBalancerConfigSheetProps) {
	const [updateVirtualKey, { isLoading }] = useUpdateVirtualKeyMutation();
	const [strategies, setStrategies] = useState<Record<number, KeySelectionStrategy>>(() => {
		const initial: Record<number, KeySelectionStrategy> = {};
		virtualKey.provider_configs?.forEach((pc, index) => {
			initial[index] = (pc.key_selection_strategy as KeySelectionStrategy) || "weighted_random";
		});
		return initial;
	});

	const handleSave = async () => {
		try {
			const providerConfigs = virtualKey.provider_configs?.map((pc, index) => ({
				id: pc.id,
				provider: pc.provider,
				weight: pc.weight,
				allowed_models: pc.allowed_models,
				key_selection_strategy: strategies[index],
				key_ids: pc.keys?.map((k) => k.key_id) || [],
			}));

			await updateVirtualKey({
				vkId: virtualKey.id,
				data: {
					provider_configs: providerConfigs,
				},
			}).unwrap();

			toast.success("Load balancing configuration updated");
			onClose();
		} catch (err) {
			toast.error(getErrorMessage(err));
		}
	};

	return (
		<Sheet open={open} onOpenChange={(isOpen) => !isOpen && onClose()}>
			<SheetContent className="flex flex-col gap-0 p-0 sm:max-w-xl">
				{/* Header band - soft brand wash + glow blob, anchors the
				    sheet visually so the form area below feels intentional
				    instead of a stranded card on white space. */}
				<div className="relative overflow-hidden border-b border-border/60 bg-[linear-gradient(135deg,rgba(13,122,112,0.08)_0%,rgba(44,95,207,0.05)_100%)] px-6 pb-5 pt-6 dark:bg-[linear-gradient(135deg,rgba(34,211,196,0.12)_0%,rgba(96,169,255,0.08)_100%)]">
					<div className="pointer-events-none absolute -top-20 right-[-8%] h-44 w-44 rounded-full bg-[radial-gradient(circle,rgba(13,122,112,0.18)_0%,transparent_70%)] blur-2xl dark:bg-[radial-gradient(circle,rgba(34,211,196,0.28)_0%,transparent_70%)]" />
					<SheetHeader className="relative space-y-1.5 p-0 text-left">
						<SheetTitle className="text-xl font-semibold tracking-[-0.02em]">Configure Load Balancing</SheetTitle>
						<SheetDescription>
							Strategy and key weighting for <strong className="text-foreground">{virtualKey.name}</strong>
						</SheetDescription>
					</SheetHeader>
				</div>

				{/* Scrollable body */}
				<div className="custom-scrollbar flex-1 overflow-y-auto px-6 py-5">
					<div className="flex flex-col gap-4">
						{virtualKey.provider_configs?.map((pc, index) => (
							<div
								key={pc.id || index}
								className="space-y-4 rounded-2xl border border-border/70 bg-card/60 p-4 shadow-[0_1px_2px_rgba(11,42,49,0.04)]"
							>
								<div className="flex items-center justify-between gap-3 border-b border-border/50 pb-3">
									<div className="flex items-center gap-2">
										<span className="inline-flex size-7 shrink-0 items-center justify-center rounded-md bg-primary/10 text-[11px] font-semibold uppercase tracking-wider text-primary">
											{pc.provider.slice(0, 2)}
										</span>
										<Label className="text-base font-semibold capitalize text-foreground">{pc.provider}</Label>
									</div>
									<Badge variant="secondary" className="text-[11px]">
										{pc.keys?.length || 0} key{(pc.keys?.length || 0) !== 1 ? "s" : ""}
									</Badge>
								</div>

								<div className="space-y-2">
									<Label className="text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
										Strategy
									</Label>
									<Select
										value={strategies[index] || "weighted_random"}
										onValueChange={(value) =>
											setStrategies((prev) => ({
												...prev,
												[index]: value as KeySelectionStrategy,
											}))
										}
									>
										<SelectTrigger className="w-full">
											<SelectValue />
										</SelectTrigger>
										<SelectContent>
											<SelectItem value="weighted_random">Weighted Random</SelectItem>
											<SelectItem value="round_robin">Round Robin</SelectItem>
											<SelectItem value="least_load">Least Load</SelectItem>
										</SelectContent>
									</Select>
									<p className="text-xs leading-5 text-muted-foreground">
										{strategyDescriptions[strategies[index] || "weighted_random"]}
									</p>
								</div>

								{pc.keys && pc.keys.length > 0 && (
									<div className="space-y-2 rounded-xl bg-muted/40 px-3 py-2.5">
										<Label className="text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
											Associated Keys
										</Label>
										<div className="flex flex-wrap gap-1.5">
											{pc.keys.map((key) => (
												<Badge key={key.key_id} variant="outline" className="bg-card text-[11px] font-medium">
													{key.name || key.key_id}
												</Badge>
											))}
										</div>
									</div>
								)}
							</div>
						))}
					</div>
				</div>

				{/* Sticky footer */}
				<div className="flex items-center justify-end gap-2 border-t border-border/60 bg-card/60 px-6 py-4">
					<Button variant="outline" onClick={onClose} className="min-w-[110px]">
						Cancel
					</Button>
					<Button onClick={handleSave} disabled={isLoading} className="min-w-[140px]">
						{isLoading ? "Saving..." : "Save Changes"}
					</Button>
				</div>
			</SheetContent>
		</Sheet>
	);
}
