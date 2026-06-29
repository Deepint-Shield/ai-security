"use client";

import {
	AlertDialog,
	AlertDialogAction,
	AlertDialogCancel,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
} from "@/components/ui/alertDialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdownMenu";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { getErrorMessage, useUpdateProviderMutation } from "@/lib/store";
import { ModelProvider } from "@/lib/types/config";
import { cn } from "@/lib/utils";
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib";
import { AlertCircle, CheckCircle2, EllipsisIcon, KeyRound, PencilIcon, PlusIcon, TrashIcon } from "lucide-react";
import { ReactNode, useState } from "react";
import { toast } from "sonner";
import AddNewKeySheet from "../dialogs/addNewKeySheet";

interface Props {
	className?: string;
	provider: ModelProvider;
	headerActions?: ReactNode;
	isKeyless?: boolean;
	providerName?: string;
}

export default function ModelProviderKeysTableView({ provider, className, headerActions, isKeyless, providerName }: Props) {
	const isVLLM = (providerName ?? "").toLowerCase() === "vllm";
	const entityLabel = isVLLM ? "model" : "key";
	const entityLabelPlural = isVLLM ? "models" : "keys";
	const EntityLabel = entityLabel.charAt(0).toUpperCase() + entityLabel.slice(1);
	const hasUpdateProviderAccess = useRbac(RbacResource.ModelProvider, RbacOperation.Update);
	const hasDeleteProviderAccess = useRbac(RbacResource.ModelProvider, RbacOperation.Delete);
	const [updateProvider, { isLoading: isUpdatingProvider }] = useUpdateProviderMutation();
	const [showAddNewKeyDialog, setShowAddNewKeyDialog] = useState<{ show: boolean; keyIndex: number } | undefined>(undefined);
	const [showDeleteKeyDialog, setShowDeleteKeyDialog] = useState<{ show: boolean; keyIndex: number } | undefined>(undefined);

	function handleAddKey(keyIndex: number) {
		setShowAddNewKeyDialog({ show: true, keyIndex: keyIndex });
	}

	return (
		<div className={cn("w-full", className)}>
			{showDeleteKeyDialog && (
				<AlertDialog open={showDeleteKeyDialog.show}>
					<AlertDialogContent onClick={(e) => e.stopPropagation()}>
						<AlertDialogHeader>
							<AlertDialogTitle>Delete {EntityLabel}</AlertDialogTitle>
							<AlertDialogDescription>
								Are you sure you want to delete this {entityLabel}. This action cannot be undone.
							</AlertDialogDescription>
						</AlertDialogHeader>
						<AlertDialogFooter className="pt-4">
							<AlertDialogCancel onClick={() => setShowDeleteKeyDialog(undefined)} disabled={isUpdatingProvider}>
								Cancel
							</AlertDialogCancel>
							<AlertDialogAction
								disabled={isUpdatingProvider || !hasDeleteProviderAccess}
								onClick={() => {
									updateProvider({
										...provider,
										keys: provider.keys.filter((_, index) => index !== showDeleteKeyDialog.keyIndex),
									})
										.unwrap()
										.then(() => {
											toast.success(`${EntityLabel} deleted successfully`);
											setShowDeleteKeyDialog(undefined);
										})
										.catch((err) => {
											toast.error(`Failed to delete ${entityLabel}`, {
												description: getErrorMessage(err),
											});
										});
								}}
							>
								Delete
							</AlertDialogAction>
						</AlertDialogFooter>
					</AlertDialogContent>
				</AlertDialog>
			)}
			{showAddNewKeyDialog && (
				<AddNewKeySheet
					show={showAddNewKeyDialog.show}
					onCancel={() => setShowAddNewKeyDialog(undefined)}
					provider={provider}
					keyIndex={showAddNewKeyDialog.keyIndex}
					providerName={providerName}
				/>
			)}
			<header className="mb-4 flex flex-wrap items-center justify-between gap-3">
				<div className="flex items-center gap-2.5">
					<span className="bg-primary/12 text-primary inline-flex h-9 w-9 items-center justify-center rounded-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
						<KeyRound className="h-4 w-4" />
					</span>
					<div>
						<h2 className="text-base font-semibold leading-none tracking-tight">Configured {entityLabelPlural}</h2>
						<p className="text-muted-foreground mt-1 text-xs">
							{provider.keys.length} {provider.keys.length === 1 ? entityLabel : entityLabelPlural}
							{!isKeyless && provider.keys.length > 0 && "edit or remove keys"}
						</p>
					</div>
				</div>
				<div className="flex items-center gap-2">
					{headerActions}
					{!isKeyless && (
						<Button
							disabled={!hasUpdateProviderAccess}
							data-testid="add-key-btn"
							onClick={() => {
								handleAddKey(provider.keys.length);
							}}
						>
							<PlusIcon className="h-4 w-4" />
							Add new {entityLabel}
						</Button>
					)}
				</div>
			</header>
			{isKeyless ? (
				<div className="border-border/60 bg-card/40 text-muted-foreground flex flex-col items-center justify-center gap-1.5 rounded-2xl border px-6 py-12 text-center text-sm">
					<span className="bg-muted text-muted-foreground inline-flex h-10 w-10 items-center justify-center rounded-xl">
						<KeyRound className="h-4 w-4" strokeWidth={1.75} />
					</span>
					<p className="text-foreground text-sm font-semibold">Keyless provider</p>
					<p className="text-muted-foreground max-w-md text-xs">
						No API keys required. Use <span className="text-foreground font-medium">Edit Provider Config</span> to update settings.
					</p>
				</div>
			) : (
				<div className="border-border/60 bg-card/40 overflow-hidden rounded-2xl border shadow-[0_1px_0_rgba(255,255,255,0.04)_inset]">
					<Table className="w-full" data-testid="keys-table">
						<TableHeader className="bg-muted/30">
							<TableRow className="hover:bg-transparent">
								<TableHead className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">
									{isVLLM ? "Model" : "API Key"}
								</TableHead>
								<TableHead className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">
									Weight
								</TableHead>
								<TableHead className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em]">
									Enabled
								</TableHead>
								<TableHead className="text-right"></TableHead>
							</TableRow>
						</TableHeader>
						<TableBody>
							{provider.keys.length === 0 && (
								<TableRow data-testid="keys-table-empty-state" className="hover:bg-transparent">
									<TableCell colSpan={4} className="py-10 text-center">
										<div className="flex flex-col items-center gap-1.5">
											<span className="bg-muted text-muted-foreground inline-flex h-10 w-10 items-center justify-center rounded-xl">
												<KeyRound className="h-4 w-4" strokeWidth={1.75} />
											</span>
											<p className="text-foreground text-sm font-semibold">No {entityLabelPlural} yet</p>
											<p className="text-muted-foreground text-xs">
												Click <span className="text-foreground font-medium">Add new {entityLabel}</span> to get started.
											</p>
										</div>
									</TableCell>
								</TableRow>
							)}
							{provider.keys.map((key, index) => {
								const isKeyEnabled = key.enabled ?? true;
								return (
									<TableRow
										key={index}
										data-testid={`key-row-${key.name}`}
										className="border-border/40 hover:bg-primary/5 text-sm transition-colors"
										onClick={() => {}}
									>
										<TableCell>
											<div className="flex items-center gap-2.5">
												{key.status === "success" && (
													<Tooltip>
														<TooltipTrigger asChild>
															<span
																aria-label="Key status: list models working"
																data-testid={`key-status-success-${key.name}`}
																className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
															>
																<CheckCircle2 aria-hidden className="h-3.5 w-3.5" />
															</span>
														</TooltipTrigger>
														<TooltipContent>List models working</TooltipContent>
													</Tooltip>
												)}
												{key.status === "list_models_failed" && (
													<Tooltip>
														<TooltipTrigger asChild>
															<span
																aria-label="Key status: list models failed"
																data-testid={`key-status-error-${key.name}`}
																className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-amber-500/15 text-amber-600 dark:text-amber-400"
															>
																<AlertCircle aria-hidden className="h-3.5 w-3.5" />
															</span>
														</TooltipTrigger>
														<TooltipContent className="max-w-xs break-words">
															{key.description || "Model discovery failed for this key"}
														</TooltipContent>
													</Tooltip>
												)}
												<span className="font-mono text-sm font-medium">{key.name}</span>
											</div>
										</TableCell>
										<TableCell data-testid="key-weight-value">
											<Badge variant="outline" className="font-mono text-[11px] font-medium tabular-nums">
												{key.weight}
											</Badge>
										</TableCell>
										<TableCell>
											<Switch
												data-testid="key-enabled-switch"
												checked={isKeyEnabled}
												size="md"
												disabled={!hasUpdateProviderAccess}
												onCheckedChange={(checked) => {
													updateProvider({
														...provider,
														keys: provider.keys.map((k, i) => (i === index ? { ...k, enabled: checked } : k)),
													})
														.unwrap()
														.then(() => {
															toast.success(`${EntityLabel} ${checked ? "enabled" : "disabled"} successfully`);
														})
														.catch((err) => {
															toast.error(`Failed to update ${entityLabel}`, { description: getErrorMessage(err) });
														});
												}}
											/>
										</TableCell>
										<TableCell className="text-right">
											<DropdownMenu>
												<DropdownMenuTrigger asChild>
													<Button onClick={(e) => e.stopPropagation()} variant="ghost" size="sm">
														<EllipsisIcon className="h-4 w-4" />
													</Button>
												</DropdownMenuTrigger>
												<DropdownMenuContent align="end">
													<DropdownMenuItem
														onClick={() => {
															setShowAddNewKeyDialog({ show: true, keyIndex: index });
														}}
														disabled={!hasUpdateProviderAccess || !isKeyEnabled}
													>
														<PencilIcon className="mr-1 h-4 w-4" />
														Edit
													</DropdownMenuItem>
													<DropdownMenuItem
														onClick={() => {
															setShowDeleteKeyDialog({ show: true, keyIndex: index });
														}}
														disabled={!hasDeleteProviderAccess}
													>
														<TrashIcon className="mr-1 h-4 w-4" />
														Delete
													</DropdownMenuItem>
												</DropdownMenuContent>
											</DropdownMenu>
										</TableCell>
									</TableRow>
								);
							})}
						</TableBody>
					</Table>
				</div>
			)}
		</div>
	);
}
