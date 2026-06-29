"use client";

import { Button } from "@/components/ui/button";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Label } from "@/components/ui/label";
import { ModelMultiselect } from "@/components/ui/modelMultiselect";
import NumberAndSelect from "@/components/ui/numberAndSelect";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { resetDurationOptions } from "@/lib/constants/governance";
import { RenderProviderIcon } from "@/lib/constants/icons";
import { ProviderLabels, ProviderName } from "@/lib/constants/logs";
import { getErrorMessage, useCreateModelConfigMutation, useGetProvidersQuery, useLazyGetModelsQuery, useUpdateModelConfigMutation } from "@/lib/store";
import { KnownProvider } from "@/lib/types/config";
import { ModelConfig } from "@/lib/types/governance";
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib";
import { zodResolver } from "@hookform/resolvers/zod";
import { Activity, Boxes, Coins, Gauge, PencilLine } from "lucide-react";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";

interface ModelLimitSheetProps {
	modelConfig?: ModelConfig | null;
	onSave: () => void;
	onCancel: () => void;
}

const formSchema = z.object({
	modelName: z.string().min(1, "Model name is required"),
	provider: z.string().optional(),
	budgetMaxLimit: z.string().optional(),
	budgetResetDuration: z.string().optional(),
	tokenMaxLimit: z.string().optional(),
	tokenResetDuration: z.string().optional(),
	requestMaxLimit: z.string().optional(),
	requestResetDuration: z.string().optional(),
});

type FormData = z.infer<typeof formSchema>;

export default function ModelLimitSheet({ modelConfig, onSave, onCancel }: ModelLimitSheetProps) {
	const [isOpen, setIsOpen] = useState(true);
	const isEditing = !!modelConfig;

	const hasCreateAccess = useRbac(RbacResource.Governance, RbacOperation.Create);
	const hasUpdateAccess = useRbac(RbacResource.Governance, RbacOperation.Update);
	const canSubmit = isEditing ? hasUpdateAccess : hasCreateAccess;

	const handleClose = () => {
		setIsOpen(false);
		setTimeout(() => {
			onCancel();
		}, 150);
	};

	const { data: providersData } = useGetProvidersQuery();
	const [createModelConfig, { isLoading: isCreating }] = useCreateModelConfigMutation();
	const [updateModelConfig, { isLoading: isUpdating }] = useUpdateModelConfigMutation();
	const [getModels] = useLazyGetModelsQuery();
	const isLoading = isCreating || isUpdating;

	const availableProviders = providersData || [];

	// Handle provider change - clear model if it doesn't exist for the new provider
	const handleProviderChange = async (newProvider: string, currentModel: string, onChange: (value: string) => void) => {
		onChange(newProvider);
		if (!currentModel) return;

		try {
			const response = await getModels({
				provider: newProvider || undefined,
				query: currentModel,
				limit: 50,
			}).unwrap();

			const modelExists = response.models.some((model) => model.name === currentModel);
			if (!modelExists) {
				form.setValue("modelName", "", { shouldDirty: true });
			}
		} catch {
			// On error, don't clear the model
		}
	};

	const form = useForm<FormData>({
		mode: "onChange",
		resolver: zodResolver(formSchema),
		defaultValues: {
			modelName: modelConfig?.model_name || "",
			provider: modelConfig?.provider || "",
			budgetMaxLimit: modelConfig?.budget ? String(modelConfig.budget.max_limit) : "",
			budgetResetDuration: modelConfig?.budget?.reset_duration || "1M",
			tokenMaxLimit: modelConfig?.rate_limit?.token_max_limit ? String(modelConfig.rate_limit.token_max_limit) : "",
			tokenResetDuration: modelConfig?.rate_limit?.token_reset_duration || "1h",
			requestMaxLimit: modelConfig?.rate_limit?.request_max_limit ? String(modelConfig.rate_limit.request_max_limit) : "",
			requestResetDuration: modelConfig?.rate_limit?.request_reset_duration || "1h",
		},
	});

	const parseLimit = (v: string | undefined) => { const n = parseFloat(v ?? ""); return !isNaN(n) && n > 0; };
	const hasAnyLimit = parseLimit(form.watch("budgetMaxLimit")) || parseLimit(form.watch("tokenMaxLimit")) || parseLimit(form.watch("requestMaxLimit"));

	useEffect(() => {
		if (modelConfig) {
			// Never reset form if user is editing - skip reset entirely
			if (form.formState.isDirty) {
				return;
			}
			form.reset({
				modelName: modelConfig.model_name || "",
				provider: modelConfig.provider || "",
				budgetMaxLimit: modelConfig.budget ? String(modelConfig.budget.max_limit) : "",
				budgetResetDuration: modelConfig.budget?.reset_duration || "1M",
				tokenMaxLimit: modelConfig.rate_limit?.token_max_limit ? String(modelConfig.rate_limit.token_max_limit) : "",
				tokenResetDuration: modelConfig.rate_limit?.token_reset_duration || "1h",
				requestMaxLimit: modelConfig.rate_limit?.request_max_limit ? String(modelConfig.rate_limit.request_max_limit) : "",
				requestResetDuration: modelConfig.rate_limit?.request_reset_duration || "1h",
			});
		}
	}, [modelConfig, form]);

	const onSubmit = async (data: FormData) => {
		if (!canSubmit) {
			toast.error("You don't have permission to perform this action");
			return;
		}

		try {
			const budgetMaxLimit = data.budgetMaxLimit ? parseFloat(data.budgetMaxLimit) : undefined;
			const tokenMaxLimit = data.tokenMaxLimit ? parseInt(data.tokenMaxLimit) : undefined;
			const requestMaxLimit = data.requestMaxLimit ? parseInt(data.requestMaxLimit) : undefined;
			const provider = data.provider && data.provider.trim() !== "" ? data.provider : undefined;

			if (isEditing && modelConfig) {
				const hadBudget = !!modelConfig.budget;
				const hasBudget = !!budgetMaxLimit;
				const hadRateLimit = !!modelConfig.rate_limit;
				const hasRateLimit = !!tokenMaxLimit || !!requestMaxLimit;

				let budgetPayload: { max_limit?: number; reset_duration?: string } | undefined;
				if (hasBudget) {
					budgetPayload = {
						max_limit: budgetMaxLimit,
						reset_duration: data.budgetResetDuration || "1M",
					};
				} else if (hadBudget) {
					budgetPayload = {};
				}

				let rateLimitPayload:
					| {
						token_max_limit?: number | null;
						token_reset_duration?: string | null;
						request_max_limit?: number | null;
						request_reset_duration?: string | null;
					}
					| undefined;
				if (hasRateLimit) {
					rateLimitPayload = {
						token_max_limit: tokenMaxLimit ?? null,
						token_reset_duration: tokenMaxLimit ? data.tokenResetDuration || "1h" : null,
						request_max_limit: requestMaxLimit ?? null,
						request_reset_duration: requestMaxLimit ? data.requestResetDuration || "1h" : null,
					};
				} else if (hadRateLimit) {
					rateLimitPayload = {};
				}

				await updateModelConfig({
					id: modelConfig.id,
					data: {
						model_name: data.modelName,
						provider: provider,
						budget: budgetPayload,
						rate_limit: rateLimitPayload,
					},
				}).unwrap();
				toast.success("Model limit updated successfully");
			} else {
				await createModelConfig({
					model_name: data.modelName,
					provider,
					budget: budgetMaxLimit
						? {
							max_limit: budgetMaxLimit,
							reset_duration: data.budgetResetDuration || "1M",
						}
						: undefined,
					rate_limit:
						tokenMaxLimit || requestMaxLimit
							? {
								token_max_limit: tokenMaxLimit,
								token_reset_duration: data.tokenResetDuration || "1h",
								request_max_limit: requestMaxLimit,
								request_reset_duration: data.requestResetDuration || "1h",
							}
							: undefined,
				}).unwrap();
				toast.success("Model limit created successfully");
			}

			onSave();
		} catch (error) {
			toast.error(getErrorMessage(error));
		}
	};

	return (
		<Sheet open={isOpen} onOpenChange={(open) => !open && handleClose()}>
			<SheetContent
				className="flex w-full flex-col overflow-x-hidden p-0"
				onInteractOutside={(e) => { if (isEditing ? form.formState.isDirty : (!!form.watch("modelName") || hasAnyLimit)) e.preventDefault(); }}
				onEscapeKeyDown={(e) => { if (isEditing ? form.formState.isDirty : (!!form.watch("modelName") || hasAnyLimit)) e.preventDefault(); }}
				data-testid="model-limit-sheet"
			>
				{/* Header */}
				<SheetHeader className="border-border/60 bg-muted/30 flex flex-row items-center gap-3 border-b px-6 py-4 space-y-0">
					<span className="bg-primary/12 text-primary inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
						{isEditing ? <PencilLine className="h-4 w-4" /> : <Gauge className="h-4 w-4" />}
					</span>
					<div className="flex-1 min-w-0">
						<div className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em] leading-none">
							Model Hub
						</div>
						<SheetTitle className="mt-1 text-base font-semibold leading-tight tracking-tight">
							{isEditing ? "Edit Model Limit" : "Create Model Limit"}
						</SheetTitle>
					</div>
				</SheetHeader>

				<Form {...form}>
					<form onSubmit={form.handleSubmit(onSubmit)} className="flex h-full flex-col">
						<div className="custom-scrollbar flex-1 space-y-5 overflow-y-auto px-6 py-5">
							{/* Section: Target */}
							<section className="space-y-3">
								<SectionHeader icon={<Boxes className="h-3.5 w-3.5" />} title="Model & Provider" />
								<FormField
									control={form.control}
									name="provider"
									render={({ field }) => (
										<FormItem>
											<FormLabel>Provider</FormLabel>
											<Select
												value={field.value || "all"}
												onValueChange={(value) => handleProviderChange(value === "all" ? "" : value, form.getValues("modelName"), field.onChange)}
												disabled={isEditing}
											>
												<FormControl>
													<SelectTrigger className="w-full" data-testid="model-limit-provider-select">
														<SelectValue placeholder="All Providers" />
													</SelectTrigger>
												</FormControl>
												<SelectContent>
													<SelectItem value="all">All Providers</SelectItem>
													{availableProviders.filter((p) => p.name).map((provider) => (
														<SelectItem key={provider.name} value={provider.name}>
															<RenderProviderIcon
																provider={provider.custom_provider_config?.base_provider_type || (provider.name as KnownProvider)}
																size="sm"
																className="h-4 w-4"
															/>
															{provider.custom_provider_config
																? provider.name
																: ProviderLabels[provider.name as ProviderName] || provider.name}
														</SelectItem>
													))}
												</SelectContent>
											</Select>
											<FormMessage />
										</FormItem>
									)}
								/>

								<FormField
									control={form.control}
									name="modelName"
									render={({ field }) => (
										<FormItem>
											<FormLabel>Model Name</FormLabel>
											<FormControl>
												<div data-testid="model-limit-model-select">
													<ModelMultiselect
														provider={form.watch("provider") || undefined}
														value={field.value}
														onChange={field.onChange}
														placeholder="Search for a model..."
														isSingleSelect
														loadModelsOnEmptyProvider="base_models"
														disabled={isEditing}
													/>
												</div>
											</FormControl>
											<FormMessage />
										</FormItem>
									)}
								/>
							</section>

							{/* Section: Budget */}
							<section className="border-border/60 bg-card/40 space-y-3 rounded-2xl border p-4">
								<SectionHeader icon={<Coins className="h-3.5 w-3.5" />} title="Budget" subtitle="Cap spend per period." />
								<FormField
									control={form.control}
									name="budgetMaxLimit"
									render={({ field }) => (
										<FormItem>
											<NumberAndSelect
												id="modelBudgetMaxLimit"
												labelClassName="font-normal"
												label="Maximum Spend (USD)"
												value={field.value || ""}
												selectValue={form.watch("budgetResetDuration") || "1M"}
												onChangeNumber={(value) => field.onChange(value)}
												onChangeSelect={(value) => form.setValue("budgetResetDuration", value, { shouldDirty: true })}
												options={resetDurationOptions}
											/>
											<FormMessage />
										</FormItem>
									)}
								/>
							</section>

							{/* Section: Rate Limits */}
							<section className="border-border/60 bg-card/40 space-y-3 rounded-2xl border p-4">
								<SectionHeader icon={<Activity className="h-3.5 w-3.5" />} title="Rate Limits" subtitle="Throttle traffic per period." />
								<FormField
									control={form.control}
									name="tokenMaxLimit"
									render={({ field }) => (
										<FormItem>
											<NumberAndSelect
												id="modelTokenMaxLimit"
												labelClassName="font-normal"
												label="Maximum Tokens"
												value={field.value || ""}
												selectValue={form.watch("tokenResetDuration") || "1h"}
												onChangeNumber={(value) => field.onChange(value)}
												onChangeSelect={(value) => form.setValue("tokenResetDuration", value, { shouldDirty: true })}
												options={resetDurationOptions}
											/>
											<FormMessage />
										</FormItem>
									)}
								/>

								<FormField
									control={form.control}
									name="requestMaxLimit"
									render={({ field }) => (
										<FormItem>
											<NumberAndSelect
												id="modelRequestMaxLimit"
												labelClassName="font-normal"
												label="Maximum Requests"
												value={field.value || ""}
												selectValue={form.watch("requestResetDuration") || "1h"}
												onChangeNumber={(value) => field.onChange(value)}
												onChangeSelect={(value) => form.setValue("requestResetDuration", value, { shouldDirty: true })}
												options={resetDurationOptions}
											/>
											<FormMessage />
										</FormItem>
									)}
								/>
							</section>

							{/* Current Usage Display (for editing) */}
							{isEditing && (modelConfig?.budget || modelConfig?.rate_limit) && (
								<section className="border-border/60 bg-card/40 space-y-3 rounded-2xl border p-4">
									<SectionHeader icon={<Gauge className="h-3.5 w-3.5" />} title="Current Usage" />
									<div className="grid grid-cols-2 gap-3">
										{modelConfig?.budget && (
											<div className="bg-card border-border/60 space-y-1 rounded-xl border p-3">
												<p className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.14em]">Budget</p>
												<p className="font-mono text-sm font-medium tabular-nums">
													${modelConfig.budget.current_usage.toFixed(2)} / ${modelConfig.budget.max_limit.toFixed(2)}
												</p>
											</div>
										)}
										{modelConfig?.rate_limit?.token_max_limit && (
											<div className="bg-card border-border/60 space-y-1 rounded-xl border p-3">
												<p className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.14em]">Tokens</p>
												<p className="font-mono text-sm font-medium tabular-nums">
													{modelConfig.rate_limit.token_current_usage.toLocaleString()} /{" "}
													{modelConfig.rate_limit.token_max_limit.toLocaleString()}
												</p>
											</div>
										)}
										{modelConfig?.rate_limit?.request_max_limit && (
											<div className="bg-card border-border/60 space-y-1 rounded-xl border p-3">
												<p className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.14em]">Requests</p>
												<p className="font-mono text-sm font-medium tabular-nums">
													{modelConfig.rate_limit.request_current_usage.toLocaleString()} /{" "}
													{modelConfig.rate_limit.request_max_limit.toLocaleString()}
												</p>
											</div>
										)}
									</div>
								</section>
							)}
						</div>

						{/* Sticky Footer */}
						<div className="border-border/60 bg-card/60 sticky bottom-0 border-t px-6 py-4 backdrop-blur">
							<div className="flex justify-end gap-3">
								<Button type="button" variant="outline" onClick={handleClose}>
									Cancel
								</Button>
								<TooltipProvider>
									<Tooltip>
										<TooltipTrigger asChild>
											<span className="inline-block">
												<Button type="submit" data-testid="model-limit-button-submit" disabled={isLoading || !form.formState.isDirty || !form.formState.isValid || !canSubmit || !form.watch("modelName") || !hasAnyLimit}>
													{isLoading ? "Saving..." : isEditing ? "Save Changes" : "Create Limit"}
												</Button>
											</span>
										</TooltipTrigger>
										{(isLoading || !form.formState.isDirty || !form.formState.isValid || !canSubmit || !form.watch("modelName") || !hasAnyLimit) && (
											<TooltipContent>
												<p>
													{!canSubmit
														? "You don't have permission"
														: isLoading
															? "Saving..."
															: !form.formState.isDirty
																? "No changes made"
																: !form.watch("modelName")
																	? "Model name is required"
																	: !hasAnyLimit
																		? "At least one budget or rate limit is required"
																		: "Please fix validation errors"}
												</p>
											</TooltipContent>
										)}
									</Tooltip>
								</TooltipProvider>
							</div>
						</div>
					</form>
				</Form>
			</SheetContent>
		</Sheet>
	);
}

function SectionHeader({ icon, title, subtitle }: { icon: React.ReactNode; title: string; subtitle?: string }) {
	return (
		<div className="flex items-center gap-2">
			<span className="text-muted-foreground inline-flex h-6 w-6 items-center justify-center rounded-md bg-muted">
				{icon}
			</span>
			<div className="flex-1 min-w-0">
				<Label className="text-sm font-semibold leading-none tracking-tight">{title}</Label>
				{subtitle && <p className="text-muted-foreground mt-0.5 text-[11px]">{subtitle}</p>}
			</div>
		</div>
	);
}
