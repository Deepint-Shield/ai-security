/**
 * Routing Rule Dialog (Sheet)
 * Create/Edit form for routing rules
 */

"use client";

import { useState, useEffect, useCallback } from "react";
import { useForm } from "react-hook-form";
import { RuleGroupType } from "react-querybuilder";
import {
	Sheet,
	SheetContent,
	SheetHeader,
	SheetTitle,
} from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { ModelMultiselect } from "@/components/ui/modelMultiselect";
import { Filter, GitBranch, Info, PencilLine, Plus, Route, Save, Sliders, Target as TargetIcon, Trash2, X } from "lucide-react";
import {
	RoutingRule,
	RoutingRuleFormData,
	RoutingTargetFormData,
	DEFAULT_ROUTING_RULE_FORM_DATA,
	DEFAULT_ROUTING_TARGET,
	ROUTING_RULE_SCOPES,
} from "@/lib/types/routingRules";
import {
	useCreateRoutingRuleMutation,
	useUpdateRoutingRuleMutation,
	useGetRoutingRulesQuery,
} from "@/lib/store/apis/routingRulesApi";
import {
	useGetVirtualKeysQuery,
	useGetTeamsQuery,
	useGetCustomersQuery,
} from "@/lib/store/apis/governanceApi";
import { useGetProvidersQuery } from "@/lib/store/apis/providersApi";
import { toast } from "sonner";
import dynamic from "next/dynamic";
import { ProviderIconType, RenderProviderIcon } from "@/lib/constants/icons";
import { getProviderLabel } from "@/lib/constants/logs";
import { getErrorMessage } from "@/lib/store";
import {
	validateRoutingRules,
	validateRateLimitAndBudgetRules
} from "@/lib/utils/celConverterRouting";

interface RoutingRuleDialogProps {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	editingRule?: RoutingRule | null;
	onSuccess?: () => void;
}

const defaultQuery: RuleGroupType = {
	combinator: "and",
	rules: [],
};

// Dynamically import CEL builder to avoid SSR issues
const CELRuleBuilder = dynamic(
	() => import("@/app/workspace/routing-rules/components/celBuilder/celRuleBuilder").then((mod) => ({
		default: mod.CELRuleBuilder,
	})),
	{
		loading: () => <div className="text-sm text-gray-500">Loading CEL builder...</div>,
		ssr: false,
	},
);

export function RoutingRuleSheet({
	open,
	onOpenChange,
	editingRule,
	onSuccess,
}: RoutingRuleDialogProps) {
	const { data: rulesData } = useGetRoutingRulesQuery();
	const rules = rulesData?.rules || [];
	const { data: providersData = [] } = useGetProvidersQuery();
	const { data: vksData = { virtual_keys: [] } } = useGetVirtualKeysQuery();
	const { data: teamsData = { teams: [], count: 0, total_count: 0, limit: 0, offset: 0 } } = useGetTeamsQuery();
	const { data: customersData = { customers: [] } } = useGetCustomersQuery();
	const [createRoutingRule, { isLoading: isCreating }] = useCreateRoutingRuleMutation();
	const [updateRoutingRule, { isLoading: isUpdating }] = useUpdateRoutingRuleMutation();

	// State for targets and query (managed outside react-hook-form for complex nested structures)
	const [targets, setTargets] = useState<RoutingTargetFormData[]>([{ ...DEFAULT_ROUTING_TARGET }]);
	const [query, setQuery] = useState<RuleGroupType>(defaultQuery);
	const [builderKey, setBuilderKey] = useState(0);

	const {
		register,
		handleSubmit,
		setValue,
		watch,
		reset,
		formState: { errors },
	} = useForm<RoutingRuleFormData>({
		defaultValues: DEFAULT_ROUTING_RULE_FORM_DATA,
	});

	const isEditing = !!editingRule;
	const isLoading = isCreating || isUpdating;
	const enabled = watch("enabled");
	const scope = watch("scope");
	const scopeId = watch("scope_id");
	const fallbacks = watch("fallbacks");

	// Get available providers from configured providers, plus any provider already
	// referenced by the current targets, existing rules' targets, or rules' fallbacks
	// so edited/removed providers are still visible in the dropdown.
	const availableProviders = Array.from(
		new Set([
			...providersData.map((p) => p.name),
			...(targets.map((t) => t.provider).filter(Boolean) as string[]),
			...(rules.flatMap((r) => r.targets?.map((t) => t.provider).filter(Boolean) ?? []) as string[]),
			...(rules.flatMap((r) => (r.fallbacks ?? []).map((f) => f.split("/")[0]?.trim()).filter(Boolean))),
		]),
	);

	// Initialize form data when editing rule changes
	useEffect(() => {
		if (editingRule) {
			setValue("id", editingRule.id);
			setValue("name", editingRule.name);
			setValue("description", editingRule.description);
			setValue("cel_expression", editingRule.cel_expression);
			setValue("fallbacks", editingRule.fallbacks || []);
			setValue("scope", editingRule.scope);
			setValue("scope_id", editingRule.scope_id || "");
			setValue("priority", editingRule.priority);
			setValue("enabled", editingRule.enabled);
			if (editingRule.targets && editingRule.targets.length > 0) {
				setTargets(editingRule.targets.map((t) => ({
					...DEFAULT_ROUTING_TARGET,
					provider: t.provider || "",
					model: t.model || "",
					key_id: t.key_id || "",
					weight: t.weight,
				})));
			} else {
				setTargets([{ ...DEFAULT_ROUTING_TARGET }]);
			}
			// Restore the query object if it exists, otherwise use default
			if (editingRule.query) {
				setQuery(editingRule.query);
			} else {
				setQuery(defaultQuery);
			}
			setBuilderKey((prev) => prev + 1);
		} else {
			reset();
			setTargets([{ ...DEFAULT_ROUTING_TARGET }]);
			setQuery(defaultQuery);
			setBuilderKey((prev) => prev + 1);
		}
	}, [editingRule, open, setValue, reset]);

	const handleQueryChange = useCallback(
		(expression: string, newQuery: RuleGroupType) => {
			setValue("cel_expression", expression);
			setQuery(newQuery);
		},
		[setValue],
	);

	const addTarget = () => {
		const remaining = 1 - targets.reduce((sum, t) => sum + (t.weight || 0), 0);
		setTargets((prev) => [...prev, { ...DEFAULT_ROUTING_TARGET, weight: Math.max(0, parseFloat(remaining.toFixed(4))) }]);
	};

	const removeTarget = (index: number) => {
		setTargets((prev) => prev.filter((_, i) => i !== index));
	};

	const updateTarget = (index: number, field: keyof RoutingTargetFormData, value: string | number) => {
		setTargets((prev) => prev.map((t, i) => i === index ? { ...t, [field]: value } : t));
	};

	const totalWeight = targets.reduce((sum, t) => sum + (t.weight || 0), 0);

	const onSubmit = (data: RoutingRuleFormData) => {
		// Validate scope_id is required when scope is not global
		if (data.scope !== "global" && !data.scope_id?.trim()) {
			toast.error(`${data.scope === "team" ? "Team" : data.scope === "customer" ? "Member" : "Virtual Key"} is required`);
			return;
		}

		// Validate targets
		if (targets.length === 0) {
			toast.error("At least one routing target is required");
			return;
		}
		for (const t of targets) {
			if (t.weight <= 0) {
				toast.error("Each target weight must be greater than 0");
				return;
			}
		}
		if (Math.abs(totalWeight - 1) > 0.001) {
			toast.error(`Target weights must sum to 1, current total: ${totalWeight.toFixed(4)}`);
			return;
		}

		// Validate regex patterns in routing rules
		const regexErrors = validateRoutingRules(query);
		if (regexErrors.length > 0) {
			toast.error(`Invalid regex pattern:\n${regexErrors.join("\n")}`);
			return;
		}

		// Validate rate limit and budget rules
		const rateLimitErrors = validateRateLimitAndBudgetRules(query);
		if (rateLimitErrors.length > 0) {
			toast.error(`Invalid rule configuration:\n${rateLimitErrors.join("\n")}`);
			return;
		}

		// Filter out incomplete fallbacks (empty provider)
		const validFallbacks = (data.fallbacks || []).filter((fb) => {
			const provider = fb.split("/")[0]?.trim();
			return provider && provider.length > 0;
		});

		const payload = {
			name: data.name,
			description: data.description,
			cel_expression: data.cel_expression,
			targets: targets.map(({ provider, model, key_id, weight }) => ({
				provider: provider || undefined,
				model: model || undefined,
				key_id: key_id || undefined,
				weight,
			})),
			fallbacks: validFallbacks,
			scope: data.scope,
			scope_id: data.scope === "global" ? undefined : (data.scope_id || undefined),
			priority: data.priority,
			enabled: data.enabled,
			query: query,
		};

		const submitPromise = isEditing && editingRule
			? updateRoutingRule({
				id: editingRule.id,
				data: payload,
			}).unwrap()
			: createRoutingRule(payload).unwrap();

		submitPromise
			.then(() => {
				toast.success(
					isEditing
						? "Routing rule updated successfully"
						: "Routing rule created successfully",
				);
				reset();
				setTargets([{ ...DEFAULT_ROUTING_TARGET }]);
				setQuery(defaultQuery);
				setBuilderKey((prev) => prev + 1);
				onOpenChange(false);
				onSuccess?.();
			})
			.catch((error: any) => {
				toast.error(getErrorMessage(error));
			});
	};

	const handleCancel = () => {
		reset();
		setTargets([{ ...DEFAULT_ROUTING_TARGET }]);
		setQuery(defaultQuery);
		setBuilderKey((prev) => prev + 1);
		onOpenChange(false);
	};

	return (
		<Sheet open={open} onOpenChange={onOpenChange}>
			<SheetContent className="flex w-full flex-col min-w-1/2 gap-0 p-0 !overflow-hidden">
				{/* Header */}
				<SheetHeader className="border-border/60 bg-muted/30 flex flex-row items-center gap-3 border-b px-6 py-3 space-y-0">
					<span className="bg-primary/12 text-primary inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
						{isEditing ? <PencilLine className="h-4 w-4" /> : <Route className="h-4 w-4" />}
					</span>
					<div className="flex-1 min-w-0">
						<div className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em] leading-none">
							Model Hub
						</div>
						<SheetTitle className="mt-1 text-base font-semibold leading-tight tracking-tight">
							{isEditing ? "Edit Routing Rule" : "Create Routing Rule"}
						</SheetTitle>
					</div>
				</SheetHeader>

				<form onSubmit={handleSubmit(onSubmit)} className="flex flex-1 min-h-0 flex-col">
					<div className="custom-scrollbar flex-1 space-y-3.5 overflow-y-auto px-6 py-4">
						{/* Section: Basics */}
						<section className="space-y-2.5">
							<SectionHeader icon={<Info className="h-3.5 w-3.5" />} title="Basics" />
							<div className="space-y-2">
								<Label htmlFor="name">
									Rule Name <span className="text-red-500">*</span>
								</Label>
								<Input
									id="name"
									placeholder="e.g., Route GPT-4 to Azure"
									{...register("name", { required: "Rule name is required", maxLength: 255 })}
								/>
								{errors.name && <p className="text-destructive text-sm">{errors.name.message}</p>}
							</div>

							<div className="space-y-2">
								<Label htmlFor="description">Description</Label>
								<Textarea
									id="description"
									placeholder="Describe what this rule does..."
									rows={2}
									{...register("description")}
								/>
							</div>

							{/* Enabled Switch */}
							<div className="border-border/60 bg-card/40 flex items-center justify-between gap-3 rounded-xl border px-3 py-2.5">
								<div>
									<Label htmlFor="enabled" className="text-sm font-medium">Enable Rule</Label>
									<p className="text-muted-foreground text-[11px]">Rule will be active and applied to matching requests.</p>
								</div>
								<Switch
									id="enabled"
									checked={enabled}
									onCheckedChange={(checked) => setValue("enabled", checked)}
								/>
							</div>
						</section>

						{/* Section: Scope */}
						<section className="border-border/60 bg-card/40 space-y-2.5 rounded-2xl border p-3.5">
							<SectionHeader icon={<Sliders className="h-3.5 w-3.5" />} title="Scope & Priority" subtitle="Where and how aggressively this rule applies." />
							<div className="grid grid-cols-2 gap-3">
								<div className="space-y-2">
									<Label htmlFor="scope">Scope</Label>
									<Select value={scope} onValueChange={(value) => {
										setValue("scope", value as any);
										setValue("scope_id", "");
									}}>
										<SelectTrigger className="w-full">
											<SelectValue placeholder="Select scope..." />
										</SelectTrigger>
										<SelectContent>
											{ROUTING_RULE_SCOPES.map((scopeOption) => (
												<SelectItem key={scopeOption.value} value={scopeOption.value}>
													{scopeOption.label}
												</SelectItem>
											))}
										</SelectContent>
									</Select>
								</div>

								<div className="space-y-2">
									<Label htmlFor="priority">
										Priority <span className="text-red-500">*</span>
									</Label>
									<Input
										id="priority"
										type="number"
										min={0}
										max={1000}
										{...register("priority", {
											required: "Priority is required",
											min: { value: 0, message: "Priority must be ≥ 0" },
											max: { value: 1000, message: "Priority must be ≤ 1000" },
											valueAsNumber: true,
										})}
									/>
									{errors.priority && <p className="text-destructive text-sm">{errors.priority.message}</p>}
								</div>
							</div>
							<p className="text-muted-foreground text-[11px]">Lower numbers = higher priority (0 is highest).</p>

							{scope !== "global" && (
								<div className="space-y-2 pt-1">
									<Label htmlFor="scope_id">
										{scope === "team" ? "Team" : scope === "customer" ? "Member" : "Virtual Key"} <span className="text-red-500">*</span>
									</Label>
									{scope === "team" && teamsData.teams.length > 0 && (
										<Select value={scopeId || ""} onValueChange={(value) => setValue("scope_id", value)}>
											<SelectTrigger className="w-full">
												<SelectValue placeholder="Select a team..." />
											</SelectTrigger>
											<SelectContent>
												{teamsData.teams.map((team) => (
													<SelectItem key={team.id} value={team.id}>
														{team.name}
													</SelectItem>
												))}
											</SelectContent>
										</Select>
									)}
									{scope === "customer" && customersData.customers.length > 0 && (
										<Select value={scopeId || ""} onValueChange={(value) => setValue("scope_id", value)}>
											<SelectTrigger className="w-full">
												<SelectValue placeholder="Select a member..." />
											</SelectTrigger>
											<SelectContent>
												{customersData.customers.map((customer) => (
													<SelectItem key={customer.id} value={customer.id}>
														{customer.name}
													</SelectItem>
												))}
											</SelectContent>
										</Select>
									)}
									{scope === "virtual_key" && vksData.virtual_keys.length > 0 && (
										<Select value={scopeId || ""} onValueChange={(value) => setValue("scope_id", value)}>
											<SelectTrigger className="w-full">
												<SelectValue placeholder="Select a virtual key..." />
											</SelectTrigger>
											<SelectContent>
												{vksData.virtual_keys.map((vk) => (
													<SelectItem key={vk.id} value={vk.id}>
														{vk.name}
													</SelectItem>
												))}
											</SelectContent>
										</Select>
									)}
									{((scope === "team" && teamsData.teams.length === 0) ||
										(scope === "customer" && customersData.customers.length === 0) ||
										(scope === "virtual_key" && vksData.virtual_keys.length === 0)) && (
											<p className="text-muted-foreground text-sm">No {scope === "team" ? "teams" : scope === "customer" ? "members" : "virtual keys"} available</p>
										)}
									{errors.scope_id && <p className="text-destructive text-sm">{errors.scope_id.message}</p>}
								</div>
							)}
						</section>

						{/* Section: CEL Rule Builder */}
						<section className="border-border/60 bg-card/40 space-y-2.5 rounded-2xl border p-3.5">
							<SectionHeader icon={<Filter className="h-3.5 w-3.5" />} title="Rule Builder" subtitle="Conditions that trigger this rule. Leave empty to match all requests." />
							<CELRuleBuilder
								key={builderKey}
								initialQuery={query}
								onChange={handleQueryChange}
								providers={availableProviders}
								models={[]}
								allowCustomModels={true}
							/>
							<div className="border-border/60 bg-amber-500/5 flex items-start gap-2 rounded-lg border border-dashed px-3 py-2">
								<Info className="text-amber-600 dark:text-amber-400 mt-0.5 h-3.5 w-3.5 shrink-0" />
								<p className="text-muted-foreground text-[11px]">
									Ensure token limits, request limits, and budget are configured in <strong className="text-foreground">Model Providers → Configurations → {'{provider}'} → Governance</strong> (provider-level) or <strong className="text-foreground">Model Providers → Budgets & Limits</strong> (model-level) before using them in routing rules.
								</p>
							</div>
						</section>

						{/* Section: Routing Targets */}
						<section className="border-border/60 bg-card/40 space-y-2.5 rounded-2xl border p-3.5">
							<div className="flex items-start justify-between gap-3">
								<SectionHeader
									icon={<TargetIcon className="h-3.5 w-3.5" />}
									title="Routing Targets"
									subtitle="Weights must sum to 1. Leave provider or model empty to use incoming."
								/>
								<Button
									type="button"
									variant="outline"
									size="sm"
									onClick={addTarget}
									className="shrink-0"
									data-testid="routing-rule-target-add"
								>
									<Plus className="h-3.5 w-3.5" />
									Add Target
								</Button>
							</div>

							<div className="space-y-2.5">
								{targets.map((target, index) => (
									<TargetRow
										key={index}
										target={target}
										index={index}
										availableProviders={availableProviders}
										providersData={providersData}
										showRemove={targets.length > 1}
										onUpdate={updateTarget}
										onRemove={removeTarget}
									/>
								))}
							</div>

							<div className={`flex items-center justify-end gap-2 text-xs font-medium tabular-nums ${Math.abs(totalWeight - 1) > 0.001 ? "text-destructive" : "text-muted-foreground"}`}>
								Total weight: {totalWeight.toFixed(4)}
								{Math.abs(totalWeight - 1) > 0.001 && (
									<span className="text-destructive">(must equal 1)</span>
								)}
							</div>
						</section>

						{/* Section: Fallbacks */}
						<section className="border-border/60 bg-card/40 space-y-2.5 rounded-2xl border p-3.5">
							<div className="flex items-start justify-between gap-3">
								<SectionHeader
									icon={<GitBranch className="h-3.5 w-3.5" />}
									title="Fallbacks"
									subtitle="Used in order when primary targets fail."
								/>
								<Button
									type="button"
									variant="outline"
									size="sm"
									onClick={() => setValue("fallbacks", [...(fallbacks || []), ""])}
									className="shrink-0"
								>
									<Plus className="h-3.5 w-3.5" />
									Add Fallback
								</Button>
							</div>
							<div className="space-y-2">
								{(fallbacks || []).length === 0 ? (
									<span className="border-border/60 text-muted-foreground inline-flex items-center rounded-full border border-dashed px-2 py-0.5 text-[11px] italic">
										No fallbacks configured
									</span>
								) : (
									(fallbacks || []).map((fallback, index) => {
										const parts = fallback.split("/");
										const fbProvider = parts[0] || "";
										const fbModel = parts[1] || "";

										const handleProviderChange = (newProvider: string) => {
											const model = fbModel || "";
											const newFallback = `${newProvider}/${model}`;
											const newFallbacks = [...fallbacks];
											newFallbacks[index] = newFallback;
											setValue("fallbacks", newFallbacks);
										};

										const handleModelChange = (newModel: string) => {
											const prov = fbProvider || "";
											const newFallback = `${prov}/${newModel}`;
											const newFallbacks = [...fallbacks];
											newFallbacks[index] = newFallback;
											setValue("fallbacks", newFallbacks);
										};

										const handleRemove = () => {
											const newFallbacks = fallbacks.filter((_: string, i: number) => i !== index);
											setValue("fallbacks", newFallbacks);
										};

										return (
											<div key={index} className="flex items-center gap-2">
												<span className="bg-muted text-muted-foreground inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md font-mono text-[11px] font-semibold tabular-nums">
													{index + 1}
												</span>
												<div className="flex-1">
													<Select value={fbProvider} onValueChange={handleProviderChange}>
														<SelectTrigger className="w-full">
															<SelectValue placeholder="Select provider..." />
														</SelectTrigger>
														<SelectContent>
															{availableProviders.map((prov) => (
																<SelectItem key={prov} value={prov}>
																	<div className="flex items-center gap-2">
																		<RenderProviderIcon
																			provider={prov as ProviderIconType}
																			size="sm"
																			className="h-4 w-4"
																		/>
																		<span>{getProviderLabel(prov)}</span>
																	</div>
																</SelectItem>
															))}
														</SelectContent>
													</Select>
												</div>
												<div className="flex-1">
													<ModelMultiselect
														provider={fbProvider || undefined}
														value={fbModel}
														onChange={handleModelChange}
														placeholder="Select model..."
														isSingleSelect
														disabled={!fbProvider}
														className="!h-9 !min-h-9 w-full"
													/>
												</div>
												<Button
													type="button"
													variant="ghost"
													size="sm"
													onClick={handleRemove}
													className="text-destructive hover:bg-destructive/10 hover:text-destructive h-9 px-2"
													aria-label={`Remove fallback ${index + 1}`}
												>
													<Trash2 className="h-4 w-4" />
												</Button>
											</div>
										);
									})
								)}
							</div>
						</section>
					</div>

					{/* Sticky Footer */}
					<div className="border-border/60 bg-card/60 shrink-0 border-t px-6 py-3 backdrop-blur">
						<div className="flex justify-end gap-3">
							<Button type="button" variant="outline" onClick={handleCancel} disabled={isLoading}>
								<X className="h-4 w-4" />
								Cancel
							</Button>
							<Button type="submit" disabled={isLoading}>
								<Save className="h-4 w-4" />
								{isEditing ? "Update Rule" : "Save Rule"}
							</Button>
						</div>
					</div>
				</form>
			</SheetContent>
		</Sheet>
	);
}

interface TargetRowProps {
	target: RoutingTargetFormData;
	index: number;
	availableProviders: string[];
	providersData: Array<{ name: string; keys: Array<{ id: string; name: string }> }>;
	showRemove: boolean;
	onUpdate: (index: number, field: keyof RoutingTargetFormData, value: string | number) => void;
	onRemove: (index: number) => void;
}

function TargetRow({ target, index, availableProviders, providersData, showRemove, onUpdate, onRemove }: TargetRowProps) {
	const availableKeys = target.provider
		? (providersData.find((p) => p.name === target.provider)?.keys ?? [])
		: [];

	return (
		<div className="rounded-lg border p-3 space-y-3" data-testid={`routing-target-${index}`}>
			<div className="flex items-center justify-between">
				<span className="text-sm font-medium text-muted-foreground">Target {index + 1}</span>
				<div className="flex items-center gap-2">
					<div className="flex items-center gap-1.5">
						<Label htmlFor={`routing-target-${index}-weight-input`} className="text-xs text-muted-foreground shrink-0">Weight</Label>
						<Input
							id={`routing-target-${index}-weight-input`}
							type="number"
							min={0.001}
							max={1}
							step={0.001}
							value={target.weight}
							onChange={(e) => onUpdate(index, "weight", parseFloat(e.target.value) || 0)}
							className="h-8 w-24 text-sm"
							data-testid={`routing-target-${index}-weight-input`}
						/>
					</div>
					{showRemove && (
						<Button
							type="button"
							variant="ghost"
							size="sm"
							onClick={() => onRemove(index)}
							className="h-8 w-8 p-0"
							aria-label={`Remove target ${index + 1}`}
							data-testid={`routing-target-${index}-remove-button`}
						>
							<Trash2 className="h-3.5 w-3.5" />
						</Button>
					)}
				</div>
			</div>

			<div className="grid grid-cols-2 gap-3">
				<div className="space-y-1.5">
					<Label id={`routing-target-${index}-provider-label`} className="text-xs">Provider</Label>
					<div className="flex gap-1.5">
						<Select
							value={target.provider}
							onValueChange={(value) => {
								onUpdate(index, "provider", value);
								onUpdate(index, "model", "");
								onUpdate(index, "key_id", "");
							}}
						>
							<SelectTrigger
								id={`routing-target-${index}-provider-select`}
								aria-labelledby={`routing-target-${index}-provider-label`}
								className="flex-1 h-9 text-sm"
								data-testid={`routing-target-${index}-provider-select`}
							>
								<SelectValue placeholder="Incoming (optional)" />
							</SelectTrigger>
							<SelectContent>
								{availableProviders.map((prov) => (
									<SelectItem key={prov} value={prov}>
										<div className="flex items-center gap-2">
											<RenderProviderIcon
												provider={prov as ProviderIconType}
												size="sm"
												className="h-4 w-4"
											/>
											<span>{getProviderLabel(prov)}</span>
										</div>
									</SelectItem>
								))}
							</SelectContent>
						</Select>
						{target.provider && (
							<Button
								type="button"
								variant="outline"
								size="sm"
								onClick={() => { onUpdate(index, "provider", ""); onUpdate(index, "model", ""); onUpdate(index, "key_id", ""); }}
								className="h-9 w-9 p-0"
								aria-label={`Clear provider for target ${index + 1}`}
								data-testid={`routing-target-${index}-provider-clear`}
							>
								<X className="h-3.5 w-3.5" />
							</Button>
						)}
					</div>
				</div>

				<div className="space-y-1.5">
					<Label id={`routing-target-${index}-model-label`} className="text-xs">Model</Label>
					<div className="flex gap-1.5">
						<div className="flex-1" data-testid={`routing-target-${index}-model-select`}>
							<ModelMultiselect
								provider={target.provider || undefined}
								value={target.model}
								onChange={(value) => onUpdate(index, "model", value)}
								placeholder="Incoming (optional)"
								isSingleSelect
								loadModelsOnEmptyProvider
								className="!h-9 !min-h-9"
								inputId={`routing-target-${index}-model-input`}
								ariaLabelledBy={`routing-target-${index}-model-label`}
							/>
						</div>
						{target.model && (
							<Button
								type="button"
								variant="outline"
								size="sm"
								onClick={() => onUpdate(index, "model", "")}
								className="h-9 w-9 p-0"
								aria-label={`Clear model for target ${index + 1}`}
								data-testid={`routing-target-${index}-model-clear`}
							>
								<X className="h-3.5 w-3.5" />
							</Button>
						)}
					</div>
				</div>
			</div>

			{target.provider && (availableKeys.length > 0 || target.key_id) && (
				<div className="space-y-1.5">
					<Label id={`routing-target-${index}-apikey-label`} className="text-xs">API Key <span className="text-muted-foreground">(optional - leave unset for load-balanced selection)</span></Label>
					<div className="flex gap-1.5">
						<Select value={target.key_id || ""} onValueChange={(value) => onUpdate(index, "key_id", value)}>
							<SelectTrigger
								id={`routing-target-${index}-apikey-select`}
								aria-labelledby={`routing-target-${index}-apikey-label`}
								className="flex-1 h-9 text-sm"
								data-testid={`routing-target-${index}-apikey-select`}
							>
								<SelectValue placeholder="Select key (optional)" />
							</SelectTrigger>
							<SelectContent>
								{availableKeys.map((key) => (
									<SelectItem key={key.id} value={key.id}>
										{key.name}
									</SelectItem>
								))}
								{target.key_id && !availableKeys.some((k) => k.id === target.key_id) && (
									<SelectItem key={`pinned-${target.key_id}`} value={target.key_id}>
										(pinned) {target.key_id}
									</SelectItem>
								)}
							</SelectContent>
						</Select>
						{target.key_id && (
							<Button
								type="button"
								variant="outline"
								size="sm"
								onClick={() => onUpdate(index, "key_id", "")}
								className="h-9 w-9 p-0"
								aria-label={`Clear API key for target ${index + 1}`}
								data-testid={`routing-target-${index}-apikey-clear`}
							>
								<X className="h-3.5 w-3.5" />
							</Button>
						)}
					</div>
				</div>
			)}
		</div>
	);
}

function SectionHeader({ icon, title, subtitle }: { icon: React.ReactNode; title: string; subtitle?: string }) {
	return (
		<div className="flex items-start gap-2">
			<span className="text-muted-foreground inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-muted">
				{icon}
			</span>
			<div className="flex-1 min-w-0">
				<Label className="text-sm font-semibold leading-none tracking-tight">{title}</Label>
				{subtitle && <p className="text-muted-foreground mt-0.5 text-[11px]">{subtitle}</p>}
			</div>
		</div>
	);
}
