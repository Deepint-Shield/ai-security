"use client";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { getErrorMessage, useForcePricingSyncMutation, useGetCoreConfigQuery, useUpdateCoreConfigMutation } from "@/lib/store";
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib";
import { DollarSign } from "lucide-react";
import { useEffect, useMemo } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";

interface PricingFormData {
	pricing_datasheet_url: string;
	pricing_sync_interval_hours: number;
}

export default function PricingConfigView() {
	const hasSettingsUpdateAccess = useRbac(RbacResource.Settings, RbacOperation.Update);
	const { data: deepintshieldConfig } = useGetCoreConfigQuery({ fromDB: true });
	const config = deepintshieldConfig?.framework_config;
	const [updateCoreConfig, { isLoading }] = useUpdateCoreConfigMutation();
	const [forcePricingSync, { isLoading: isForceSyncing }] = useForcePricingSyncMutation();

	const {
		register,
		handleSubmit,
		formState: { errors, isDirty },
		reset,
		watch,
	} = useForm<PricingFormData>({
		defaultValues: {
			pricing_datasheet_url: "",
			pricing_sync_interval_hours: 24,
		},
	});

	const formValues = watch();

	useEffect(() => {
		if (deepintshieldConfig && config) {
			reset({
				pricing_datasheet_url: config.pricing_url || "",
				pricing_sync_interval_hours: Math.round(config.pricing_sync_interval / 3600) || 24,
			});
		}
	}, [config, deepintshieldConfig, reset]);

	const hasChanges = useMemo(() => {
		if (!config || !isDirty) return false;
		const serverUrl = config.pricing_url || "";
		const serverInterval = Math.round(config.pricing_sync_interval / 3600);
		return formValues.pricing_datasheet_url !== serverUrl || formValues.pricing_sync_interval_hours !== serverInterval;
	}, [config, formValues, isDirty]);

	const onSubmit = async (data: PricingFormData) => {
		try {
			await updateCoreConfig({
				...deepintshieldConfig!,
				framework_config: {
					...config,
					id: deepintshieldConfig?.framework_config.id || 0,
					pricing_url: data.pricing_datasheet_url,
					pricing_sync_interval: data.pricing_sync_interval_hours * 3600,
				},
			}).unwrap();
			toast.success("Pricing configuration updated successfully.");
			reset(data);
		} catch (error) {
			toast.error(getErrorMessage(error));
		}
	};

	const handleForceSync = async () => {
		try {
			await forcePricingSync().unwrap();
			toast.success("Pricing sync triggered successfully.");
		} catch (error) {
			toast.error(getErrorMessage(error));
		}
	};

	return (
		<div className="workspace-page-shell space-y-5" data-testid="pricing-config-view">
			<form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
				<header className="space-y-1.5">
					<div className="text-muted-foreground text-[11px] font-semibold uppercase tracking-[0.18em]">Settings</div>
					<div className="flex items-center gap-2.5">
						<span className="bg-primary/12 text-primary inline-flex h-9 w-9 items-center justify-center rounded-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
							<DollarSign className="h-4 w-4" />
						</span>
						<div>
							<h1 className="text-2xl font-semibold leading-none tracking-tight">Pricing Configuration</h1>
							<p className="text-muted-foreground mt-1 text-sm">Configure custom pricing datasheet and sync intervals.</p>
						</div>
					</div>
				</header>

				<div className="space-y-4">
					{/* Pricing Datasheet URL */}
					<div className="space-y-2 rounded-sm border p-4">
						<div className="space-y-0.5">
							<Label htmlFor="pricing-datasheet-url">Pricing Datasheet URL</Label>
							<p className="text-muted-foreground text-sm">URL to a custom pricing datasheet. Leave empty to use default pricing.</p>
						</div>
						<Input
							id="pricing-datasheet-url"
							type="text"
							placeholder="https://example.com/pricing.json"
							data-testid="pricing-datasheet-url-input"
							{...register("pricing_datasheet_url", {
								pattern: {
									value: /^(https?:\/\/)?((localhost|(\d{1,3}\.){3}\d{1,3})(:\d+)?|([\da-z\.-]+)\.([a-z\.]{2,6}))([\/\w \.-]*)*\/?$/,
									message: "Please enter a valid URL.",
								},
								validate: {
									checkIfHttp: (value) => {
										if (!value) return true; // Allow empty
										return value.startsWith("http://") || value.startsWith("https://") || "URL must start with http:// or https://";
									},
								},
							})}
							className={errors.pricing_datasheet_url ? "border-destructive" : ""}
						/>
						{errors.pricing_datasheet_url && <p className="text-destructive text-sm">{errors.pricing_datasheet_url.message}</p>}
					</div>

					{/* Pricing Sync Interval */}
					<div className="space-y-2 rounded-sm border p-4">
						<div className="space-y-2">
							<div className="space-y-0.5">
								<Label htmlFor="pricing-sync-interval">Pricing Sync Interval (hours)</Label>
								<p className="text-muted-foreground text-sm">How often to sync pricing data from the datasheet URL.</p>
							</div>
							<Input
								id="pricing-sync-interval"
								type="number"
								className={errors.pricing_sync_interval_hours ? "border-destructive" : ""}
								{...register("pricing_sync_interval_hours", {
									required: "Pricing sync interval is required",
									min: {
										value: 1,
										message: "Sync interval must be at least 1 hour",
									},
									max: {
										value: 8760,
										message: "Sync interval cannot exceed 8760 hours (1 year)",
									},
									valueAsNumber: true,
								})}
							/>
							{errors.pricing_sync_interval_hours && (
								<p className="text-destructive text-sm">{errors.pricing_sync_interval_hours.message}</p>
							)}
						</div>
					</div>
				</div>
				<div className="flex justify-end gap-2 pt-2">
					<Button variant="outline" type="button" onClick={handleForceSync} disabled={isForceSyncing || !hasSettingsUpdateAccess} data-testid="pricing-force-sync-btn">
						{isForceSyncing ? "Syncing..." : "Force Sync Now"}
					</Button>
					<Button type="submit" disabled={!hasChanges || isLoading || !hasSettingsUpdateAccess} data-testid="pricing-save-btn">
						{isLoading ? "Saving..." : "Save Changes"}
					</Button>
				</div>
			</form>
		</div>
	);
}
