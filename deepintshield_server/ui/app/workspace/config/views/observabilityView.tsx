"use client";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { getErrorMessage, useGetCoreConfigQuery, useUpdateCoreConfigMutation } from "@/lib/store";
import { CoreConfig, DefaultCoreConfig } from "@/lib/types/config";
import { parseArrayFromText } from "@/lib/utils/array";
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib";
import { AlertTriangle, Telescope } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

export default function ObservabilityView() {
	const hasSettingsUpdateAccess = useRbac(RbacResource.Settings, RbacOperation.Update);
	const { data: deepintshieldConfig } = useGetCoreConfigQuery({ fromDB: true });
	const config = deepintshieldConfig?.client_config;
	const [updateCoreConfig, { isLoading }] = useUpdateCoreConfigMutation();
	const [localConfig, setLocalConfig] = useState<CoreConfig>(DefaultCoreConfig);
	const [needsRestart, setNeedsRestart] = useState<boolean>(false);

	const [localValues, setLocalValues] = useState<{
		prometheus_labels: string;
	}>({
		prometheus_labels: "",
	});

	useEffect(() => {
		if (deepintshieldConfig && config) {
			setLocalConfig(config);
			setLocalValues({
				prometheus_labels: config?.prometheus_labels?.join(", ") || "",
			});
		}
	}, [config, deepintshieldConfig]);

	const hasChanges = useMemo(() => {
		if (!config) return false;
		const localLabels = localConfig.prometheus_labels.slice().sort().join(",");
		const serverLabels = config.prometheus_labels.slice().sort().join(",");
		return localLabels !== serverLabels;
	}, [config, localConfig]);

	const handlePrometheusLabelsChange = useCallback((value: string) => {
		setLocalValues((prev) => ({ ...prev, prometheus_labels: value }));
		setLocalConfig((prev) => ({ ...prev, prometheus_labels: parseArrayFromText(value) }));
		setNeedsRestart(true);
	}, []);

	const handleSave = useCallback(async () => {
		if (!deepintshieldConfig) {
			toast.error("Could not save settings: configuration not loaded.");
			return;
		}
		try {
			await updateCoreConfig({ ...deepintshieldConfig, client_config: localConfig }).unwrap();
			toast.success("Observability settings updated successfully.");
		} catch (error) {
			toast.error(getErrorMessage(error));
		}
	}, [deepintshieldConfig, localConfig, updateCoreConfig]);

	return (
		<div className="workspace-page-shell space-y-5">
			<header className="space-y-1.5">
				<div className="text-muted-foreground text-[11px] font-semibold uppercase tracking-[0.18em]">Settings</div>
				<div className="flex items-center gap-2.5">
					<span className="bg-primary/12 text-primary inline-flex h-9 w-9 items-center justify-center rounded-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
						<Telescope className="h-4 w-4" />
					</span>
					<div>
						<h1 className="text-2xl font-semibold leading-none tracking-tight">Observability</h1>
						<p className="text-muted-foreground mt-1 text-sm">Configure metrics, traces, and Prometheus integration.</p>
					</div>
				</div>
			</header>

			<Alert variant="destructive">
				<AlertTriangle className="h-4 w-4" />
				<AlertDescription>
					These settings require a DeepIntShield service restart to take effect. Current connections will continue with existing settings
					until restart.
				</AlertDescription>
			</Alert>

			<div className="space-y-4">
				{/* Prometheus Labels */}
				<div>
					<div className="space-y-2 rounded-lg border p-4">
						<div className="space-y-0.5">
							<label htmlFor="prometheus-labels" className="text-sm font-medium">
								Prometheus Labels
							</label>
							<p className="text-muted-foreground text-sm">Comma-separated list of custom labels to add to the Prometheus metrics.</p>
						</div>
						<Textarea
							id="prometheus-labels"
							className="h-24"
							placeholder="teamId, projectId, environment"
							value={localValues.prometheus_labels}
							onChange={(e) => handlePrometheusLabelsChange(e.target.value)}
						/>
					</div>
					{needsRestart && <RestartWarning />}
				</div>
			</div>
			<div className="flex justify-end pt-2">
				<Button onClick={handleSave} disabled={!hasChanges || isLoading || !hasSettingsUpdateAccess}>
					{isLoading ? "Saving..." : "Save Changes"}
				</Button>
			</div>
		</div>
	);
}

const RestartWarning = () => {
	return <div className="text-muted-foreground mt-2 pl-4 text-xs font-semibold">Need to restart DeepIntShield to apply changes.</div>;
};
