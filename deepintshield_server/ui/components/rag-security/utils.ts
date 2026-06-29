export function badgeVariantForSeverity(severity: string): "default" | "secondary" | "destructive" | "outline" | "success" {
	switch (severity) {
		case "critical":
		case "high":
			return "destructive";
		case "medium":
			return "default";
		case "low":
			return "secondary";
		default:
			return "outline";
	}
}

export function badgeVariantForState(state: string): "default" | "secondary" | "destructive" | "outline" | "success" {
	switch (state) {
		case "approved":
		case "healthy":
		case "healthy_shadow":
		case "strong":
			return "success";
		case "pending":
		case "monitored":
		case "warn":
		case "partial":
			return "default";
		case "blocked":
		case "quarantined":
		case "rejected":
		case "degraded":
			return "destructive";
		case "shadow-allow":
		case "shadow-warn":
		case "shadow-block":
		case "shadow-quarantine":
		case "emerging":
			return "secondary";
		default:
			return "outline";
	}
}

export function formatDateTime(value?: string) {
	if (!value) {
		return "n/a";
	}
	const date = new Date(value);
	if (Number.isNaN(date.getTime())) {
		return value;
	}
	return date.toLocaleString();
}

export function csvToList(value: string) {
	return value
		.split(",")
		.map((item) => item.trim())
		.filter(Boolean);
}

export function listToCsv(values?: string[]) {
	return (values ?? []).join(", ");
}

export function numberValue(value: string, fallback = 0) {
	const parsed = Number(value);
	return Number.isFinite(parsed) ? parsed : fallback;
}

