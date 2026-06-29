import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { ProviderIconType, RenderProviderIcon } from "@/lib/constants/icons";
import { ProviderLabels } from "@/lib/constants/logs";
import { ModelProvider } from "@/lib/types/config";
import { toast } from "sonner";
import ProviderKeyForm from "../views/providerKeyForm";

interface Props {
	show: boolean;
	onCancel: () => void;
	provider: ModelProvider;
	keyIndex: number;
	providerName?: string;
}

export default function AddNewKeySheet({ show, onCancel, provider, keyIndex, providerName }: Props) {
	const isEditing = keyIndex < provider.keys.length;
	const resolvedProviderName = (providerName ?? provider.name).toLowerCase();
	const isVLLM = resolvedProviderName === "vllm";
	const entityLabel = isVLLM ? "model" : "key";
	const EntityLabel = entityLabel.charAt(0).toUpperCase() + entityLabel.slice(1);
	const dialogTitle = isEditing ? `Edit ${entityLabel}` : `Add new ${entityLabel}`;
	const successMessage = isEditing ? `${EntityLabel} updated successfully` : `${EntityLabel} added successfully`;

	const isCustomProvider = !!provider.custom_provider_config;
	const iconProvider = (isCustomProvider ? provider.custom_provider_config?.base_provider_type : provider.name) as ProviderIconType;
	const providerLabel = isCustomProvider ? provider.name : ProviderLabels[provider.name as keyof typeof ProviderLabels] ?? provider.name;

	return (
		<Sheet
			open={show}
			onOpenChange={(open) => {
				if (!open) onCancel();
			}}
		>
			<SheetContent
				className="custom-scrollbar p-0"
				data-testid="key-form"
				onInteractOutside={(e) => e.preventDefault()}
				onEscapeKeyDown={(e) => e.preventDefault()}
			>
				<SheetHeader className="border-border/60 bg-muted/30 flex flex-row items-center gap-3 border-b px-6 py-4 space-y-0">
					<span className="bg-[linear-gradient(135deg,rgba(34,211,196,0.18),rgba(96,169,255,0.14))] inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
						<RenderProviderIcon provider={iconProvider} size="sm" className="h-5 w-5" />
					</span>
					<div className="flex-1 min-w-0">
						<div className="text-muted-foreground text-[10px] font-semibold uppercase tracking-[0.16em] leading-none">
							{providerLabel}
						</div>
						<SheetTitle className="mt-1 text-base font-semibold leading-tight tracking-tight">
							{dialogTitle}
						</SheetTitle>
					</div>
				</SheetHeader>

				<div className="px-6 py-5">
					<ProviderKeyForm
						provider={provider}
						keyIndex={keyIndex}
						onCancel={onCancel}
						onSave={() => {
							toast.success(successMessage);
							onCancel();
						}}
					/>
				</div>
			</SheetContent>
		</Sheet>
	);
}
