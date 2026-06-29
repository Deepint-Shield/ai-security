import { Message } from "@/lib/message";
import { AlertCircle, XIcon } from "lucide-react";

/**
 * Render a styled error message block with an optional delete control.
 *
 * @param message - The message object whose `content` is displayed inside the error block.
 * @param disabled - When true, the remove button is not rendered.
 * @param onRemove - Callback invoked when the delete button is clicked.
 * @returns The React element that displays the error message view.
 */
export default function ErrorMessageView({ message, disabled, onRemove }: { message: Message; disabled?: boolean; onRemove?: () => void }) {
	return (
		<div className="group rounded-sm px-3 py-2">
			<div className="border-destructive/40 bg-destructive/10 flex items-start gap-2 rounded-md border px-2.5 py-2">
				<AlertCircle className="text-destructive mt-0.5 size-4 shrink-0" />
				<p className="text-destructive text-sm whitespace-pre-wrap flex-1">{message.content}</p>
				{!disabled && onRemove && (
					<button
						type="button"
						aria-label="Delete message"
						data-testid="error-msg-delete"
						onClick={onRemove}
						className="hover:bg-destructive/20 focus:bg-destructive/20 rounded-sm p-1 opacity-0 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100 focus:opacity-100"
					>
						<XIcon className="text-destructive size-3 shrink-0 cursor-pointer" />
					</button>
				)}
			</div>
		</div>
	);
}
