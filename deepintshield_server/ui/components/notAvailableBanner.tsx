import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Database } from "lucide-react";
import Link from "next/link";

const NotAvailableBanner = () => {
	return (
		<div className="h-base flex items-center justify-center p-4">
			<div className="w-full max-w-md">
				<Alert className="border-destructive/35 text-destructive/85 [&>svg]:text-destructive bg-[rgba(114,36,28,0.22)] shadow-[0_18px_36px_-28px_rgba(7,24,30,0.36)]">
					<AlertTitle className="flex items-center gap-2">
						<Database className="text-destructive/80 h-4 w-4" />
						Control-plane storage is not configured.
					</AlertTitle>
					<AlertDescription className="mt-2 space-y-2 text-xs">
						<div>DeepIntShield needs a configuration datastore to persist policies, routing controls, and platform settings.</div>
						<div className="text-muted-foreground">
							To enable the full console, add the datastore settings to your <code>config.json</code> (see{" "}
							<Link
								href="https://deepintshield.com"
								target="_blank"
								rel="noopener noreferrer"
								className="font-medium underline underline-offset-2"
							>
								platform guidance
							</Link>
							).
						</div>
					</AlertDescription>
				</Alert>
			</div>
		</div>
	);
};

export default NotAvailableBanner;
