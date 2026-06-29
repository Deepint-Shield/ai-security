"use client";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { useGetCoreConfigQuery } from "@/lib/store";
import { Copy, InfoIcon, KeyRound } from "lucide-react";
import Link from "next/link";
import { useMemo } from "react";
import { toast } from "sonner";
import ContactUsView from "../views/contactUsView";

export default function APIKeysView() {
	const { data: deepintshieldConfig, isLoading } = useGetCoreConfigQuery({ fromDB: true });
	const isAuthConfigure = useMemo(() => {
		return deepintshieldConfig?.auth_config?.is_enabled;
	}, [deepintshieldConfig]);

	const curlExample = `# Base64 encode your username:password
# Example: echo -n "username:password" | base64
curl --location 'http://localhost:8080/v1/chat/completions'
--header 'Content-Type: application/json' 
--header 'Accept: application/json' 
--header 'Authorization: Basic <base64_encoded_username:password>' 
--data '{ 
  "model": "openai/gpt-4", 
  "messages": [ 
    { 
      "role": "user", 
      "content": "explain big bang?" 
    } 
  ] 
}'`;

	const copyToClipboard = (text: string) => {
		navigator.clipboard.writeText(text);
		toast.success("Copied to clipboard");
	};

	if (isLoading) {
		return <div>Loading...</div>;
	}
	if (!isAuthConfigure) {
		return (
			<Alert variant="default">
				<InfoIcon className="text-muted h-4 w-4" />
				<AlertDescription>
					<p className="text-md text-muted-foreground">
						To generate API keys, you need to set up admin username and password first.{" "}
						<Link href="/workspace/config/security" className="text-md text-primary underline">
							Configure Security Settings
						</Link>
						.<br />
						<br />
						Once generated, use this API key for control-plane API calls and the DeepIntShield administrative UI.
					</p>
				</AlertDescription>
			</Alert>
		);
	}

	const isInferenceAuthDisabled = deepintshieldConfig?.auth_config?.disable_auth_on_inference ?? true;

	return (
		<div className="mx-auto w-full max-w-4xl space-y-5">
			<header className="space-y-1.5">
				<div className="text-muted-foreground text-[11px] font-semibold uppercase tracking-[0.18em]">Settings</div>
				<div className="flex items-center gap-2.5">
					<span className="bg-primary/12 text-primary inline-flex h-9 w-9 items-center justify-center rounded-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.18)]">
						<KeyRound className="h-4 w-4" />
					</span>
					<div>
						<h1 className="text-2xl font-semibold leading-none tracking-tight">API Keys</h1>
						<p className="text-muted-foreground mt-1 text-sm">Manage admin and inference authentication credentials.</p>
					</div>
				</div>
			</header>

			<Alert variant="default">
				<InfoIcon className="text-muted h-4 w-4" />
				<AlertDescription>
					<p className="text-md text-muted-foreground">
						{isInferenceAuthDisabled ? (
							<>
								Authentication is currently <strong>disabled for inference API calls</strong>. You can make inference requests without
								authentication. Dashboard and admin API calls still require Basic auth with your admin credentials encoded in the standard{" "}
								<code className="bg-muted rounded px-1 py-0.5 text-sm">username:password</code> format with base64 encoding.
							</>
						) : (
							<>
								Use Basic auth with your admin credentials when making API calls to DeepIntShield. Encode your credentials in the standard{" "}
								<code className="bg-muted rounded px-1 py-0.5 text-sm">username:password</code> format with base64 encoding.
							</>
						)}
					</p>
					{!isInferenceAuthDisabled && (
						<>
							<br />
							<p className="text-md text-muted-foreground">
								<strong>Example:</strong>
							</p>

							<div className="relative mt-2 w-full min-w-0 overflow-x-auto">
								<Button variant="ghost" size="sm" onClick={() => copyToClipboard(curlExample)} className="absolute top-2 right-2 z-10 h-8">
									<Copy className="h-4 w-4" />
								</Button>
								<pre className="bg-muted min-w-max rounded p-3 pr-12 font-mono text-sm whitespace-pre">{curlExample}</pre>
							</div>
						</>
					)}
				</AlertDescription>
			</Alert>

			<ContactUsView
				className="mt-4 rounded-md border px-3 py-8"
				icon={<KeyRound size={48} />}
				title="Scoped Service Keys"
				description="Need granular access control with scope-based API keys? Enterprise workspaces can create multiple API keys with specific permissions for different services, teams, or environments."
				readmeLink="https://deepintshield.com"
			/>
		</div>
	);
}
