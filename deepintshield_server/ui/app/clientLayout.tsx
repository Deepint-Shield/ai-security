"use client";

import FullPageLoader from "@/components/fullPageLoader";
import NotAvailableBanner from "@/components/notAvailableBanner";
import ProgressProvider from "@/components/progressBar";
import Sidebar from "@/components/sidebar";
import { ThemeProvider } from "@/components/themeProvider";
import { SidebarProvider } from "@/components/ui/sidebar";
import { useStoreSync } from "@/hooks/useStoreSync";
import { WebSocketProvider } from "@/hooks/useWebSocket";
import { useThemeSync } from "@/lib/hooks/useThemeSync";
import { getErrorMessage, ReduxProvider, useGetCoreConfigQuery } from "@/lib/store";
import { DeepIntShieldConfig } from "@/lib/types/config";
import { RbacProvider } from "@enterprise/lib/contexts/rbacContext";
import dynamic from "next/dynamic";
import { usePathname } from "next/navigation";
import { NuqsAdapter } from "nuqs/adapters/next/app";
import { useEffect } from "react";
import { CookiesProvider } from "react-cookie";
import { toast, Toaster } from "sonner";

// Dynamic import - only loaded in development, completely excluded from prod bundle
const DevProfiler = dynamic(() => import("@/components/devProfiler").then((mod) => ({ default: mod.DevProfiler })), { ssr: false });

function StoreSyncInitializer() {
	useStoreSync();
	return null;
}

function WorkspaceAccessGate({ children }: { children: React.ReactNode }) {
	// OSS build: no login page, single implicit user/workspace. The portal
	// renders directly - no session check, no inactivity sign-out, no /login redirect.
	return <>{children}</>;
}

function AppContent({ children }: { children: React.ReactNode }) {
	const { data: deepintshieldConfig, error, isLoading } = useGetCoreConfigQuery({ fromDB: true });

	// Per-user theme persistence: pulls the saved preference on mount,
	// applies it via next-themes, and writes back to the server when the
	// user toggles. No-op when unauthenticated.
	useThemeSync();

	useEffect(() => {
		if (error) {
			toast.error(getErrorMessage(error));
		}
	}, [error]);

	return (
		<WebSocketProvider>
			<CookiesProvider>
				<StoreSyncInitializer />
				<SidebarProvider>
					<Sidebar />
					<div className="content-container custom-scrollbar border-border/70 bg-card/78 my-2 mr-2 h-[calc(100dvh-1rem)] w-full min-w-xl overflow-auto rounded-xl border px-4 py-3 md:px-5 md:py-4">
						<main className="content-container-inner custom-scrollbar relative mx-auto flex flex-col overflow-y-hidden p-2 md:p-3">
							{isLoading ? (
								<FullPageLoader />
							) : (
								<FullPage config={deepintshieldConfig}>
									<TenantWorkspaceGate>{children}</TenantWorkspaceGate>
								</FullPage>
							)}
						</main>
					</div>
				</SidebarProvider>
			</CookiesProvider>
		</WebSocketProvider>
	);
}

function FullPage({ config, children }: { config: DeepIntShieldConfig | undefined; children: React.ReactNode }) {
	const pathname = usePathname();
	if (config && config.is_db_connected) {
		return children;
	}
	if (config && config.is_logs_connected && pathname.startsWith("/workspace/logs")) {
		return children;
	}
	return <NotAvailableBanner />;
}

function TenantWorkspaceGate({ children }: { children: React.ReactNode }) {
	// OSS build: single implicit workspace, no tenant/workspace creation
	// flow. The portal renders every page directly without bouncing to a
	// create-tenant / create-workspace screen.
	return <>{children}</>;
}

export function ClientLayout({ children }: { children: React.ReactNode }) {
	return (
		<ProgressProvider>
			<ThemeProvider attribute="class" defaultTheme="light" enableSystem>
				<Toaster position="top-right" richColors closeButton />
				<ReduxProvider>
					<NuqsAdapter>
						<RbacProvider>
							<WorkspaceAccessGate>
								<AppContent>{children}</AppContent>
							</WorkspaceAccessGate>
							{process.env.NODE_ENV === "development" && !process.env.NEXT_PUBLIC_DISABLE_PROFILER && <DevProfiler />}
						</RbacProvider>
					</NuqsAdapter>
				</ReduxProvider>
			</ThemeProvider>
		</ProgressProvider>
	);
}
