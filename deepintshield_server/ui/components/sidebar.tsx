"use client";

import {
	ArrowUpRight,
	Bot,
	Boxes,
	ChartPie,
	CircleGauge,
	FlaskConical,
	Globe,
	KeyRound,
	PanelLeft,
	ScanSearch,
	Search,
	SearchCheck,
	ScrollText,
	Settings,
	Shield,
	ShieldCheck,
	Shuffle,
	Wallet,
} from "lucide-react";

import { DeepIntShieldMark, DeepIntShieldWordmark } from "@/components/brand/deepIntShieldBrand";
import { UpdatesVersionChip } from "@/components/updatesVersionChip";
import {
	Sidebar,
	SidebarContent,
	SidebarGroup,
	SidebarGroupContent,
	SidebarHeader,
	SidebarMenu,
	SidebarMenuButton,
	SidebarMenuItem,
	SidebarMenuSub,
	SidebarMenuSubButton,
	SidebarMenuSubItem,
	useSidebar,
} from "@/components/ui/sidebar";
import { useWebSocket } from "@/hooks/useWebSocket";
import { ChevronRight } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Badge } from "./ui/badge";

// Sidebar item interface
interface SidebarItem {
	title: string;
	url: string;
	icon: React.ComponentType<{ className?: string }>;
	description: string;
	hasAccess: boolean;
	subItems?: SidebarItem[];
	tag?: string;
	isExternal?: boolean;
	onClick?: () => void;
	queryParam?: string; // Optional: for tab-based subitems (e.g., "client-settings")
}

const getSidebarItemHref = (item: Pick<SidebarItem, "url" | "queryParam">) => {
	return item.queryParam ? `${item.url}?tab=${item.queryParam}` : item.url;
};

const SidebarItemView = ({
	item,
	isActive,
	isExternal,
	isWebSocketConnected,
	isExpanded,
	onToggle,
	pathname,
	router,
	isSidebarCollapsed,
	expandSidebar,
	highlightedUrl,
	prefetchRoute,
}: {
	item: SidebarItem;
	isActive: boolean;
	isExternal?: boolean;
	isWebSocketConnected: boolean;
	isExpanded?: boolean;
	onToggle?: () => void;
	pathname: string;
	router: ReturnType<typeof useRouter>;
	isSidebarCollapsed: boolean;
	expandSidebar: () => void;
	highlightedUrl?: string;
	prefetchRoute: (url: string) => void;
}) => {
	const hasSubItems = "subItems" in item && item.subItems && item.subItems.length > 0;
	const isAnySubItemActive =
		hasSubItems &&
		item.subItems?.some((subItem) => {
			if (subItem.onClick) return false;
			return pathname.startsWith(subItem.url);
		});

	const handleClick = (e: React.MouseEvent) => {
		if (hasSubItems && item.hasAccess) {
			e.preventDefault();
			// If sidebar is collapsed, expand it first then toggle the submenu
			if (isSidebarCollapsed) {
				expandSidebar();
				// Small delay to allow sidebar to expand before toggling submenu
				setTimeout(() => {
					if (onToggle) onToggle();
				}, 100);
			} else if (onToggle) {
				onToggle();
			}
		}
	};

	const openInNewTab = (url: string) => {
		window.open(url, "_blank", "noopener,noreferrer");
	};

	const handleNavigation = (sidebarItem: SidebarItem, e?: React.MouseEvent) => {
		if (sidebarItem.onClick) {
			sidebarItem.onClick();
			return;
		}
		const url = getSidebarItemHref(sidebarItem);
		if (sidebarItem.isExternal || e?.metaKey || e?.ctrlKey) {
			openInNewTab(url);
			return;
		}
		router.push(url);
	};

	const handleSubItemClick = (subItem: SidebarItem, e?: React.MouseEvent) => {
		if (subItem.onClick) {
			subItem.onClick();
			return;
		}
		const url = getSidebarItemHref(subItem);
		if (subItem.isExternal || e?.metaKey || e?.ctrlKey) {
			openInNewTab(url);
			return;
		}
		router.push(url);
	};

	const isHighlighted = !hasSubItems && highlightedUrl === item.url;

	return (
		<SidebarMenuItem key={item.title}>
			<SidebarMenuButton
				tooltip={item.title}
				data-nav-url={!hasSubItems ? item.url : undefined}
				className={`relative h-9 cursor-pointer rounded-xl border px-3.5 transition-all duration-200 ${
					isHighlighted
						? "bg-sidebar-accent text-accent-foreground border-primary/30 shadow-[0_10px_22px_-18px_rgba(34,211,196,0.5)]"
						: isActive || isAnySubItemActive
							? "text-primary border-primary/25 bg-[linear-gradient(135deg,rgba(34,211,196,0.14),rgba(96,169,255,0.08))] shadow-[0_14px_26px_-20px_rgba(34,211,196,0.46)]"
							: item.hasAccess
								? "hover:bg-sidebar-accent/90 hover:text-accent-foreground text-muted-foreground border-transparent"
								: "hover:bg-destructive/5 hover:text-muted-foreground text-muted-foreground cursor-not-allowed border-transparent"
				} `}
				onClick={hasSubItems ? handleClick : item.hasAccess ? (e) => handleNavigation(item, e) : undefined}
				onMouseEnter={!hasSubItems && item.hasAccess && !item.onClick ? () => prefetchRoute(item.url) : undefined}
				onFocus={!hasSubItems && item.hasAccess && !item.onClick ? () => prefetchRoute(item.url) : undefined}
			>
				<div className="flex w-full items-center justify-between">
					<div className="flex w-full items-center gap-2">
						<item.icon className={`h-4 w-4 shrink-0 ${isActive || isAnySubItemActive ? "text-primary" : "text-muted-foreground"}`} />
						<span
							className={`text-sm group-data-[collapsible=icon]:hidden ${isActive || isAnySubItemActive ? "font-medium" : "font-normal"}`}
						>
							{item.title}
						</span>
						{item.tag && (
							<Badge variant="secondary" className="text-muted-foreground ml-auto text-xs group-data-[collapsible=icon]:hidden">
								{item.tag}
							</Badge>
						)}
					</div>
					{hasSubItems && (
						<ChevronRight
							className={`h-4 w-4 transition-transform duration-200 group-data-[collapsible=icon]:hidden ${isExpanded ? "rotate-90" : ""}`}
						/>
					)}
					{!hasSubItems && item.url === "/logs" && isWebSocketConnected && (
						<div className="h-2 w-2 animate-pulse rounded-full bg-green-800 dark:bg-green-200" />
					)}
					{isExternal && <ArrowUpRight className="text-muted-foreground h-4 w-4 group-data-[collapsible=icon]:hidden" size={16} />}
				</div>
			</SidebarMenuButton>
			{hasSubItems && isExpanded && (
				<SidebarMenuSub className="border-sidebar-border/70 mt-1 ml-4 space-y-0.5 border-l pl-3">
					{item.subItems?.map((subItem: SidebarItem) => {
						const subItemHref = getSidebarItemHref(subItem);
						// For query param based subitems, check if tab matches
						const isSubItemActive = subItem.onClick
							? false
							: subItem.queryParam
								? pathname === subItem.url
								: pathname.startsWith(subItem.url);
						const isSubItemHighlighted = highlightedUrl === subItemHref;
						const SubItemIcon = subItem.icon;
						return (
							<SidebarMenuSubItem key={subItem.title}>
								<SidebarMenuSubButton
									data-nav-url={subItemHref}
									className={`relative h-8 cursor-pointer rounded-lg px-2.5 transition-all duration-200 ${
										isSubItemHighlighted
											? "bg-sidebar-accent text-accent-foreground"
											: isSubItemActive
												? "text-primary bg-[linear-gradient(135deg,rgba(34,211,196,0.10),rgba(96,169,255,0.06))] font-medium"
												: subItem.hasAccess === false
													? "hover:bg-destructive/5 hover:text-muted-foreground text-muted-foreground cursor-not-allowed border-transparent"
													: "hover:bg-sidebar-accent/90 hover:text-accent-foreground text-muted-foreground"
									}`}
									onClick={(e) => (subItem.hasAccess === false ? undefined : handleSubItemClick(subItem, e))}
									onMouseEnter={
										subItem.hasAccess === false || subItem.onClick ? undefined : () => prefetchRoute(getSidebarItemHref(subItem))
									}
									onFocus={subItem.hasAccess === false || subItem.onClick ? undefined : () => prefetchRoute(getSidebarItemHref(subItem))}
								>
									{/* Left-rail accent for the active sub-item - anchors
									 * the highlight to the parent guide line so the eye
									 * traces hierarchy at a glance instead of just
									 * spotting a tinted background. */}
									{isSubItemActive && (
										<span
											aria-hidden
											className="bg-primary absolute top-1/2 -left-3.5 h-4 w-0.5 -translate-y-1/2 rounded-full shadow-[0_0_0_3px_rgba(34,211,196,0.18)]"
										/>
									)}
									<div className="flex w-full items-center gap-2">
										{SubItemIcon && <SubItemIcon className={`h-3.5 w-3.5 ${isSubItemActive ? "text-primary" : "text-muted-foreground"}`} />}
										<span className={`text-sm ${isSubItemActive ? "font-medium" : "font-normal"}`}>{subItem.title}</span>
										{subItem.tag && (
											<Badge variant="secondary" className="text-muted-foreground ml-auto text-xs">
												{subItem.tag}
											</Badge>
										)}
									</div>
								</SidebarMenuSubButton>
							</SidebarMenuSubItem>
						);
					})}
				</SidebarMenuSub>
			)}
		</SidebarMenuItem>
	);
};

export default function AppSidebar() {
	const pathname = usePathname();
	const router = useRouter();
	const [expandedItems, setExpandedItems] = useState<Set<string>>(new Set());
	const [searchQuery, setSearchQuery] = useState("");
	const [focusedIndex, setFocusedIndex] = useState(-1);
	const searchInputRef = useRef<HTMLInputElement>(null);

	const items = useMemo<SidebarItem[]>(
		() => [
			{
				title: "Analytics",
				url: "/workspace/analytics",
				icon: ChartPie,
				description: "Usage, cost, and latency analytics",
				hasAccess: true,
			},
			{
				title: "AI Logs",
				url: "/workspace/logs",
				icon: ScrollText,
				description: "Model request activity and traces",
				hasAccess: true,
			},
			{
				title: "AI Providers",
				url: "/workspace/providers",
				icon: Boxes,
				description: "Provider access, keys, and policies",
				hasAccess: true,
			},
			{
				title: "Model Registry",
				url: "/workspace/model-catalog",
				icon: SearchCheck,
				description: "Unified view of active model assets",
				hasAccess: true,
			},
			{
				title: "Model Routing",
				url: "/workspace/routing-rules",
				icon: Shuffle,
				description: "Routing logic and provider steering",
				hasAccess: true,
			},
			{
				title: "Usage Controls",
				url: "/workspace/model-limits",
				icon: Wallet,
				description: "Budgets, quotas, and limits",
				hasAccess: true,
			},
			{
				title: "Virtual Keys",
				url: "/workspace/access/virtual-keys",
				icon: KeyRound,
				description: "Scoped session and workload keys",
				hasAccess: true,
			},
			{
				title: "Guardrails",
				url: "/workspace/config/guardrails",
				icon: Shield,
				description: "Deterministic regex + PII guardrails",
				hasAccess: true,
			},
			{
				title: "Agentic Policy",
				url: "/workspace/config/agentic",
				icon: Bot,
				description: "Agentic policy decisions (/decide)",
				hasAccess: true,
			},
			{
				title: "Caching & Cost",
				url: "/workspace/config/caching",
				icon: CircleGauge,
				description: "Semantic cache & cost optimization",
				hasAccess: true,
			},
			{
				title: "Hallucination Control",
				url: "/workspace/hallucination/control",
				icon: ScanSearch,
				description: "Zero-latency mitigations: grounding, anti-fabrication, citations",
				hasAccess: true,
			},
			{
				title: "Playground",
				url: "/workspace/prompt-repo/prompts",
				icon: FlaskConical,
				description: "Compose and run prompts against the gateway",
				hasAccess: true,
			},
			{
				title: "Config",
				url: "/workspace/config/proxy",
				icon: Settings,
				description: "Proxy and logging configuration",
				hasAccess: true,
				subItems: [
					{
						title: "Proxy",
						url: "/workspace/config/proxy",
						icon: Globe,
						description: "Proxy and egress routing",
						hasAccess: true,
					},
					{
						title: "Logging",
						url: "/workspace/config/logging",
						icon: ShieldCheck,
						description: "Runtime logging controls",
						hasAccess: true,
					},
				],
			},
		],
		[],
	);

	const filteredItems: SidebarItem[] = useMemo(() => {
		const query = searchQuery.trim().toLowerCase();
		if (!query) return items;

		return items
			.map((item) => {
				const parentMatches = item.title.toLowerCase().includes(query);
				if (parentMatches) return item;

				if (item.subItems) {
					const matchingSubItems = item.subItems.filter((sub) => sub.title.toLowerCase().includes(query));
					if (matchingSubItems.length > 0) {
						return { ...item, subItems: matchingSubItems };
					}
				}
				return null;
			})
			.filter(Boolean) as SidebarItem[];
	}, [items, searchQuery]);

	const prefetchRoute = useCallback(
		(url: string) => {
			if (!url.startsWith("/")) {
				return;
			}
			router.prefetch(url);
		},
		[router],
	);

	// Auto-expand items when their subitems are active
	useEffect(() => {
		const newExpandedItems = new Set<string>();
		items.forEach((item) => {
			if (item.subItems?.some((subItem) => pathname.startsWith(subItem.url))) {
				newExpandedItems.add(item.title);
			}
		});
		if (newExpandedItems.size > 0) {
			setExpandedItems((prev) => new Set([...prev, ...newExpandedItems]));
		}
	}, [pathname, items]);

	// Auto-expand parents when search matches their subItems
	useEffect(() => {
		const query = searchQuery.trim().toLowerCase();
		if (!query) return;
		const toExpand = new Set<string>();
		items.forEach((item) => {
			if (!item.subItems?.length) return;
			const parentMatches = item.title.toLowerCase().includes(query);
			if (parentMatches) return;
			const hasMatchingChild = item.subItems.some((sub) => sub.title.toLowerCase().includes(query));
			if (hasMatchingChild) {
				toExpand.add(item.title);
			}
		});
		if (toExpand.size > 0) {
			setExpandedItems((prev) => {
				const hasAll = [...toExpand].every((t) => prev.has(t));
				if (hasAll) return prev;
				return new Set([...prev, ...toExpand]);
			});
		}
	}, [searchQuery, items]);

	// Cmd+K to focus search input
	useEffect(() => {
		const handleKeyDown = (event: KeyboardEvent) => {
			if (event.key === "k" && (event.metaKey || event.ctrlKey)) {
				event.preventDefault();
				searchInputRef.current?.focus();
			}
		};
		window.addEventListener("keydown", handleKeyDown);
		return () => window.removeEventListener("keydown", handleKeyDown);
	}, []);

	// Flat list of navigable items for keyboard navigation
	const navigableItems = useMemo(() => {
		const result: { title: string; url: string; queryParam?: string; isExternal?: boolean; onClick?: () => void }[] = [];
		for (const item of filteredItems) {
			if (item.isExternal) {
				if (item.hasAccess) result.push({ title: item.title, url: item.url, isExternal: true, onClick: item.onClick });
				continue;
			}
			const hasSubItems = item.subItems && item.subItems.length > 0;
			if (hasSubItems) {
				// When search is active or parent is expanded, include visible subItems
				if (searchQuery.trim() || expandedItems.has(item.title)) {
					for (const sub of item.subItems!) {
						if (sub.hasAccess === false) continue;
						result.push({
							title: sub.title,
							url: getSidebarItemHref(sub),
							queryParam: sub.queryParam,
							isExternal: sub.isExternal,
							onClick: sub.onClick,
						});
					}
				} else {
					// Parent is collapsed - include parent as a toggle target
					if (item.hasAccess) result.push({ title: item.title, url: item.url, onClick: item.onClick });
				}
			} else {
				if (item.hasAccess) result.push({ title: item.title, url: item.url, isExternal: item.isExternal, onClick: item.onClick });
			}
		}
		return result;
	}, [filteredItems, expandedItems, searchQuery]);

	const handleSearchKeyDown = useCallback(
		(e: React.KeyboardEvent<HTMLInputElement>) => {
			if (e.key === "ArrowDown") {
				e.preventDefault();
				setFocusedIndex((prev) => Math.min(prev + 1, navigableItems.length - 1));
			} else if (e.key === "ArrowUp") {
				e.preventDefault();
				setFocusedIndex((prev) => Math.max(prev - 1, 0));
			} else if (e.key === "Enter") {
				e.preventDefault();
				const target = navigableItems[focusedIndex];
				if (target) {
					if (target.onClick) {
						target.onClick();
						setSearchQuery("");
						setFocusedIndex(-1);
						searchInputRef.current?.blur();
						return;
					}
					const url = target.url;
					if (target.isExternal || e.metaKey || e.ctrlKey) {
						window.open(url, "_blank", "noopener,noreferrer");
					} else {
						router.push(url);
					}
					setSearchQuery("");
					setFocusedIndex(-1);
					searchInputRef.current?.blur();
				}
			} else if (e.key === "Escape") {
				setSearchQuery("");
				setFocusedIndex(-1);
				searchInputRef.current?.blur();
			}
		},
		[navigableItems, focusedIndex, router],
	);

	// Auto-scroll focused item into view
	useEffect(() => {
		if (focusedIndex < 0) return;
		const url = navigableItems[focusedIndex]?.url;
		if (!url) return;
		const el = document.querySelector(`[data-nav-url="${url}"]`);
		el?.scrollIntoView({ block: "nearest" });
	}, [focusedIndex, navigableItems]);

	const toggleItem = (title: string) => {
		setExpandedItems((prev) => {
			const next = new Set(prev);
			if (next.has(title)) {
				next.delete(title);
			} else {
				next.add(title);
			}
			return next;
		});
	};

	const configExceptions = ["/workspace/config/logging"];

	const isActiveRoute = (url: string) => {
		if (url === "/" && pathname === "/") return true;
		if (url !== "/" && pathname.startsWith(url)) {
			if (url === "/workspace/config" && configExceptions.some((e) => pathname.startsWith(e))) {
				return false;
			}
			return true;
		}
		return false;
	};

	const { isConnected: isWebSocketConnected } = useWebSocket();

	const { state: sidebarState, toggleSidebar } = useSidebar();

	return (
		<Sidebar collapsible="icon" className="overflow-y-clip border-none bg-transparent">
			<SidebarHeader className="mt-2 ml-2 flex justify-between px-0 group-data-[collapsible=icon]:ml-0 group-data-[collapsible=icon]:h-auto">
				{/* Expanded state: horizontal layout */}
				<div className="flex h-10 w-full items-center justify-between px-1.5 group-data-[collapsible=icon]:hidden">
					<Link href="/workspace/analytics" className="group flex items-center gap-2 pl-2">
						<DeepIntShieldWordmark compact />
					</Link>
					<button
						onClick={toggleSidebar}
						className="text-muted-foreground hover:text-foreground hover:bg-sidebar-accent hover:border-border/60 flex h-8 w-8 items-center justify-center rounded-xl border border-transparent transition-colors"
						aria-label="Collapse sidebar"
					>
						<PanelLeft className="h-4 w-4" />
					</button>
				</div>
				{/* Collapsed state: vertical layout */}
				<div
					className="hidden w-full cursor-pointer flex-col items-center gap-2 py-2 group-data-[collapsible=icon]:flex"
					onClick={toggleSidebar}
				>
					<DeepIntShieldMark className="h-10 w-10" />
				</div>
			</SidebarHeader>
			<div className="mx-2 pb-1 group-data-[collapsible=icon]:hidden">
				<div className="relative">
					<Search className="text-muted-foreground absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2" />
					<input
						ref={searchInputRef}
						type="text"
						aria-label="Search sidebar navigation"
						placeholder="Find..."
						value={searchQuery}
						onChange={(e) => {
							setSearchQuery(e.target.value);
							setFocusedIndex(-1);
						}}
						onKeyDown={handleSearchKeyDown}
						className="border-border text-foreground placeholder:text-muted-foreground focus:ring-ring bg-input/80 focus:bg-input/95 h-10 w-full rounded-xl border pr-14 pl-9 text-sm shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] backdrop-blur-md outline-none"
					/>
					<kbd className="text-muted-foreground pointer-events-none absolute top-1/2 right-2 flex -translate-y-1/2 gap-0.5 text-[10px]">
						<span className="border-border bg-muted rounded-sm px-1 font-mono shadow-sm">⌘</span>
					</kbd>
				</div>
			</div>
			<SidebarContent className="overflow-hidden pb-4">
				<SidebarGroup className="custom-scrollbar h-[calc(100vh-8rem)] overflow-scroll">
					<SidebarGroupContent>
						<SidebarMenu className="space-y-0.5">
							{filteredItems.map((item) => {
								const isActive = isActiveRoute(item.url);

								const highlightedUrl = focusedIndex >= 0 ? navigableItems[focusedIndex]?.url : undefined;
								return (
									<SidebarItemView
										key={item.title}
										item={item}
										isActive={isActive}
										isExternal={item.isExternal ?? false}
										isWebSocketConnected={isWebSocketConnected}
										isExpanded={expandedItems.has(item.title)}
										onToggle={() => toggleItem(item.title)}
										pathname={pathname}
										router={router}
										isSidebarCollapsed={sidebarState === "collapsed"}
										expandSidebar={() => toggleSidebar()}
										highlightedUrl={highlightedUrl}
										prefetchRoute={prefetchRoute}
									/>
								);
							})}
						</SidebarMenu>
					</SidebarGroupContent>
				</SidebarGroup>
				<div className="flex flex-col gap-3 px-3 pt-3 group-data-[collapsible=icon]:px-1">
					{/* Hairline gradient separator above the footer block. */}
					<div
						className="via-border -mx-1 h-px bg-gradient-to-r from-transparent to-transparent group-data-[collapsible=icon]:hidden"
						aria-hidden
					/>
					<UpdatesVersionChip />
				</div>
			</SidebarContent>
		</Sidebar>
	);
}
