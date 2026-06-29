"use client";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ONBOARDING_STEP_ORDER, OnboardingStepId, useOnboarding } from "@/hooks/useOnboarding";
import { cn } from "@/lib/utils";
import { ArrowRight, Boxes, CheckCircle2, KeyRound, Rocket, Sparkles, Users, Building, ShieldCheck, Layers, FolderTree } from "lucide-react";
import { useRouter } from "next/navigation";
import { useMemo } from "react";

type StepDefinition = {
	id: OnboardingStepId;
	title: string;
	subtitle: string;
	href: string;
	icon: React.ComponentType<{ className?: string }>;
	details: string[];
};

const STEPS: StepDefinition[] = [
	{
		id: "tenant",
		title: "Create a tenant",
		subtitle: "Governance Hub → Tenants",
		href: "/workspace/governance/tenants",
		icon: Layers,
		details: [
			"A tenant is your top-level environment - like Dev, Staging, or Production.",
			"Click Add Tenant and give it a name.",
			"Everything you do next (workspaces, keys, policies) lives inside this tenant.",
		],
	},
	{
		id: "workspace",
		title: "Create a workspace",
		subtitle: "Governance Hub → Workspaces",
		href: "/workspace/governance/workspaces",
		icon: FolderTree,
		details: [
			"Workspaces split a tenant into projects or teams.",
			"Click Add Workspace, name it, and pick the tenant you just created.",
			"Members, providers, and policies you add next will be scoped to this workspace.",
		],
	},
	{
		id: "providers",
		title: "Connect an AI provider",
		subtitle: "Model Hub → AI Providers",
		href: "/workspace/providers",
		icon: Boxes,
		details: [
			"Open AI Providers and click Add Provider.",
			"Pick a provider (OpenAI, Anthropic, Bedrock…) and update details.",
			"Save. That provider is now usable by every team and key you create next.",
		],
	},
	{
		id: "members",
		title: "Add a teammate",
		subtitle: "Governance Hub → Members",
		href: "/workspace/access/members",
		icon: Users,
		details: [
			"Click Add Member and enter their name or email.",
			"Optionally set a monthly budget or rate limit so spending stays in check.",
		],
	},
	{
		id: "teams",
		title: "Group them into a team",
		subtitle: "Governance Hub → Teams",
		href: "/workspace/access/teams",
		icon: Building,
		details: [
			"Click Add Team, give it a name, and add the member you just created.",
			"You can add more members and set a shared team budget at any time.",
		],
	},
	{
		id: "policies",
		title: "Pick safety rules",
		subtitle: "AI Guardrails → Policies",
		href: "/workspace/guardrails/configuration",
		icon: ShieldCheck,
		details: [
			"Click Create Policy and choose a ready-made pack (PII, healthcare, code…).",
			"Update Policy details.",
			"Click Publish.",
		],
	},
	{
		id: "keys",
		title: "Create your app's API key",
		subtitle: "Virtual API Keys",
		href: "/workspace/access/virtual-keys",
		icon: KeyRound,
		details: [
			"Click Create Virtual Key.",
			"Attach the team, provider(s), and safety policy you just set up.",
			"Copy the key - paste it into your app. That's the only key your code needs.",
		],
	},
];

export function WelcomeOnboarding() {
	const router = useRouter();
	const onboarding = useOnboarding();

	const completedSet = useMemo(() => new Set(onboarding.completed), [onboarding.completed]);
	const completedCount = completedSet.size;
	const progressPct = Math.round((completedCount / STEPS.length) * 100);

	const handleGoToStep = (step: StepDefinition) => {
		onboarding.setCurrentStep(step.id);
		onboarding.markCompleted(step.id);
		onboarding.closeModal();
		router.push(step.href);
	};

	const handleDismissChange = (checked: boolean) => {
		onboarding.setDismissed(checked);
	};

	// Don't render anything until hydrated to avoid SSR/CSR localStorage mismatch.
	if (!onboarding.hydrated) return null;

	const showResumeFab = !onboarding.open && !onboarding.dismissed && completedCount < STEPS.length;

	const allDone = completedCount === STEPS.length;

	return (
		<>
			<Dialog open={onboarding.open} onOpenChange={(o) => (o ? onboarding.openModal() : onboarding.closeModal())}>
				<DialogContent className="max-w-2xl gap-0 overflow-hidden p-0 sm:max-w-2xl">
					{/* Hero */}
					<div className="relative overflow-hidden border-b border-border/60 px-6 py-6">
						<div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_15%_20%,rgba(34,211,196,0.18),transparent_42%),radial-gradient(circle_at_85%_0%,rgba(96,169,255,0.16),transparent_38%),linear-gradient(180deg,rgba(34,211,196,0.05),transparent_40%)]" />
						<div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary/40 to-transparent" />
						<div className="relative flex items-start gap-4">
							<div className="relative flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-primary/15 text-primary shadow-[inset_0_1px_0_rgba(255,255,255,0.1),0_8px_24px_-12px_rgba(34,211,196,0.55)]">
								<Sparkles className="h-7 w-7" />
								<span className="absolute -right-1 -top-1 inline-flex h-3 w-3 items-center justify-center">
									<span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary/50 opacity-75" />
									<span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-primary" />
								</span>
							</div>
							<div className="flex-1 min-w-0">
								<DialogHeader className="border-0 p-0 text-left">
									<DialogTitle className="text-xl tracking-tight">Welcome to DeepintShield</DialogTitle>
									<DialogDescription className="leading-relaxed">
										Set up your tenant and workspace, connect a provider, invite
										your team, pick safety rules, and grab your app's API key.
									</DialogDescription>
								</DialogHeader>
								<div className="mt-4 flex items-center gap-3">
									<div className="relative h-2 flex-1 overflow-hidden rounded-full bg-muted/60">
										<div
											className="h-full rounded-full bg-gradient-to-r from-primary to-cyan-400 transition-all duration-500"
											style={{ width: `${progressPct}%` }}
										/>
									</div>
									<div className="flex shrink-0 items-baseline gap-1.5 text-xs tabular-nums">
										<span className="font-semibold text-foreground">{completedCount}</span>
										<span className="text-muted-foreground">/ {STEPS.length}</span>
										<span className="ml-1 rounded-full bg-primary/10 px-1.5 py-0.5 text-[10px] font-semibold text-primary">
											{progressPct}%
										</span>
									</div>
								</div>
							</div>
						</div>
					</div>

					{/* Steps */}
					<div className="custom-scrollbar max-h-[60vh] overflow-y-auto bg-muted/20 px-5 py-4">
						<ol className="flex flex-col gap-2.5">
							{STEPS.map((step, idx) => {
								const isDone = completedSet.has(step.id);
								const isCurrent = onboarding.currentStep === step.id;
								const Icon = step.icon;
								return (
									<li
										key={step.id}
										className={cn(
											"group relative flex flex-col gap-3 rounded-2xl border bg-card p-4 transition-all",
											"border-border/60 hover:border-primary/30 hover:shadow-[0_8px_28px_-18px_rgba(11,42,49,0.16)]",
											isDone && "border-emerald-500/30 bg-emerald-500/[0.04] hover:border-emerald-500/50",
											isCurrent && !isDone && "border-primary/40 bg-primary/[0.04] shadow-[0_8px_28px_-18px_rgba(34,211,196,0.4)]",
										)}
									>
										<div className="flex items-start gap-3.5">
											{/* Step number / done check */}
											<button
												type="button"
												onClick={() => onboarding.toggleCompleted(step.id)}
												aria-label={isDone ? `Mark step ${idx + 1} as not done` : `Mark step ${idx + 1} as done`}
												className={cn(
													"mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-full border-2 text-sm font-semibold transition-all",
													isDone
														? "border-emerald-500 bg-emerald-500 text-white shadow-[0_4px_14px_-6px_rgba(16,185,129,0.6)]"
														: isCurrent
															? "border-primary bg-primary/10 text-primary"
															: "border-border bg-background text-muted-foreground hover:border-primary/50 hover:bg-primary/5 hover:text-primary",
												)}
											>
												{isDone ? <CheckCircle2 className="h-4.5 w-4.5" /> : <span className="tabular-nums">{idx + 1}</span>}
											</button>

											{/* Body */}
											<div className="flex-1 min-w-0">
												<div className="flex flex-wrap items-center gap-2">
													<span
														className={cn(
															"flex h-6 w-6 shrink-0 items-center justify-center rounded-md border",
															isDone
																? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-300"
																: "border-border/60 bg-muted/60 text-muted-foreground",
														)}
													>
														<Icon className="h-3.5 w-3.5" />
													</span>
													<h3
														className={cn(
															"text-sm font-semibold",
															isDone && "text-muted-foreground line-through decoration-emerald-500/40 decoration-1",
														)}
													>
														{step.title}
													</h3>
													<span className="rounded-md border border-border/60 bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-muted-foreground">
														{step.subtitle}
													</span>
												</div>
												<ul className="mt-2.5 ml-0.5 flex flex-col gap-1.5 text-xs leading-relaxed text-muted-foreground">
													{step.details.map((d, i) => (
														<li key={i} className="flex gap-2">
															<span
																className={cn(
																	"mt-1.5 inline-block h-1 w-1 shrink-0 rounded-full",
																	isDone ? "bg-emerald-500/50" : "bg-primary/50",
																)}
															/>
															<span>{d}</span>
														</li>
													))}
												</ul>
											</div>

											{/* Actions */}
											<div className="flex shrink-0 flex-col items-end gap-1.5">
												<Button
													size="sm"
													variant={isDone ? "outline" : "default"}
													onClick={() => handleGoToStep(step)}
													className="min-w-[6.5rem]"
												>
													{isDone ? "Revisit" : "Go to step"}
													<ArrowRight className="ml-1 h-3.5 w-3.5" />
												</Button>
												<button
													type="button"
													onClick={() => onboarding.toggleCompleted(step.id)}
													className={cn(
														"inline-flex items-center gap-1 rounded-md px-2 py-1 text-[11px] font-medium transition-colors",
														isDone
															? "text-emerald-600 hover:bg-emerald-500/10 dark:text-emerald-300"
															: "text-muted-foreground hover:bg-muted hover:text-foreground",
													)}
												>
													<CheckCircle2 className="h-3 w-3" />
													{isDone ? "Done" : "Mark done"}
												</button>
											</div>
										</div>
									</li>
								);
							})}
						</ol>
					</div>

					{/* Footer */}
					<div className="flex flex-col gap-3 border-t border-border/60 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
						<label className="flex cursor-pointer items-center gap-2 text-sm">
							<Checkbox checked={onboarding.dismissed} onCheckedChange={(v) => handleDismissChange(v === true)} />
							<span className="text-muted-foreground">Don't show this on startup</span>
						</label>
						<div className="flex items-center gap-2">
							{!allDone && (
								<Button variant="ghost" size="sm" onClick={onboarding.closeModal}>
									Skip for now
								</Button>
							)}
							{allDone && (
								<Button
									size="sm"
									onClick={onboarding.closeModal}
									className="bg-emerald-500 text-white hover:bg-emerald-500/90 dark:bg-emerald-500"
								>
									<CheckCircle2 className="mr-1.5 h-3.5 w-3.5" />
									Finish setup
								</Button>
							)}
						</div>
					</div>
				</DialogContent>
			</Dialog>

			{/* Resume FAB */}
			{showResumeFab && (
				<button
					type="button"
					onClick={onboarding.openModal}
					className="fixed right-6 bottom-6 z-40 flex items-center gap-2.5 rounded-full border border-primary/40 bg-card/95 px-4 py-2.5 text-sm font-medium shadow-[0_18px_38px_-22px_rgba(34,211,196,0.55)] backdrop-blur-md transition-all hover:-translate-y-0.5 hover:border-primary hover:bg-primary/10 hover:shadow-[0_20px_42px_-18px_rgba(34,211,196,0.65)]"
					aria-label="Resume onboarding"
				>
					{/* Mini progress ring */}
					<span className="relative flex h-7 w-7 items-center justify-center">
						<svg className="absolute inset-0 -rotate-90" viewBox="0 0 32 32">
							<circle cx="16" cy="16" r="13" className="stroke-muted" strokeWidth="3" fill="none" />
							<circle
								cx="16"
								cy="16"
								r="13"
								className="stroke-primary transition-all duration-500"
								strokeWidth="3"
								strokeLinecap="round"
								fill="none"
								strokeDasharray={`${(2 * Math.PI * 13 * progressPct) / 100} ${2 * Math.PI * 13}`}
							/>
						</svg>
						<Rocket className="relative h-3.5 w-3.5 text-primary" />
					</span>
					<span>Continue setup</span>
					<span className="rounded-full bg-primary/15 px-2 py-0.5 text-xs font-semibold text-primary tabular-nums">
						{completedCount}/{STEPS.length}
					</span>
				</button>
			)}
		</>
	);
}
