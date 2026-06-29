"use client";

import Image from "next/image";
import { useTheme } from "next-themes";
import { useEffect, useState } from "react";

import { cn } from "@/lib/utils";

interface BrandMarkProps {
	className?: string;
}

/**
 * Resolves which logo asset to use based on the active theme. The
 * "-dark.png" file is the dark-foreground variant - designed to sit on
 * a *light* background. The plain "logo" / "mark" / "icon" file is the
 * light-foreground variant for dark backgrounds. We pick by reading
 * resolvedTheme so System mode also works (next-themes resolves it to
 * the OS preference).
 *
 * Anti-flash: until the client effect runs, `resolvedTheme` is undefined.
 * We default to the light asset (matches our defaultTheme="light"
 * in ThemeProvider) so SSR + first paint stay consistent.
 */
function useThemedAsset(lightSrc: string, darkSrc: string): string {
	const { resolvedTheme } = useTheme();
	const [mounted, setMounted] = useState(false);
	useEffect(() => setMounted(true), []);
	if (!mounted) return lightSrc;
	return resolvedTheme === "dark" ? darkSrc : lightSrc;
}

export function DeepIntShieldMark({ className }: BrandMarkProps) {
	const src = useThemedAsset("/deepintshield-mark.png", "/deepintshield-mark.png");
	return (
		<span
			className={cn("inline-flex shrink-0 items-center justify-center", className)}
			role="img"
			aria-label="DeepIntShield mark"
		>
			<Image src={src} alt="DeepIntShield" width={96} height={96} className="h-full w-full object-contain" priority />
		</span>
	);
}

interface WordmarkProps {
	className?: string;
	compact?: boolean;
	showTagline?: boolean;
}

export function DeepIntShieldWordmark({ className, compact = false, showTagline = false }: WordmarkProps) {
	// The DeepintShield horizontal lockup (shield + wordmark + tagline). Same
	// asset in both themes - the colored shield + wordmark read on light and
	// dark surfaces alike.
	const src = useThemedAsset("/deepintshield-logo.png", "/deepintshield-logo.png");
	return (
		<div className={cn("flex items-center justify-start", className)}>
			<Image
				src={src}
				alt="DeepIntShield"
				width={compact ? 220 : showTagline ? 300 : 260}
				height={compact ? 52 : showTagline ? 72 : 60}
				className={cn("object-contain object-left", compact ? "h-12" : showTagline ? "h-16" : "h-14")}
				priority
			/>
		</div>
	);
}
