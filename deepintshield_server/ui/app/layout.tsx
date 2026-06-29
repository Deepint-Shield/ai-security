import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

// Inter as the single sans-serif across the app, loaded as a VARIABLE font
// (no `weight` array) so every weight from 100..900 ships in one woff2 file
// instead of five - that's 1 fetch + decode instead of 5 on first paint,
// and any in-between weight (e.g. our 650/750 light-mode heading bumps)
// renders without an extra network request. next/font self-hosts the file
// at build time so there's no third-party DNS / TLS RTT on the critical
// path either. `display: swap` keeps the page legible during the swap
// window (system fallback paints first, Inter swaps in zero-shift thanks
// to next/font's adjusted-font-fallback metrics). `axes: ["opsz"]` opts
// into Inter's optical-size axis so small captions and 30px headlines
// each pull the glyph variant tuned for their size - that's where the
// "sharp at every size" feel comes from. Token name `--font-sora` is
// retained for backwards compat with existing `font-[var(--font-sora)]`
// consumers.
const inter = Inter({
	subsets: ["latin"],
	variable: "--font-sora",
	display: "swap",
	axes: ["opsz"],
	preload: true,
});

// JetBrains Mono - variable file too; covers every code / id / numeric
// column the app renders with one fetch + one shared rhythm.
const jetbrainsMono = JetBrains_Mono({
	subsets: ["latin"],
	variable: "--font-jetbrains-mono",
	display: "swap",
	preload: true,
});

export const metadata: Metadata = {
	title: "DeepintShield",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
	return (
		<html lang="en" suppressHydrationWarning className={`${inter.variable} ${jetbrainsMono.variable}`}>
			<head>
				<link rel="dns-prefetch" href="https://deepintshield.com" />
				<link rel="preconnect" href="https://deepintshield.com" />
			</head>
			<body className="font-sans antialiased">{children}</body>
		</html>
	);
}
