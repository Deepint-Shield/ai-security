// The in-app docs page is deprecated. Documentation lives at
// docs.deepintshield.com (Starlight, source in deepintshield_docs/).
//
// This page exists only to handle bookmarks to /docs and /docs/* and bounce
// them out to the canonical home. Subpath bookmarks (e.g. /docs/sdk-guide)
// will land here too - the static-export build means every URL under /docs
// resolves to this single index, so we redirect everyone to the docs root
// and let users navigate from there.
import { Suspense } from "react";

export const dynamic = "error";

const TARGET = "https://docs.deepintshield.com";

export default function DocsRedirectPage() {
	return (
		<html lang="en">
			<head>
				<meta httpEquiv="refresh" content={`0; url=${TARGET}`} />
				<meta name="robots" content="noindex" />
				<link rel="canonical" href={TARGET} />
				<title>Redirecting…</title>
				<script
					// eslint-disable-next-line react/no-danger
					dangerouslySetInnerHTML={{
						__html: `if (typeof window !== 'undefined') { window.location.replace(${JSON.stringify(TARGET)}); }`,
					}}
				/>
			</head>
			<body
				style={{
					fontFamily:
						"Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
					padding: "3rem 1.5rem",
					textAlign: "center",
					color: "#0c3b43",
				}}
			>
				<Suspense fallback={null}>
					<p style={{ fontSize: "1rem" }}>
						Documentation has moved.{" "}
						<a href={TARGET} style={{ color: "#0e8f82", textDecoration: "underline" }}>
							Continue to docs.deepintshield.com →
						</a>
					</p>
				</Suspense>
			</body>
		</html>
	);
}
