import type { NextConfig } from "next";
import fs from "node:fs";
import path from "node:path";

const isEnterpriseBuild = fs.existsSync(path.join(__dirname, "app", "enterprise"));
const skipTypecheckForContainerBuild =
	(process.env.DEEPINTSHIELD_UI_SKIP_TYPECHECK ?? process.env.DEEPINTSHIELD_UI_SKIP_TYPECHECK) === "1";

const nextConfig: NextConfig = {
	output: "export",
	trailingSlash: true,
	skipTrailingSlashRedirect: true,
	distDir: "out",
	images: {
		unoptimized: true,
	},
	basePath: "",
	generateBuildId: () => "build",
	typescript: {
		// Local Docker builds can OOM during Next's type-validation phase.
		// Keep type-checking on by default and only skip it when the image opts in.
		ignoreBuildErrors: skipTypecheckForContainerBuild,
	},
	eslint: {
		ignoreDuringBuilds: true,
	},
	env: {
		NEXT_PUBLIC_IS_ENTERPRISE: isEnterpriseBuild ? "true" : "false",
	},
	// Proxy API requests to backend in development
	async rewrites() {
		return [
			{
				source: "/api/:path*",
				destination: "http://localhost:8080/api/:path*",
			},
		];
	},
	webpack: (config) => {
		config.resolve = config.resolve || {};
		config.resolve.alias = config.resolve.alias || {};
		config.resolve.alias["@enterprise"] = isEnterpriseBuild
			? path.join(__dirname, "app", "enterprise")
			: path.join(__dirname, "app", "_fallbacks", "enterprise");
		config.resolve.alias["@schemas"] = isEnterpriseBuild
			? path.join(__dirname, "app", "enterprise", "lib", "schemas")
			: path.join(__dirname, "app", "_fallbacks", "enterprise", "lib", "schemas");		
		// Ensure modules are resolved from the main project's node_modules
		config.resolve.modules = [
			path.join(__dirname, "node_modules"),
			"node_modules",
		];		
		// Ensure symlinks are resolved correctly
		config.resolve.symlinks = true;		
		return config;
	},
};

export default nextConfig;
