#!/usr/bin/env node

// DeepintShield npx launcher.
//
// Resolves the prebuilt `deepintshield-http` gateway binary for the current
// platform/arch, downloads it from this project's GitHub Releases (caching it
// under the OS cache directory), verifies its SHA-256 when a checksum is
// published, then executes it - forwarding every CLI argument and the exit
// code. With no arguments the gateway listens on http://localhost:8080.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
	chmodSync,
	createReadStream,
	createWriteStream,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	renameSync,
	rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Readable } from "node:stream";

const REPO = "deepint-shield/ai-security";
const GITHUB = "https://github.com";

// Bundled vector store for the semantic cache. redis-stack-server ships the
// RediSearch module the gateway needs for FT.* / HNSW vector queries - plain
// Redis won't do. We run it in a long-lived Docker container so the cache
// survives gateway restarts.
const REDIS_CONTAINER = "deepintshield-redis";
const REDIS_IMAGE = "redis/redis-stack-server:latest";
const REDIS_PORT = 6379;

const __dirname = dirname(fileURLToPath(import.meta.url));

function readPackageVersion() {
	try {
		const pkg = JSON.parse(readFileSync(join(__dirname, "package.json"), "utf8"));
		return pkg.version;
	} catch {
		return null;
	}
}

// The release tag to fetch. Defaults to this package's own version so the
// wrapper and the binary it runs are always in lock-step. Override with
// DEEPINTSHIELD_VERSION (e.g. "v0.10.2" or "latest") for testing.
function resolveTag() {
	const override = process.env.DEEPINTSHIELD_VERSION;
	if (override) {
		return override === "latest" ? "latest" : override.startsWith("v") ? override : `v${override}`;
	}
	const version = readPackageVersion();
	if (!version || version === "0.0.0") {
		// Unstamped local checkout - fall back to the newest published release.
		return "latest";
	}
	return `v${version}`;
}

function resolveTarget() {
	const platform = process.platform;
	const arch = process.arch;

	const osName = { darwin: "darwin", linux: "linux", win32: "windows" }[platform];
	const archName = { arm64: "arm64", x64: "amd64" }[arch];

	if (!osName || !archName) {
		fail(
			`Unsupported platform/arch: ${platform}/${arch}.\n` +
				`Prebuilt binaries are published for darwin (arm64, amd64), linux (arm64, amd64) and windows (amd64).\n` +
				`To run on this platform, build from source: https://github.com/${REPO}`,
		);
	}

	// windows is published for amd64 only.
	if (osName === "windows" && archName !== "amd64") {
		fail(`Unsupported platform/arch: ${platform}/${arch}. Windows binaries are published for amd64 only.`);
	}

	const ext = osName === "windows" ? ".exe" : "";
	return { asset: `deepintshield-http-${osName}-${archName}${ext}`, ext };
}

function assetUrl(tag, asset) {
	return tag === "latest"
		? `${GITHUB}/${REPO}/releases/latest/download/${asset}`
		: `${GITHUB}/${REPO}/releases/download/${tag}/${asset}`;
}

// Cache directory per platform: Linux ~/.cache, macOS ~/Library/Caches,
// Windows %LOCALAPPDATA%.
function cacheRoot() {
	if (process.platform === "linux") {
		return process.env.XDG_CACHE_HOME || join(process.env.HOME || tmpdir(), ".cache");
	}
	if (process.platform === "darwin") {
		return join(process.env.HOME || tmpdir(), "Library", "Caches");
	}
	if (process.platform === "win32") {
		return process.env.LOCALAPPDATA || join(process.env.USERPROFILE || tmpdir(), "AppData", "Local");
	}
	return tmpdir();
}

function fail(message, code = 1) {
	console.error(`\ndeepintshield: ${message}`);
	process.exit(code);
}

function formatBytes(bytes) {
	if (!bytes) return "0 B";
	const units = ["B", "KB", "MB", "GB"];
	const i = Math.floor(Math.log(bytes) / Math.log(1024));
	return `${parseFloat((bytes / 1024 ** i).toFixed(1))} ${units[i]}`;
}

async function fetchText(url) {
	const res = await fetch(url);
	if (!res.ok) return null;
	return (await res.text()).trim();
}

// Streams the asset to `target` (a temporary path). The caller verifies and
// marks it executable before atomically moving it into the final location.
async function download(url, target) {
	const res = await fetch(url, { redirect: "follow" });
	if (!res.ok) {
		fail(
			`download failed (${res.status} ${res.statusText}).\n` +
				`  ${url}\n` +
				`Check that the release exists at https://github.com/${REPO}/releases`,
		);
	}

	const total = Number(res.headers.get("content-length")) || 0;
	let received = 0;
	const out = createWriteStream(target);

	await new Promise((resolve, reject) => {
		const stream = Readable.fromWeb(res.body);
		stream.on("data", (chunk) => {
			received += chunk.length;
			const label = total
				? `${((received / total) * 100).toFixed(0)}% (${formatBytes(received)}/${formatBytes(total)})`
				: formatBytes(received);
			process.stderr.write(`\rdeepintshield: downloading gateway ${label}   `);
		});
		stream.on("error", reject);
		out.on("error", reject);
		out.on("finish", resolve);
		stream.pipe(out);
	});
	process.stderr.write("\n");
}

function sha256(file) {
	return new Promise((resolve, reject) => {
		const hash = createHash("sha256");
		const rs = createReadStream(file);
		rs.on("error", reject);
		rs.on("data", (d) => hash.update(d));
		rs.on("end", () => resolve(hash.digest("hex")));
	});
}

async function verifyChecksum(tag, asset, file) {
	// Checksums are best-effort: enforced when published, skipped for releases
	// that predate them. The .sha256 sidecar holds the bare hex digest.
	const expected = await fetchText(assetUrl(tag, `${asset}.sha256`));
	if (!expected) return;
	const actual = await sha256(file);
	const want = expected.split(/\s+/)[0].toLowerCase();
	if (actual.toLowerCase() !== want) {
		rmSync(file, { force: true });
		fail(`checksum mismatch for ${asset}\n  expected ${want}\n  actual   ${actual}`);
	}
}

function note(message) {
	process.stderr.write(`deepintshield: ${message}\n`);
}

// Blocking sleep without spinning the CPU - we run before the gateway starts and
// have nothing else to do while Redis comes up.
function sleepSync(ms) {
	Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

// Bring up the bundled Redis (redis-stack) so the semantic cache has a vector
// store, and point the gateway at it via DEEPINTSHIELD_REDIS_ADDR. Best-effort
// by design: caching is optional, so a missing Docker or a slow pull must never
// stop the gateway from starting - the gateway degrades to no semantic cache.
//
// We always export the address (not just on success): if Redis isn't up, the
// gateway's own connect attempt fails and it boots without the vector store,
// which keeps the env-substitution in config.json valid either way.
function ensureRedis(env) {
	// Bring-your-own Redis/Valkey wins - never second-guess an explicit endpoint.
	if (env.DEEPINTSHIELD_REDIS_ADDR) return;

	const docker = (args, opts = {}) =>
		execFileSync("docker", args, { stdio: ["ignore", "pipe", "ignore"], encoding: "utf8", ...opts }).trim();

	try {
		docker(["version", "--format", "{{.Server.Version}}"]);
	} catch {
		note("Docker not found - semantic caching is off. Install Docker, or set DEEPINTSHIELD_REDIS_ADDR to your own Redis (with the search module) to enable it.");
		return;
	}

	try {
		let running = false;
		try {
			running = docker(["inspect", "-f", "{{.State.Running}}", REDIS_CONTAINER]) === "true";
		} catch {
			// No such container yet.
		}
		if (!running) {
			try {
				docker(["start", REDIS_CONTAINER]); // restart a stopped one, keeping its data
			} catch {
				docker(
					["run", "-d", "--name", REDIS_CONTAINER, "--restart", "unless-stopped", "-p", `${REDIS_PORT}:6379`, REDIS_IMAGE],
					{ timeout: 300_000 }, // first run pulls the image
				);
			}
		}
	} catch (err) {
		note(`could not start the bundled Redis (${String(err.message || err).split("\n")[0]}) - semantic caching is off for this run.`);
		return;
	}

	for (let i = 0; i < 60; i++) {
		try {
			if (docker(["exec", REDIS_CONTAINER, "redis-cli", "ping"]) === "PONG") {
				env.DEEPINTSHIELD_REDIS_ADDR = `localhost:${REDIS_PORT}`;
				if (!env.DEEPINTSHIELD_REDIS_DB) env.DEEPINTSHIELD_REDIS_DB = "0";
				note(`semantic cache vector store ready (container '${REDIS_CONTAINER}' on :${REDIS_PORT}).`);
				return;
			}
		} catch {
			// Not accepting connections yet.
		}
		sleepSync(1000);
	}
	note("Redis did not come up in time - semantic caching is off for this run.");
}

async function main() {
	const tag = resolveTag();
	const { asset } = resolveTarget();
	const args = process.argv.slice(2);

	// Cacheable versions live under a stable per-version cache dir. "latest" can
	// move, so it downloads into a fresh private temp dir each run (never a
	// shared, predictable path).
	const cacheable = tag !== "latest";
	const binDir = cacheable
		? join(cacheRoot(), "deepintshield", tag, "bin")
		: mkdtempSync(join(tmpdir(), "deepintshield-"));
	const binPath = join(binDir, asset);

	if (!cacheable || !existsSync(binPath)) {
		mkdirSync(binDir, { recursive: true });
		// Stage to a temp file, verify + mark executable, then atomically move
		// into place - so binPath only ever appears fully ready. This avoids a
		// concurrent run exec-ing a half-written, unverified, or non-executable
		// file (the rename-before-chmod race).
		const staged = `${binPath}.${process.pid}.download`;
		await download(assetUrl(tag, asset), staged);
		await verifyChecksum(tag, asset, staged);
		chmodSync(staged, 0o755);
		renameSync(staged, binPath);
	}

	// Start the bundled vector store before launching the gateway, unless this is
	// just a help/version query that won't run the server.
	const childEnv = { ...process.env };
	const infoOnly = args.some((a) => ["-h", "--help", "-v", "--version", "version", "help"].includes(a));
	if (!infoOnly) ensureRedis(childEnv);

	try {
		execFileSync(binPath, args, { stdio: "inherit", env: childEnv });
	} catch (err) {
		if (err.status != null) process.exit(err.status);
		if (err.signal) process.exit(1);
		// A corrupt / half-initialized cached binary - drop it so the next run refetches.
		if (cacheable && (err.code === "ENOENT" || err.code === "ETXTBSY" || err.code === "EACCES")) {
			rmSync(binPath, { force: true });
		}
		fail(`failed to start gateway: ${err.message}`, err.status || 1);
	}
}

main().catch((err) => fail(err?.message || String(err)));
