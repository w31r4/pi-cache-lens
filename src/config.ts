import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import type { CacheLensConfig, HealthyThemeColor, Locale } from "./types.ts";

const DEFAULT_MAX_LOG_BYTES = 10 * 1024 * 1024;
const MIN_MAX_LOG_BYTES = 64 * 1024;
const MAX_MAX_LOG_BYTES = 512 * 1024 * 1024;

const DEFAULT_TTL_THRESHOLD_SEC = 290;
const MIN_TTL_THRESHOLD_SEC = 1;
const MAX_TTL_THRESHOLD_SEC = 7 * 24 * 3600;

const DEFAULT_MIN_CACHEABLE_TOKENS = 1024;
const MAX_MIN_CACHEABLE_TOKENS = 1_000_000;

const DEFAULT_ICON = "\uF0E7";
const DEFAULT_STATUS_KEY = "cache-stats";

export function expandTildePath(input: string, homeDir = os.homedir()): string {
	if (input === "~") return homeDir;
	if (input.startsWith("~/") || (process.platform === "win32" && input.startsWith("~\\"))) {
		return path.join(homeDir, input.slice(2));
	}
	if (input.startsWith("file://")) {
		try {
			return fileURLToPath(input);
		} catch {
			return input;
		}
	}
	return input;
}

function detectLocale(): Locale {
	try {
		const rpivPath = path.join(os.homedir(), ".config", "rpiv-i18n", "locale.json");
		if (fs.existsSync(rpivPath)) {
			const parsed = JSON.parse(fs.readFileSync(rpivPath, "utf8")) as { locale?: unknown };
			if (typeof parsed.locale === "string") {
				return parsed.locale.toLowerCase().startsWith("zh") ? "zh" : "en";
			}
		}
	} catch {
		// fall through to env check
	}
	const envLang = (process.env.LC_ALL || process.env.LC_MESSAGES || process.env.LANG || "").toLowerCase();
	return envLang.startsWith("zh") ? "zh" : "en";
}

function isHealthyColor(value: unknown): value is HealthyThemeColor {
	return value === "accent" || value === "muted" || value === "text" || value === "success";
}

function parseBoundedInt(value: unknown, min: number, max: number, fallback: number): number {
	if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
	const rounded = Math.round(value);
	if (!Number.isSafeInteger(rounded) || rounded < min || rounded > max) return fallback;
	return rounded;
}

export function loadConfig(agentDir: string): CacheLensConfig {
	const resolvedAgentDir = expandTildePath(agentDir);
	const defaults: CacheLensConfig = {
		locale: detectLocale(),
		statusKey: DEFAULT_STATUS_KEY,
		icon: DEFAULT_ICON,
		healthyColor: "accent",
		ttlThresholdSec: DEFAULT_TTL_THRESHOLD_SEC,
		minCacheableTokens: DEFAULT_MIN_CACHEABLE_TOKENS,
		maxLogBytes: DEFAULT_MAX_LOG_BYTES,
		telemetryDir: path.join(resolvedAgentDir, "cache-lens"),
	};

	const configPath = path.join(resolvedAgentDir, "cache-lens.json");
	try {
		if (!fs.existsSync(configPath)) return defaults;
		const raw = JSON.parse(fs.readFileSync(configPath, "utf8")) as Record<string, unknown>;
		if (!raw || typeof raw !== "object" || Array.isArray(raw)) return defaults;
		return {
			locale: raw.locale === "zh" || raw.locale === "en" ? raw.locale : defaults.locale,
			statusKey: typeof raw.statusKey === "string" && raw.statusKey.trim() ? raw.statusKey.trim() : defaults.statusKey,
			icon: typeof raw.icon === "string" ? raw.icon : defaults.icon,
			healthyColor: isHealthyColor(raw.healthyColor) ? raw.healthyColor : defaults.healthyColor,
			ttlThresholdSec: parseBoundedInt(
				raw.ttlThresholdSec,
				MIN_TTL_THRESHOLD_SEC,
				MAX_TTL_THRESHOLD_SEC,
				defaults.ttlThresholdSec,
			),
			minCacheableTokens: parseBoundedInt(
				raw.minCacheableTokens,
				0,
				MAX_MIN_CACHEABLE_TOKENS,
				defaults.minCacheableTokens,
			),
			maxLogBytes: parseBoundedInt(raw.maxLogBytes, MIN_MAX_LOG_BYTES, MAX_MAX_LOG_BYTES, defaults.maxLogBytes),
			telemetryDir:
				typeof raw.telemetryDir === "string" && raw.telemetryDir.trim()
					? path.resolve(resolvedAgentDir, expandTildePath(raw.telemetryDir.trim()))
					: defaults.telemetryDir,
		};
	} catch {
		return defaults;
	}
}
