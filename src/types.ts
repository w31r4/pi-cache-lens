export type Locale = "zh" | "en";

export type HealthyThemeColor = "accent" | "muted" | "text" | "success";

export interface CacheLensConfig {
	locale: Locale;
	statusKey: string;
	icon: string;
	healthyColor: HealthyThemeColor;
	ttlThresholdSec: number;
	minCacheableTokens: number;
	maxLogBytes: number;
	telemetryDir: string;
}

export interface ToolDigest {
	name: string;
	hash: string;
	logicalHash: string;
	isStrict: boolean;
	bytes: number;
}

export interface InlineToolItemMeta {
	envelopeHash: string;
	tools: ToolDigest[];
}

export type CacheRetentionState =
	| "explicit_ttl"
	| "short_default"
	| "disabled"
	| "unrecognized"
	| "unknown";

export interface WireFingerprint {
	capturedAtMs: number;
	modelInPayload: string;
	/** Canonical SHA-256 prefix over the entire wire payload (for transport-retry equivalence). */
	fullRequestHash: string;
	/** Canonical SHA-256 prefix over non-prefix request parameters (`max_tokens`, retention, sampling, etc.). */
	nonToolEnvelopeHash: string;
	systemHash: string;
	systemBytes: number;
	/** Volatile in-memory copy used only to compute numeric diff offsets; never persisted. */
	systemTextSample: string;
	toolsHash: string;
	logicalToolsHash: string;
	toolsBytes: number;
	tools: ToolDigest[];
	itemHashes: string[];
	inlineToolItems: Array<InlineToolItemMeta | null>;
	effortConfigHash: string;
	retentionState: CacheRetentionState;
	/** Explicit wire cache retention in seconds (e.g. 1800 for 30m, 3600 for 1h, 86400 for 24h), or null when not explicit. */
	retentionTtlSec: number | null;
	promptCacheKey: string | null;
	hasCacheControl: boolean;
}

export type DiagnosisCode =
	| "cold_start"
	| "below_min_tokens"
	| "usage_unavailable"
	| "insufficient_evidence"
	| "healthy_hit"
	| "partial_hit"
	| "model_changed"
	| "provider_strict_fallback"
	| "tools_mutated"
	| "system_mutated"
	| "history_rewritten"
	| "ttl_expired_likely"
	| "provider_miss_or_routing";

export interface DiagnosisVerdict {
	diagnosis: DiagnosisCode;
	anomaly: boolean;
	shortTag: string;
	detail: string;
	firstDivergedItemIdx: number | null;
	observedChanges: string[];
}

export interface TurnCacheRecord {
	ts: string;
	sessionId: string;
	cwd: string;
	provider: string;
	requestedModel: string;
	model: string;
	api: string;
	thinkingLevel: string;
	providerThinkingLevel: string | null;
	callIndex: number;
	idleSec: number | null;
	input: number;
	cacheRead: number;
	cacheWrite: number;
	output: number;
	promptTotal: number;
	singleHitPct: number | null;
	sessionHitPct: number;
	sessionPromptTotal: number;
	sessionCacheRead: number;
	costUsd: number;
	systemHash: string | null;
	systemBytes: number | null;
	toolsHash: string | null;
	toolsBytes: number | null;
	itemCount: number | null;
	firstDivergedItemIdx: number | null;
	promptCacheKey: string | null;
	hasCacheControl: boolean | null;
	observedChanges: string[];
	diagnosis: DiagnosisCode;
	anomaly: boolean;
	shortTag: string;
	detail: string;
}
