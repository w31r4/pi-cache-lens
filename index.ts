import { createRequire } from "node:module";
import * as os from "node:os";
import * as path from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { classifyTurn } from "./src/classify.ts";
import { expandTildePath, loadConfig } from "./src/config.ts";
import {
	extractWireFingerprint,
	isStrictItemRepresentationTransition,
	isStrictToolsRepresentationTransition,
	resolveEffectiveTtlSec,
} from "./src/fingerprint.ts";
import { persistRecord, readRecentJsonl } from "./src/ledger.ts";
import { formatStatusChip } from "./src/status.ts";
import type { TurnCacheRecord, WireFingerprint } from "./src/types.ts";

const MAX_SESSION_RECORDS = 32;
const MAX_PENDING_WRITES = 64;
const MAX_TURN_CAPTURES = 8;
const PERSIST_WARN_INTERVAL_MS = 60_000;

let hostGetAgentDir: (() => string) | null | undefined;

function resolveAgentDir(): string {
	if (hostGetAgentDir === undefined) {
		try {
			const req = createRequire(import.meta.url);
			const mod = req("@earendil-works/pi-coding-agent") as { getAgentDir?: () => string };
			hostGetAgentDir = typeof mod?.getAgentDir === "function" ? mod.getAgentDir : null;
		} catch {
			hostGetAgentDir = null;
		}
	}
	if (hostGetAgentDir) {
		try {
			const resolved = hostGetAgentDir();
			if (resolved) return resolved;
		} catch {
			// fall through to env/default resolution
		}
	}
	const envDir = process.env.PI_CODING_AGENT_DIR;
	if (envDir) return expandTildePath(envDir);
	return path.join(os.homedir(), ".pi", "agent");
}

interface PendingCapture {
	wire: WireFingerprint | null;
	requestId: string | null;
	capturedAtMs: number;
	capturedWhileStreaming: boolean;
	capturedAfterOkResponse: boolean;
}

function parseEntryTimestampMs(rawTs: unknown): number | null {
	if (typeof rawTs === "number" && Number.isFinite(rawTs) && rawTs > 0) return rawTs;
	if (typeof rawTs === "string" && rawTs.length > 0) {
		const parsed = Date.parse(rawTs);
		if (Number.isFinite(parsed) && parsed > 0) return parsed;
	}
	return null;
}

function areWiresIdentical(a: WireFingerprint, b: WireFingerprint): boolean {
	return a.fullRequestHash === b.fullRequestHash;
}

function isStrictFallbackRetryPair(a: WireFingerprint, b: WireFingerprint): boolean {
	if (
		a.modelInPayload !== b.modelInPayload ||
		a.nonToolEnvelopeHash !== b.nonToolEnvelopeHash ||
		a.systemHash !== b.systemHash ||
		a.itemHashes.length !== b.itemHashes.length
	) {
		return false;
	}
	const wireToolsDiffer = a.toolsHash !== b.toolsHash;
	if (wireToolsDiffer && !isStrictToolsRepresentationTransition(a.tools, b.tools, true)) {
		return false;
	}
	let wireItemsDiffer = false;
	for (let i = 0; i < a.itemHashes.length; i++) {
		if (a.itemHashes[i] !== b.itemHashes[i]) {
			wireItemsDiffer = true;
			if (!isStrictItemRepresentationTransition(a, b, i, true)) {
				return false;
			}
		}
	}
	return wireToolsDiffer || wireItemsDiffer;
}

export default function cacheLensExtension(pi: ExtensionAPI): void {
	let config = loadConfig(resolveAgentDir());

	let turnCaptures: PendingCapture[] = [];
	let turnFirstCaptureWire: WireFingerprint | null = null;
	let turnCaptureOverflowed = false;
	let turnCaptureOverflowAmbiguous = false;
	let foregroundStreamStarted = false;
	let okProviderResponsesInTurn = 0;
	let inCompaction = false;
	let turnStartedAtMs: number | null = null;
	let messageStartedAtMs: number | null = null;
	let responseHeaderAtMs: number | null = null;

	let prevWire: WireFingerprint | null = null;
	let prevWireModelKey: string | null = null;
	let prevStrictToolsFallback = false;
	let lastCacheTouchAtMs: number | null = null;
	let lastCacheTouchTtlSec: number | null = null;
	let lastCacheTouchScopeKey: string | null = null;
	let lastCacheTouchFromWarm = false;
	let touchInvalidatedAtMs: number | null = null;
	let prevModelKey: string | null = null;
	let prevSingleHitPct: number | null = null;

	let calls = 0;
	let sessionPromptTotal = 0;
	let sessionCacheRead = 0;
	let lastSinglePct: number | null = null;
	let lastShortTag = "";
	let lastAnomaly = false;

	const sessionRecords: TurnCacheRecord[] = [];
	let writeChain: Promise<void> = Promise.resolve();
	let pendingWrites = 0;
	let droppedWrites = 0;
	let persistFailures = 0;
	let lastPersistWarnAtMs = 0;

	function renderStatus(ctx: ExtensionContext): void {
		if (!ctx.hasUI) return;
		ctx.ui.setStatus(
			config.statusKey,
			formatStatusChip(
				{
					calls,
					lastSinglePct,
					sessionPromptTotal,
					sessionCacheRead,
					lastShortTag,
					lastAnomaly,
					icon: config.icon,
					locale: config.locale,
					healthyColor: config.healthyColor,
				},
				ctx.ui.theme,
			),
		);
	}

	function notifyPersistWarning(ctx: ExtensionContext, reason: string): void {
		if (!ctx.hasUI) return;
		const now = Date.now();
		if (now - lastPersistWarnAtMs < PERSIST_WARN_INTERVAL_MS) return;
		lastPersistWarnAtMs = now;
		const msg =
			config.locale === "zh"
				? `pi-cache-lens 后台落盘告警: ${reason} (失败 ${persistFailures} 次, 丢弃 ${droppedWrites} 次)`
				: `pi-cache-lens persistence warning: ${reason} (failures=${persistFailures}, dropped=${droppedWrites})`;
		try {
			ctx.ui.notify(msg, "warning");
		} catch {
			// ignore UI mock differences
		}
	}

	function invalidateCacheTouch(nowMs: number): void {
		lastCacheTouchAtMs = null;
		lastCacheTouchTtlSec = null;
		lastCacheTouchScopeKey = null;
		lastCacheTouchFromWarm = false;
		touchInvalidatedAtMs = nowMs;
	}

	function refreshTouchFromWarmEntries(
		ctx: ExtensionContext,
		targetModelKey: string,
		targetScopeKey: string,
		maxTimestampMs: number | null,
	): void {
		try {
			const entries = ctx.sessionManager.getEntries() as any[];
			for (const entry of entries) {
				if (entry?.type !== "usage" || entry?.kind !== "cache_warm" || !entry.usage) continue;
				const u = entry.usage;
				const total = Number(u.input || 0) + Number(u.cacheRead || 0) + Number(u.cacheWrite || 0);
				if (total <= 0) continue;
				const entryApi = typeof entry.api === "string" && entry.api.length > 0 ? entry.api : null;
				if (entryApi !== null && entry.provider && entry.model) {
					if (`${entry.provider}/${entryApi}/${entry.model}` !== targetScopeKey) continue;
				} else {
					const entryKey = entry.provider && entry.model ? `${entry.provider}/${entry.model}` : null;
					if (entryKey && entryKey !== targetModelKey) continue;
					if (lastCacheTouchScopeKey !== targetScopeKey) continue;
				}
				const tsMs = parseEntryTimestampMs(entry.timestamp);
				if (tsMs === null) continue;
				if (touchInvalidatedAtMs !== null && tsMs <= touchInvalidatedAtMs) continue;
				if (maxTimestampMs !== null && tsMs > maxTimestampMs) continue;
				if (
					lastCacheTouchScopeKey !== targetScopeKey ||
					lastCacheTouchAtMs === null ||
					tsMs > lastCacheTouchAtMs
				) {
					if (lastCacheTouchScopeKey !== targetScopeKey) {
						lastCacheTouchTtlSec = null;
					}
					lastCacheTouchAtMs = tsMs;
					lastCacheTouchScopeKey = targetScopeKey;
					lastCacheTouchFromWarm = true;
				}
			}
		} catch {
			// sessionManager may be stubbed
		}
	}

	function syncFromSessionEntries(ctx: ExtensionContext): void {
		config = loadConfig(resolveAgentDir());
		calls = 0;
		sessionPromptTotal = 0;
		sessionCacheRead = 0;
		lastSinglePct = null;
		lastShortTag = "";
		lastAnomaly = false;
		prevWire = null;
		prevWireModelKey = null;
		prevStrictToolsFallback = false;
		prevModelKey = null;
		prevSingleHitPct = null;
		lastCacheTouchAtMs = null;
		lastCacheTouchTtlSec = null;
		lastCacheTouchScopeKey = null;
		lastCacheTouchFromWarm = false;
		touchInvalidatedAtMs = null;

		try {
			const entries = ctx.sessionManager.getEntries() as any[];
			for (const entry of entries) {
				if (!entry || typeof entry !== "object") continue;
				if (entry.type === "compaction" || entry.type === "branch_summary") {
					prevModelKey = null;
					prevSingleHitPct = null;
					lastCacheTouchAtMs = null;
					lastCacheTouchTtlSec = null;
					lastCacheTouchScopeKey = null;
					lastCacheTouchFromWarm = false;
					continue;
				}
				if (entry.type === "usage" && entry.kind === "cache_warm" && entry.usage) {
					const u = entry.usage;
					const total = Number(u.input || 0) + Number(u.cacheRead || 0) + Number(u.cacheWrite || 0);
					if (total > 0) {
						const entryApi =
							typeof entry.api === "string" && entry.api
								? entry.api
								: ctx.model?.provider === entry.provider && ctx.model?.api
									? String(ctx.model.api)
									: "unknown";
						if (entry.provider && entry.model) {
							prevModelKey = `${entry.provider}/${entry.model}`;
						}
						const tsMs = parseEntryTimestampMs(entry.timestamp);
						if (tsMs !== null) {
							lastCacheTouchAtMs = tsMs;
							lastCacheTouchTtlSec = null;
							lastCacheTouchScopeKey =
								entry.provider && entry.model
									? `${entry.provider}/${entryApi}/${entry.model}`
									: null;
							lastCacheTouchFromWarm = true;
						}
					}
					continue;
				}
				if (entry.type !== "message") continue;
				const msg = entry.message as any;
				if (msg?.role !== "assistant" || !msg.usage) continue;
				const u = msg.usage;
				const total = Number(u.input || 0) + Number(u.cacheRead || 0) + Number(u.cacheWrite || 0);
				const out = Number(u.output || 0);
				if (total <= 0 && out <= 0) continue;
				if (total <= 0) continue;

				calls += 1;
				sessionPromptTotal += total;
				sessionCacheRead += Number(u.cacheRead || 0);
				lastSinglePct = (Number(u.cacheRead || 0) * 100) / total;
				prevSingleHitPct = lastSinglePct;
				const effectiveModel = msg.responseModel || msg.model;
				const entryApi =
					typeof msg.api === "string" && msg.api
						? msg.api
						: ctx.model?.provider === msg.provider && ctx.model?.api
							? String(ctx.model.api)
							: "unknown";
				if (msg.provider && effectiveModel) {
					prevModelKey = `${msg.provider}/${effectiveModel}`;
				}
				const tsMs = parseEntryTimestampMs(msg.timestamp) ?? parseEntryTimestampMs(entry.timestamp);
				if (tsMs !== null) {
					lastCacheTouchAtMs = tsMs;
					lastCacheTouchTtlSec = null;
					lastCacheTouchScopeKey =
						msg.provider && effectiveModel
							? `${msg.provider}/${entryApi}/${effectiveModel}`
							: null;
					lastCacheTouchFromWarm = false;
				}
			}
		} catch {
			// non-standard session manager mocks
		}

		renderStatus(ctx);
	}

	function clearInFlightTurnState(): void {
		turnCaptures = [];
		turnFirstCaptureWire = null;
		turnCaptureOverflowed = false;
		turnCaptureOverflowAmbiguous = false;
		foregroundStreamStarted = false;
		okProviderResponsesInTurn = 0;
		turnStartedAtMs = null;
		messageStartedAtMs = null;
		responseHeaderAtMs = null;
	}

	function consumePairedWire(
		msg: any,
		requestedModel: string,
		effectiveModel: string,
		strictToolsFallback: boolean,
	): {
		wire: WireFingerprint | null;
		pairingAmbiguous: boolean;
		hadProviderActivity: boolean;
		dispatchAtMs: number | null;
		touchAtMs: number | null;
		warmCutoffMs: number | null;
	} {
		const turnStartSnapshot = turnStartedAtMs;
		const fallbackDispatch = turnStartedAtMs ?? messageStartedAtMs;
		const headerAtMs = responseHeaderAtMs;
		const okResponses = okProviderResponsesInTurn;
		const overflowed = turnCaptureOverflowed;
		const overflowAmbiguous = turnCaptureOverflowAmbiguous;
		const firstEverWire = turnFirstCaptureWire;
		const captures = turnCaptures.splice(0, turnCaptures.length);
		const hadProviderActivity =
			captures.length > 0 || okResponses > 0 || overflowed || headerAtMs !== null;
		clearInFlightTurnState();

		if (captures.length === 0) {
			if (okResponses > 1) {
				return {
					wire: null,
					pairingAmbiguous: true,
					hadProviderActivity,
					dispatchAtMs: null,
					touchAtMs: null,
					warmCutoffMs: turnStartSnapshot,
				};
			}
			const syntheticTouch = headerAtMs ?? fallbackDispatch ?? parseEntryTimestampMs(msg?.timestamp);
			return {
				wire: null,
				pairingAmbiguous: false,
				hadProviderActivity,
				dispatchAtMs: fallbackDispatch,
				touchAtMs: syntheticTouch,
				warmCutoffMs: turnStartSnapshot ?? fallbackDispatch,
			};
		}

		const msgRequestId = typeof msg?.requestId === "string" ? msg.requestId : null;
		if (msgRequestId) {
			const matched = captures.find((c) => c.requestId === msgRequestId);
			if (matched?.wire) {
				return {
					wire: matched.wire,
					pairingAmbiguous: false,
					hadProviderActivity,
					dispatchAtMs: matched.capturedAtMs,
					touchAtMs: okResponses > 1 ? null : (headerAtMs ?? matched.capturedAtMs),
					warmCutoffMs: turnStartSnapshot ?? matched.capturedAtMs,
				};
			}
			if (overflowed) {
				return {
					wire: null,
					pairingAmbiguous: true,
					hadProviderActivity,
					dispatchAtMs: null,
					touchAtMs: null,
					warmCutoffMs: turnStartSnapshot,
				};
			}
		}

		if (overflowAmbiguous || captures.some((c) => c.wire === null)) {
			return {
				wire: null,
				pairingAmbiguous: overflowAmbiguous || overflowed || captures.length > 1 || okResponses > 1,
				hadProviderActivity,
				dispatchAtMs: null,
				touchAtMs: null,
				warmCutoffMs: turnStartSnapshot,
			};
		}

		const modelMatches = (w: WireFingerprint): boolean => {
			if (!w.modelInPayload || w.modelInPayload === "unknown") return true;
			if (requestedModel !== "unknown" && w.modelInPayload === requestedModel) return true;
			if (effectiveModel !== "unknown" && w.modelInPayload === effectiveModel) return true;
			return requestedModel === "unknown" && effectiveModel === "unknown";
		};

		if (okResponses > 1 || captures.some((c) => c.capturedWhileStreaming || c.capturedAfterOkResponse)) {
			return {
				wire: null,
				pairingAmbiguous: true,
				hadProviderActivity,
				dispatchAtMs: null,
				touchAtMs: null,
				warmCutoffMs: turnStartSnapshot,
			};
		}

		if (captures.length === 1 && !overflowed) {
			const only = captures[0]!;
			const wire = only.wire!;
			if (!modelMatches(wire)) {
				return {
					wire: null,
					pairingAmbiguous: true,
					hadProviderActivity,
					dispatchAtMs: null,
					touchAtMs: null,
					warmCutoffMs: turnStartSnapshot,
				};
			}
			return {
				wire,
				pairingAmbiguous: false,
				hadProviderActivity,
				dispatchAtMs: only.capturedAtMs,
				touchAtMs: headerAtMs ?? only.capturedAtMs,
				warmCutoffMs: turnStartSnapshot ?? only.capturedAtMs,
			};
		}

		const anchorWire = firstEverWire ?? captures[0]!.wire!;
		const allIdentical = captures.every((c) => areWiresIdentical(anchorWire, c.wire!));
		if (allIdentical && modelMatches(anchorWire)) {
			const last = captures[captures.length - 1]!;
			return {
				wire: last.wire,
				pairingAmbiguous: false,
				hadProviderActivity,
				dispatchAtMs: last.capturedAtMs,
				touchAtMs: headerAtMs ?? last.capturedAtMs,
				warmCutoffMs: turnStartSnapshot ?? captures[0]!.capturedAtMs,
			};
		}

		if (
			!overflowed &&
			strictToolsFallback &&
			captures.length === 2 &&
			isStrictFallbackRetryPair(captures[0]!.wire!, captures[1]!.wire!) &&
			modelMatches(captures[1]!.wire!)
		) {
			const retryCap = captures[1]!;
			return {
				wire: retryCap.wire,
				pairingAmbiguous: false,
				hadProviderActivity,
				dispatchAtMs: retryCap.capturedAtMs,
				touchAtMs: headerAtMs ?? retryCap.capturedAtMs,
				warmCutoffMs: turnStartSnapshot ?? captures[0]!.capturedAtMs,
			};
		}

		return {
			wire: null,
			pairingAmbiguous: true,
			hadProviderActivity,
			dispatchAtMs: null,
			touchAtMs: null,
			warmCutoffMs: turnStartSnapshot,
		};
	}

	pi.on("session_start", (_event, ctx) => {
		clearInFlightTurnState();
		inCompaction = false;
		sessionRecords.length = 0;
		syncFromSessionEntries(ctx);
	});

	pi.on("session_tree", (_event, ctx) => {
		clearInFlightTurnState();
		syncFromSessionEntries(ctx);
	});

	pi.on("session_before_compact", () => {
		inCompaction = true;
	});

	pi.on("session_compact", (_event, ctx) => {
		inCompaction = false;
		clearInFlightTurnState();
		syncFromSessionEntries(ctx);
	});

	pi.on("session_compact_failed", () => {
		inCompaction = false;
	});

	pi.on("turn_start", () => {
		clearInFlightTurnState();
		turnStartedAtMs = Date.now();
	});

	pi.on("after_provider_response", (event) => {
		if (!inCompaction && event.status >= 200 && event.status < 300) {
			okProviderResponsesInTurn += 1;
			if (okProviderResponsesInTurn === 1) {
				responseHeaderAtMs = Date.now();
			} else {
				responseHeaderAtMs = null;
			}
		}
	});

	pi.on("turn_end", () => {
		if (
			turnCaptures.length > 0 ||
			okProviderResponsesInTurn > 0 ||
			turnCaptureOverflowed ||
			responseHeaderAtMs !== null
		) {
			invalidateCacheTouch(Date.now());
		}
		clearInFlightTurnState();
	});

	pi.on("agent_end", () => {
		if (
			turnCaptures.length > 0 ||
			okProviderResponsesInTurn > 0 ||
			turnCaptureOverflowed ||
			responseHeaderAtMs !== null
		) {
			invalidateCacheTouch(Date.now());
		}
		clearInFlightTurnState();
	});

	pi.on("message_start", (event) => {
		const msg = event.message as any;
		if (msg?.role === "assistant") {
			foregroundStreamStarted = true;
			if (messageStartedAtMs === null) {
				messageStartedAtMs = Date.now();
			}
		}
	});

	pi.on("before_provider_request", (event) => {
		const evAny = event as any;
		if (inCompaction || evAny?.purpose === "cache_warm" || evAny?.purpose === "compaction") {
			return undefined;
		}
		const nowMs = Date.now();
		let wire: WireFingerprint | null = null;
		try {
			wire = extractWireFingerprint(event.payload, nowMs);
		} catch {
			wire = null;
		}

		const capturedAfterOkResponse = okProviderResponsesInTurn > 0;
		if (turnCaptures.length === 0 && !turnCaptureOverflowed) {
			turnFirstCaptureWire = wire;
			if (wire === null || foregroundStreamStarted || capturedAfterOkResponse) {
				turnCaptureOverflowAmbiguous = true;
			}
		}

		if (turnCaptures.length >= MAX_TURN_CAPTURES) {
			turnCaptureOverflowed = true;
			const evicted = turnCaptures.shift()!;
			if (
				!evicted.wire ||
				!turnFirstCaptureWire ||
				evicted.capturedWhileStreaming ||
				evicted.capturedAfterOkResponse ||
				!areWiresIdentical(turnFirstCaptureWire, evicted.wire)
			) {
				turnCaptureOverflowAmbiguous = true;
			}
			if (
				!wire ||
				!turnFirstCaptureWire ||
				foregroundStreamStarted ||
				capturedAfterOkResponse ||
				!areWiresIdentical(turnFirstCaptureWire, wire)
			) {
				turnCaptureOverflowAmbiguous = true;
			}
		}

		turnCaptures.push({
			wire,
			requestId: typeof evAny?.requestId === "string" ? evAny.requestId : null,
			capturedAtMs: nowMs,
			capturedWhileStreaming: foregroundStreamStarted,
			capturedAfterOkResponse,
		});
		return undefined;
	});

	pi.on("message_end", (event, ctx) => {
		const msg = event.message as any;
		if (!msg || msg.role !== "assistant") return;

		const provider = String(msg.provider || ctx.model?.provider || "unknown");
		const requestedModel = String(msg.model || ctx.model?.id || "unknown");
		const effectiveModel = String(msg.responseModel || requestedModel);
		const api = String(msg.api || ctx.model?.api || "unknown");
		const hasStrictFallbackDiag =
			Array.isArray(msg.diagnostics) &&
			msg.diagnostics.some((d: any) => d?.type === "anthropic_strict_tools_fallback");

		const paired = consumePairedWire(msg, requestedModel, effectiveModel, hasStrictFallbackDiag);
		const nowMs = Date.now();
		const u = msg.usage;
		const input = Number(u?.input || 0);
		const cacheRead = Number(u?.cacheRead || 0);
		const cacheWrite = Number(u?.cacheWrite || 0);
		const output = Number(u?.output || 0);
		const costUsd = Number(u?.cost?.total || 0);
		const promptTotal = input + cacheRead + cacheWrite;

		if (
			(!u || promptTotal <= 0) &&
			(paired.pairingAmbiguous || paired.touchAtMs === null || paired.hadProviderActivity)
		) {
			invalidateCacheTouch(nowMs);
		}

		if (!u) return;

		if (promptTotal <= 0 && output <= 0 && costUsd <= 0) {
			return;
		}

		const currWire = paired.wire;
		const resolvedRequestedModel =
			requestedModel !== "unknown" ? requestedModel : (currWire?.modelInPayload ?? "unknown");
		const resolvedEffectiveModel =
			msg.responseModel ? String(msg.responseModel) : resolvedRequestedModel;
		const modelKey = `${provider}/${resolvedEffectiveModel}`;
		const wireScopeKey = `${provider}/${api}/${resolvedEffectiveModel}`;

		const thinkingLevel =
			typeof msg.thinkingLevel === "string" && msg.thinkingLevel
				? msg.thinkingLevel
				: typeof (pi as any).getThinkingLevel === "function"
					? String((pi as any).getThinkingLevel() || "off")
					: String((ctx as any).thinkingLevel || "off");
		const providerThinkingLevel =
			typeof msg.providerThinkingLevel === "string" && msg.providerThinkingLevel
				? msg.providerThinkingLevel
				: null;

		let sessionId = "ephemeral";
		try {
			sessionId = ctx.sessionManager.getSessionId() || "ephemeral";
		} catch {
			// ignore
		}

		const comparablePrevWire = prevWire !== null && prevWireModelKey === wireScopeKey ? prevWire : null;
		const effectiveStrictFallback =
			comparablePrevWire !== null ? hasStrictFallbackDiag || prevStrictToolsFallback : hasStrictFallbackDiag;

		if (promptTotal <= 0) {
			const verdict = classifyTurn({
				callIndex: calls,
				modelKey,
				prevModelKey,
				promptTotal: 0,
				cacheRead: 0,
				prevSingleHitPct,
				idleSec: null,
				prevWire: comparablePrevWire,
				currWire: null,
				priorTouchTtlSec: null,
				effectiveTtlSec: null,
				strictToolsFallback: effectiveStrictFallback,
				pairingAmbiguous: paired.pairingAmbiguous,
				ttlThresholdSec: config.ttlThresholdSec,
				minCacheableTokens: config.minCacheableTokens,
				locale: config.locale,
			});
			const sessionHitPct = sessionPromptTotal > 0 ? (sessionCacheRead * 100) / sessionPromptTotal : 0;
			const record: TurnCacheRecord = {
				ts: new Date(nowMs).toISOString(),
				sessionId,
				cwd: ctx.cwd || process.cwd(),
				provider,
				requestedModel: resolvedRequestedModel,
				model: resolvedEffectiveModel,
				api,
				thinkingLevel,
				providerThinkingLevel,
				callIndex: calls,
				idleSec: null,
				input,
				cacheRead,
				cacheWrite,
				output,
				promptTotal: 0,
				singleHitPct: null,
				sessionHitPct: Number(sessionHitPct.toFixed(2)),
				sessionPromptTotal,
				sessionCacheRead,
				costUsd,
				systemHash: null,
				systemBytes: null,
				toolsHash: null,
				toolsBytes: null,
				itemCount: null,
				firstDivergedItemIdx: null,
				promptCacheKey: null,
				hasCacheControl: null,
				observedChanges: [],
				diagnosis: verdict.diagnosis,
				anomaly: false,
				shortTag: "",
				detail: verdict.detail,
			};
			if (sessionRecords.length >= MAX_SESSION_RECORDS) sessionRecords.shift();
			sessionRecords.push(record);
			enqueuePersist(record, ctx);
			return;
		}

		if (paired.warmCutoffMs !== null) {
			refreshTouchFromWarmEntries(ctx, modelKey, wireScopeKey, paired.warmCutoffMs);
		}

		calls += 1;
		sessionPromptTotal += promptTotal;
		sessionCacheRead += cacheRead;

		const singleHitPct = (cacheRead * 100) / promptTotal;
		const sessionHitPct = (sessionCacheRead * 100) / sessionPromptTotal;
		const dispatchAtMs = paired.dispatchAtMs;
		const sameTouchScope =
			lastCacheTouchScopeKey !== null && lastCacheTouchScopeKey === wireScopeKey;
		const idleSec =
			sameTouchScope && lastCacheTouchAtMs !== null && dispatchAtMs !== null
				? Math.max(0, Math.round((dispatchAtMs - lastCacheTouchAtMs) / 1000))
				: null;
		const effectiveTtlSec = resolveEffectiveTtlSec(currWire, config.ttlThresholdSec);
		const wireRetentionChanged =
			comparablePrevWire !== null &&
			currWire !== null &&
			(comparablePrevWire.retentionState !== currWire.retentionState ||
				comparablePrevWire.retentionTtlSec !== currWire.retentionTtlSec);
		const priorTouchTtlSec = !sameTouchScope
			? null
			: lastCacheTouchFromWarm && (comparablePrevWire === null || wireRetentionChanged)
				? null
				: lastCacheTouchTtlSec;

		const verdict = classifyTurn({
			callIndex: calls,
			modelKey,
			prevModelKey,
			promptTotal,
			cacheRead,
			prevSingleHitPct,
			idleSec,
			prevWire: comparablePrevWire,
			currWire,
			priorTouchTtlSec,
			effectiveTtlSec,
			strictToolsFallback: effectiveStrictFallback,
			pairingAmbiguous: paired.pairingAmbiguous,
			ttlThresholdSec: config.ttlThresholdSec,
			minCacheableTokens: config.minCacheableTokens,
			locale: config.locale,
		});

		lastSinglePct = singleHitPct;
		lastShortTag = verdict.shortTag;
		lastAnomaly = verdict.anomaly;
		if (currWire !== null && !paired.pairingAmbiguous) {
			prevWire = currWire;
			prevWireModelKey = wireScopeKey;
			prevStrictToolsFallback = hasStrictFallbackDiag;
		} else if (prevWireModelKey !== null && prevWireModelKey !== wireScopeKey) {
			prevWire = null;
			prevWireModelKey = null;
			prevStrictToolsFallback = false;
		}

		if (paired.pairingAmbiguous || paired.touchAtMs === null) {
			invalidateCacheTouch(nowMs);
		} else {
			const turnTouchMs = paired.touchAtMs;
			if (
				lastCacheTouchScopeKey !== wireScopeKey ||
				lastCacheTouchAtMs === null ||
				turnTouchMs >= lastCacheTouchAtMs
			) {
				lastCacheTouchAtMs = turnTouchMs;
				lastCacheTouchTtlSec = effectiveTtlSec;
				lastCacheTouchScopeKey = wireScopeKey;
				lastCacheTouchFromWarm = false;
			}
			refreshTouchFromWarmEntries(ctx, modelKey, wireScopeKey, null);
		}
		prevModelKey = modelKey;
		prevSingleHitPct = singleHitPct;

		renderStatus(ctx);

		const record: TurnCacheRecord = {
			ts: new Date(nowMs).toISOString(),
			sessionId,
			cwd: ctx.cwd || process.cwd(),
			provider,
			requestedModel: resolvedRequestedModel,
			model: resolvedEffectiveModel,
			api,
			thinkingLevel,
			providerThinkingLevel,
			callIndex: calls,
			idleSec,
			input,
			cacheRead,
			cacheWrite,
			output,
			promptTotal,
			singleHitPct: Number(singleHitPct.toFixed(2)),
			sessionHitPct: Number(sessionHitPct.toFixed(2)),
			sessionPromptTotal,
			sessionCacheRead,
			costUsd,
			systemHash: currWire?.systemHash ?? null,
			systemBytes: currWire?.systemBytes ?? null,
			toolsHash: currWire?.toolsHash ?? null,
			toolsBytes: currWire?.toolsBytes ?? null,
			itemCount: currWire?.itemHashes.length ?? null,
			firstDivergedItemIdx: verdict.firstDivergedItemIdx,
			promptCacheKey: currWire?.promptCacheKey ?? null,
			hasCacheControl: currWire?.hasCacheControl ?? null,
			observedChanges: verdict.observedChanges,
			diagnosis: verdict.diagnosis,
			anomaly: verdict.anomaly,
			shortTag: verdict.shortTag,
			detail: verdict.detail,
		};

		if (sessionRecords.length >= MAX_SESSION_RECORDS) {
			sessionRecords.shift();
		}
		sessionRecords.push(record);
		enqueuePersist(record, ctx);
	});

	function enqueuePersist(record: TurnCacheRecord, ctx: ExtensionContext): void {
		if (pendingWrites >= MAX_PENDING_WRITES) {
			droppedWrites += 1;
			notifyPersistWarning(ctx, config.locale === "zh" ? "写入队列已满" : "write queue full");
			return;
		}
		const { telemetryDir, maxLogBytes, locale } = config;
		pendingWrites += 1;
		writeChain = writeChain
			.then(() => persistRecord(record, telemetryDir, maxLogBytes, locale))
			.catch((err: unknown) => {
				persistFailures += 1;
				const reason = err instanceof Error ? err.message : String(err);
				notifyPersistWarning(ctx, reason);
			})
			.finally(() => {
				pendingWrites = Math.max(0, pendingWrites - 1);
			});
	}

	pi.on("session_shutdown", async () => {
		await writeChain;
	});

	pi.registerCommand("cache", {
		description:
			config.locale === "zh"
				? "查看单次/会话缓存命中率与掉缓存根因诊断 (/cache [anomalies|path])"
				: "Inspect single/session KV cache hit rate and cache-drop forensics (/cache [anomalies|path])",
		handler: async (rawArgs, ctx) => {
			const arg = rawArgs.trim().toLowerCase();
			const dir = config.telemetryDir;
			const zh = config.locale === "zh";

			if (arg === "path") {
				ctx.ui.notify(
					zh
						? `缓存诊断目录: ${dir}\n- 全量流水: ${path.join(dir, "events.jsonl")}\n- 异常专表: ${path.join(dir, "anomalies.jsonl")}\n- 汇总报告: ${path.join(dir, "latest-report.md")}`
						: `Cache diagnostics directory: ${dir}\n- Full log: ${path.join(dir, "events.jsonl")}\n- Anomalies: ${path.join(dir, "anomalies.jsonl")}\n- Summary report: ${path.join(dir, "latest-report.md")}`,
					"info",
				);
				return;
			}

			if (arg === "anomalies") {
				const anomalies = await readRecentJsonl(path.join(dir, "anomalies.jsonl"), 10);
				if (anomalies.length === 0) {
					ctx.ui.notify(
						zh ? `暂无异常掉缓存记录（目录: ${dir}）` : `No cache-drop anomalies recorded (${dir})`,
						"info",
					);
					return;
				}
				const lines = anomalies
					.reverse()
					.map((a) => {
						const singleStr = a.singleHitPct !== null ? `${a.singleHitPct}%` : "n/a";
						return zh
							? `[${a.ts.slice(11, 19)}] #${a.callIndex} ${a.model} 单次 ${singleStr} / 会话 ${a.sessionHitPct}% [${a.diagnosis}] ${a.detail}`
							: `[${a.ts.slice(11, 19)}] #${a.callIndex} ${a.model} last ${singleStr} / sess ${a.sessionHitPct}% [${a.diagnosis}] ${a.detail}`;
					});
				ctx.ui.notify(`${zh ? "最近掉缓存异常" : "Recent cache-drop anomalies"}:\n${lines.join("\n")}`, "info");
				return;
			}

			const sessionPct =
				sessionPromptTotal > 0 ? ((sessionCacheRead * 100) / sessionPromptTotal).toFixed(1) : "--";
			const singleStr = lastSinglePct !== null ? `${lastSinglePct.toFixed(1)}%` : "--";
			const recentLines = sessionRecords
				.slice(-8)
				.map((r) => {
					const rSingle = r.singleHitPct !== null ? `${r.singleHitPct.toFixed(1)}%` : "n/a";
					return zh
						? `  #${r.callIndex} ${r.model}: 单次 ${rSingle} (${r.cacheRead}/${r.promptTotal}) | 会话 ${r.sessionHitPct.toFixed(1)}% | sys=${r.systemHash?.slice(0, 6) ?? "-"} tools=${r.toolsHash?.slice(0, 6) ?? "-"} | [${r.diagnosis}] ${r.detail}`
						: `  #${r.callIndex} ${r.model}: last ${rSingle} (${r.cacheRead}/${r.promptTotal}) | sess ${r.sessionHitPct.toFixed(1)}% | sys=${r.systemHash?.slice(0, 6) ?? "-"} tools=${r.toolsHash?.slice(0, 6) ?? "-"} | [${r.diagnosis}] ${r.detail}`;
				});
			const healthSuffix =
				persistFailures > 0 || droppedWrites > 0
					? zh
						? ` | 落盘异常: 失败 ${persistFailures} / 丢弃 ${droppedWrites}`
						: ` | persistence errors=${persistFailures} dropped=${droppedWrites}`
					: "";
			const body = [
				zh
					? `当前会话缓存统计: 调用 ${calls} 次 | 最近单次 ${singleStr} | 会话累计 ${sessionPct}% (${sessionCacheRead.toLocaleString()} / ${sessionPromptTotal.toLocaleString()} tok)${healthSuffix}`
					: `Session cache stats: ${calls} calls | last ${singleStr} | session ${sessionPct}% (${sessionCacheRead.toLocaleString()} / ${sessionPromptTotal.toLocaleString()} tok)${healthSuffix}`,
				`${zh ? "后台诊断账本" : "Diagnostics report"}: ${path.join(dir, "latest-report.md")}`,
				...(recentLines.length > 0 ? [zh ? "最近调用明细:" : "Recent calls:", ...recentLines] : []),
			].join("\n");
			ctx.ui.notify(body, "info");
		},
	});
}
