import {
	diffTools,
	firstDiffSummary,
	isStrictItemRepresentationTransition,
	isStrictToolsRepresentationTransition,
	resolveEffectiveTtlSec,
	sanitizeIdentifierKeepTail,
} from "./fingerprint.ts";
import type { DiagnosisVerdict, Locale, WireFingerprint } from "./types.ts";

export interface ClassifyTurnParams {
	callIndex: number;
	modelKey: string;
	prevModelKey: string | null;
	promptTotal: number;
	cacheRead: number;
	prevSingleHitPct: number | null;
	idleSec: number | null;
	prevWire: WireFingerprint | null;
	currWire: WireFingerprint | null;
	/** Verified cache TTL in seconds of the previous cache touch being evaluated, or null if uncertain. */
	priorTouchTtlSec?: number | null;
	/** Effective cache TTL in seconds requested on the current turn, or null when unverified/disabled. */
	effectiveTtlSec?: number | null;
	/** True when upstream reported `anthropic_strict_tools_fallback` on this turn or its predecessor. */
	strictToolsFallback?: boolean;
	/** True when multiple unattributed outgoing requests overlapped before completion. */
	pairingAmbiguous?: boolean;
	ttlThresholdSec: number;
	minCacheableTokens: number;
	locale: Locale;
}

export function classifyTurn(params: ClassifyTurnParams): DiagnosisVerdict {
	const {
		callIndex,
		modelKey,
		prevModelKey,
		promptTotal,
		cacheRead,
		prevSingleHitPct,
		idleSec,
		prevWire,
		currWire,
		strictToolsFallback = false,
		pairingAmbiguous = false,
		ttlThresholdSec,
		minCacheableTokens,
		locale,
	} = params;
	const zh = locale === "zh";

	if (promptTotal <= 0) {
		return {
			diagnosis: "usage_unavailable",
			anomaly: false,
			shortTag: "",
			detail: zh
				? "上游未返回可评估的输入 token 统计，跳过缓存命中归因"
				: "Prompt token usage unavailable; excluded from cache-miss attribution",
			firstDivergedItemIdx: null,
			observedChanges: [],
		};
	}

	const hitPct = (cacheRead * 100) / promptTotal;
	const currTtlSec =
		params.effectiveTtlSec !== undefined
			? params.effectiveTtlSec
			: resolveEffectiveTtlSec(currWire, ttlThresholdSec);
	const touchTtlSec =
		params.priorTouchTtlSec !== undefined
			? params.priorTouchTtlSec
			: prevWire !== null
				? resolveEffectiveTtlSec(prevWire, ttlThresholdSec)
				: null;
	const retentionTransitioned =
		touchTtlSec !== currTtlSec ||
		(prevWire !== null &&
			currWire !== null &&
			(prevWire.retentionState !== currWire.retentionState ||
				prevWire.retentionTtlSec !== currWire.retentionTtlSec));

	const comparableWire = !pairingAmbiguous && prevWire !== null && currWire !== null;

	let firstDivergedItemIdx: number | null = null;
	const observedChanges: string[] = [];
	let toolsDelta = "";
	let isStrictFallbackChange = false;
	let sysDiff = "";

	if (comparableWire && prevWire && currWire) {
		const minLen = Math.min(prevWire.itemHashes.length, currWire.itemHashes.length);
		let genuineDivergedIdx: number | null = null;
		let sawInlineStrictTransition = false;
		for (let i = 0; i < minLen; i++) {
			if (prevWire.itemHashes[i] !== currWire.itemHashes[i]) {
				if (strictToolsFallback && isStrictItemRepresentationTransition(prevWire, currWire, i, false)) {
					sawInlineStrictTransition = true;
					continue;
				}
				genuineDivergedIdx = i;
				break;
			}
		}
		if (genuineDivergedIdx === null && currWire.itemHashes.length < prevWire.itemHashes.length) {
			genuineDivergedIdx = currWire.itemHashes.length;
		}
		firstDivergedItemIdx = genuineDivergedIdx;

		if (prevWire.toolsHash !== currWire.toolsHash) {
			if (
				strictToolsFallback &&
				isStrictToolsRepresentationTransition(prevWire.tools, currWire.tools, false)
			) {
				isStrictFallbackChange = true;
				observedChanges.push("strict_tools_fallback");
			} else {
				toolsDelta = diffTools(prevWire.tools, currWire.tools);
				observedChanges.push("tools");
			}
		}

		if (prevWire.systemHash !== currWire.systemHash) {
			sysDiff = firstDiffSummary(prevWire.systemTextSample, currWire.systemTextSample);
			observedChanges.push("system");
		}

		if (firstDivergedItemIdx !== null && firstDivergedItemIdx < prevWire.itemHashes.length) {
			observedChanges.push("history");
		} else if (sawInlineStrictTransition) {
			isStrictFallbackChange = true;
			if (!observedChanges.includes("strict_tools_fallback")) {
				observedChanges.push("strict_tools_fallback");
			}
		}

		if (prevWire.effortConfigHash !== currWire.effortConfigHash) {
			observedChanges.push("effort_config");
		}
	}

	if (promptTotal < minCacheableTokens && cacheRead === 0) {
		return {
			diagnosis: "below_min_tokens",
			anomaly: false,
			shortTag: "<1k",
			detail: zh
				? `输入 ${promptTotal} tok 低于缓存起效阈值 (${minCacheableTokens})`
				: `Prompt ${promptTotal} tok below cache threshold (${minCacheableTokens})`,
			firstDivergedItemIdx,
			observedChanges,
		};
	}

	if (callIndex <= 1 && prevModelKey === null && prevSingleHitPct === null) {
		return {
			diagnosis: hitPct >= 50 ? "healthy_hit" : "cold_start",
			anomaly: false,
			shortTag: hitPct >= 50 ? "" : zh ? "冷启" : "cold",
			detail:
				hitPct >= 50
					? zh
						? `首轮复用热缓存 (${hitPct.toFixed(1)}%)`
						: `First turn reused warm cache (${hitPct.toFixed(1)}%)`
					: zh
						? "会话首轮冷启动建缓存"
						: "First turn cold-start cache warmup",
			firstDivergedItemIdx,
			observedChanges,
		};
	}

	const sharpDrop = hitPct < 50 || (prevSingleHitPct !== null && prevSingleHitPct - hitPct >= 35);

	if (prevModelKey !== null && prevModelKey !== modelKey) {
		const safePrevModel = sanitizeIdentifierKeepTail(prevModelKey, 96);
		const safeCurrModel = sanitizeIdentifierKeepTail(modelKey, 96);
		return {
			diagnosis: "model_changed",
			anomaly: sharpDrop,
			shortTag: sharpDrop ? "!model" : "",
			detail: zh
				? `生效模型从 ${safePrevModel} 切换为 ${safeCurrModel}`
				: `Effective model switched from ${safePrevModel} to ${safeCurrModel}`,
			firstDivergedItemIdx,
			observedChanges: ["model", ...observedChanges],
		};
	}

	if (!sharpDrop) {
		if (!comparableWire) {
			return {
				diagnosis: "healthy_hit",
				anomaly: false,
				shortTag: "",
				detail: zh
					? `缓存命中率正常 (${hitPct.toFixed(1)}%，无前序前缀快照可对比)`
					: `Healthy cache hit (${hitPct.toFixed(1)}%; prefix comparison unavailable)`,
				firstDivergedItemIdx: null,
				observedChanges,
			};
		}
		const changeNote =
			observedChanges.length > 0
				? zh
					? `（前缀已更新但未触发掉缓存: ${observedChanges.join(",")}）`
					: ` (prefix updated without cache drop: ${observedChanges.join(",")})`
				: "";
		return {
			diagnosis: "healthy_hit",
			anomaly: false,
			shortTag: "",
			detail: `${zh ? "前缀稳定命中" : "Prefix cache hit intact"}${changeNote}`,
			firstDivergedItemIdx,
			observedChanges,
		};
	}

	if (comparableWire && prevWire && currWire) {
		if (observedChanges.includes("tools")) {
			return {
				diagnosis: "tools_mutated",
				anomaly: true,
				shortTag: "!tools",
				detail: zh ? `tools 定义变更导致前缀失效: ${toolsDelta}` : `Tools schema mutated: ${toolsDelta}`,
				firstDivergedItemIdx,
				observedChanges,
			};
		}

		if (prevWire.systemHash !== currWire.systemHash) {
			return {
				diagnosis: "system_mutated",
				anomaly: true,
				shortTag: "!sys",
				detail: zh ? `system 提示词变更导致前缀失效: ${sysDiff}` : `System prompt mutated: ${sysDiff}`,
				firstDivergedItemIdx,
				observedChanges,
			};
		}

		if (observedChanges.includes("history") && firstDivergedItemIdx !== null) {
			return {
				diagnosis: "history_rewritten",
				anomaly: true,
				shortTag: "!hist",
				detail: zh
					? `历史消息在索引 #${firstDivergedItemIdx}/${prevWire.itemHashes.length} 处被改写或压缩`
					: `History mutated or compacted at item #${firstDivergedItemIdx}/${prevWire.itemHashes.length}`,
				firstDivergedItemIdx,
				observedChanges,
			};
		}

		if (isStrictFallbackChange) {
			return {
				diagnosis: "provider_strict_fallback",
				anomaly: true,
				shortTag: "!strict",
				detail: zh
					? "上游拒绝 strict 工具语法并触发降级重试 (anthropic_strict_tools_fallback)，导致前缀重算"
					: "Provider rejected strict tool grammar and retried with fallback schemas (anthropic_strict_tools_fallback)",
				firstDivergedItemIdx,
				observedChanges,
			};
		}
	}

	const hasMeasuredPrior = prevSingleHitPct !== null && prevSingleHitPct >= 50;

	if (!comparableWire) {
		const reasonZh = pairingAmbiguous
			? "存在并发/预热请求交叠，无法唯一配对请求快照"
			: "缺少可对比的前序或当前请求前缀快照（如会话恢复/分叉首轮）";
		const reasonEn = pairingAmbiguous
			? "overlapping requests prevented unambiguous wire snapshot pairing"
			: "no comparable prior/current wire snapshot (e.g. first turn after resume/fork)";
		return {
			diagnosis: "insufficient_evidence",
			anomaly: hasMeasuredPrior,
			shortTag: hasMeasuredPrior ? "!drop" : "",
			detail: zh
				? `命中率 ${hitPct.toFixed(1)}%，但${reasonZh}，暂不归因为网关路由异常`
				: `Hit rate ${hitPct.toFixed(1)}%, ${reasonEn}; withholding prefix/routing attribution`,
			firstDivergedItemIdx: null,
			observedChanges,
		};
	}

	if (idleSec !== null && currTtlSec !== null && touchTtlSec !== null && idleSec >= touchTtlSec) {
		return {
			diagnosis: "ttl_expired_likely",
			anomaly: true,
			shortTag: "!ttl",
			detail: zh
				? `距上次缓存触达间隔 ${idleSec}s (>=${touchTtlSec}s)，上游 KV 缓存过期`
				: `Idle ${idleSec}s since last cache touch (>=${touchTtlSec}s), upstream KV cache likely expired`,
			firstDivergedItemIdx,
			observedChanges,
		};
	}

	const retentionState = currWire?.retentionState ?? "unknown";
	if (retentionState === "disabled") {
		return {
			diagnosis: "insufficient_evidence",
			anomaly: hasMeasuredPrior,
			shortTag: hasMeasuredPrior ? "!drop" : "",
			detail: zh
				? `命中率 ${hitPct.toFixed(1)}%，当前请求显式禁用了提示词缓存，暂不归因为过期或网关路由异常`
				: `Hit rate ${hitPct.toFixed(1)}%; prompt caching is disabled on this request, withholding TTL/routing attribution`,
			firstDivergedItemIdx,
			observedChanges,
		};
	}
	if (currTtlSec === null || touchTtlSec === null || retentionTransitioned || idleSec === null) {
		const reasonZh =
			idleSec === null
				? "前序缓存触达时间不唯一"
				: currTtlSec === null || touchTtlSec === null
					? "请求未携带可验证的缓存保留策略"
					: `缓存保留策略发生切换 (${touchTtlSec}s->${currTtlSec}s)`;
		const reasonEn =
			idleSec === null
				? "prior cache touch timestamp could not be established unambiguously"
				: currTtlSec === null || touchTtlSec === null
					? "request has unverified or unknown cache retention"
					: `cache retention policy transitioned (${touchTtlSec}s->${currTtlSec}s)`;
		return {
			diagnosis: "insufficient_evidence",
			anomaly: hasMeasuredPrior,
			shortTag: hasMeasuredPrior ? "!drop" : "",
			detail: zh
				? `命中率 ${hitPct.toFixed(1)}%（间隔 ${idleSec ?? "?"}s），${reasonZh}，暂不归因为 TTL 过期或路由异常`
				: `Hit rate ${hitPct.toFixed(1)}% after ${idleSec ?? "?"}s idle (${reasonEn}); withholding TTL/routing attribution`,
			firstDivergedItemIdx,
			observedChanges,
		};
	}

	if (hitPct === 0) {
		const effortNote = observedChanges.includes("effort_config")
			? zh
				? "（注: 推理强度配置已变更）"
				: " (note: provider effort config changed)"
			: "";
		return {
			diagnosis: "provider_miss_or_routing",
			anomaly: true,
			shortTag: "!route",
			detail: zh
				? `前缀哈希未变且间隔 ${idleSec}s，但 cacheRead=0（排查网关节点/账号池漂移）${effortNote}`
				: `Prefix intact after ${idleSec}s but cacheRead=0 (check gateway routing / upstream pool)${effortNote}`,
			firstDivergedItemIdx,
			observedChanges,
		};
	}

	return {
		diagnosis: "partial_hit",
		anomaly: true,
		shortTag: "!drop",
		detail: zh
			? `命中率从 ${(prevSingleHitPct ?? 0).toFixed(1)}% 跌至 ${hitPct.toFixed(1)}% (divergedIdx=${firstDivergedItemIdx ?? "none"})`
			: `Hit rate dropped from ${(prevSingleHitPct ?? 0).toFixed(1)}% to ${hitPct.toFixed(1)}% (divergedIdx=${firstDivergedItemIdx ?? "none"})`,
		firstDivergedItemIdx,
		observedChanges,
	};
}
