import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import test from "node:test";
import cacheLensExtension from "../index.ts";
import { classifyTurn } from "../src/classify.ts";
import { expandTildePath, loadConfig } from "../src/config.ts";
import {
	extractWireFingerprint,
	firstDiffSummary,
	isStrictItemRepresentationTransition,
	isStrictToolsRepresentationTransition,
	redactSecrets,
} from "../src/fingerprint.ts";
import { persistRecord, readRecentJsonl, readRecentJsonlUnlocked, withLedgerLock } from "../src/ledger.ts";
import { formatStatusChip } from "../src/status.ts";
import type { TurnCacheRecord } from "../src/types.ts";

function makeTempDir(prefix: string): Promise<string> {
	return fs.mkdtemp(path.join(os.tmpdir(), prefix));
}

function createHarness(initialEntries: any[] = [], cwd = "/tmp/repo") {
	const handlers = new Map<string, Array<(event: any, ctx: any) => any>>();
	const commands = new Map<string, { description: string; handler: (args: string, ctx: any) => Promise<void> }>();
	const statuses = new Map<string, string | undefined>();
	const notifications: Array<{ message: string; level: string }> = [];
	const entries = [...initialEntries];

	const pi: any = {
		on(event: string, handler: (event: any, ctx: any) => any) {
			const list = handlers.get(event) ?? [];
			list.push(handler);
			handlers.set(event, list);
			return () => {};
		},
		registerCommand(name: string, spec: any) {
			commands.set(name, spec);
		},
		getThinkingLevel() {
			return "medium";
		},
	};

	const ctx: any = {
		hasUI: true,
		cwd,
		thinkingLevel: "low",
		model: { provider: "anthropic", id: "claude-sonnet-4-6", api: "anthropic-messages" },
		ui: {
			theme: {
				fg: (color: string, text: string) => `<${color}>${text}</${color}>`,
			},
			setStatus(key: string, text: string | undefined) {
				statuses.set(key, text);
			},
			notify(message: string, level: string) {
				notifications.push({ message, level });
			},
		},
		sessionManager: {
			getSessionId: () => "sess-test-12345678",
			getEntries: () => entries,
		},
	};

	async function emit(eventName: string, eventPayload: any = {}) {
		const list = handlers.get(eventName) ?? [];
		let last: any;
		for (const h of list) {
			last = await h({ type: eventName, ...eventPayload }, ctx);
		}
		return last;
	}

	return { pi, ctx, handlers, commands, statuses, notifications, entries, emit };
}

test("system diff persists zero raw prompt excerpts and reports exact pre-redaction offsets", async () => {
	const prev = "prefix sk-1234567890abcdef token v1 ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
	const next = "prefix sk-1234567890abcdef token v2 ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
	const diff = firstDiffSummary(prev, next);

	// Exact offset of '1' vs '2' in unredacted string is char 34 / byte 34.
	assert.match(diff, /^char@34 byte@34 /);
	assert.equal(diff.includes("ghp_"), false);
	assert.equal(diff.includes("sk-"), false);
	assert.equal(diff.includes("v1"), false);
	assert.equal(redactSecrets(next).includes("ghp_"), false);

	const tmpDir = await makeTempDir("cache-lens-sec-");
	try {
		const w1 = extractWireFingerprint({ system: prev, messages: [{ role: "user", content: "hi" }] }, 1000)!;
		const w2 = extractWireFingerprint({ system: next, messages: [{ role: "user", content: "hi" }] }, 2000)!;
		const verdict = classifyTurn({
			callIndex: 2,
			modelKey: "openai/gpt-5.4",
			prevModelKey: "openai/gpt-5.4",
			promptTotal: 4000,
			cacheRead: 0,
			prevSingleHitPct: 95,
			idleSec: 2,
			prevWire: w1,
			currWire: w2,
			ttlThresholdSec: 290,
			minCacheableTokens: 1024,
			locale: "en",
		});

		const rec: TurnCacheRecord = {
			ts: new Date(2000).toISOString(),
			sessionId: "sess-ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
			cwd: "/tmp/token=my-secret-value",
			provider: "openai",
			requestedModel: "gpt-5.4",
			model: "gpt-5.4",
			api: "openai-responses",
			thinkingLevel: "high",
			providerThinkingLevel: "high",
			callIndex: 2,
			idleSec: 2,
			input: 4000,
			cacheRead: 0,
			cacheWrite: 0,
			output: 50,
			promptTotal: 4000,
			singleHitPct: 0,
			sessionHitPct: 48.7,
			sessionPromptTotal: 8000,
			sessionCacheRead: 3900,
			costUsd: 0.02,
			systemHash: w2.systemHash,
			systemBytes: w2.systemBytes,
			toolsHash: w2.toolsHash,
			toolsBytes: w2.toolsBytes,
			itemCount: 1,
			firstDivergedItemIdx: null,
			promptCacheKey: "Bearer supersecretbearer123456",
			hasCacheControl: false,
			observedChanges: verdict.observedChanges,
			diagnosis: verdict.diagnosis,
			anomaly: verdict.anomaly,
			shortTag: verdict.shortTag,
			detail: verdict.detail,
		};

		await persistRecord(rec, tmpDir, 1024 * 1024, "en");
		for (const file of ["events.jsonl", "anomalies.jsonl", "latest-report.md"]) {
			const content = await fs.readFile(path.join(tmpDir, file), "utf8");
			assert.equal(content.includes("ghp_"), false, `${file} leaked ghp_ token`);
			assert.equal(content.includes("sk-123456"), false, `${file} leaked sk- token`);
			assert.equal(content.includes("my-secret-value"), false, `${file} leaked kv secret`);
			assert.equal(content.includes("supersecretbearer"), false, `${file} leaked bearer secret`);
		}
	} finally {
		await fs.rm(tmpDir, { recursive: true, force: true });
	}
});

test("rolling cache_control wrappers normalize user, assistant, and Completions tool messages while preserving schema/arg properties named cache_control", () => {
	const makeTool = (propType: string, withMarker: boolean) => ({
		name: "configure_proxy",
		input_schema: {
			type: "object",
			properties: {
				cache_control: { type: propType },
			},
		},
		...(withMarker ? { cache_control: { type: "ephemeral" } } : {}),
	});

	const call1 = {
		model: "claude-sonnet-4-6",
		system: [{ type: "text", text: "sys", cache_control: { type: "ephemeral" } }],
		tools: [makeTool("string", true)],
		messages: [
			{ role: "user", content: [{ type: "text", text: "run", cache_control: { type: "ephemeral" } }] },
			{
				role: "assistant",
				content: [{ type: "text", text: "checking", cache_control: { type: "ephemeral" } }],
				tool_calls: [{ id: "tc_1", type: "function", function: { name: "configure_proxy", arguments: '{"cache_control":"no-cache"}' } }],
			},
			{
				role: "tool",
				tool_call_id: "tc_1",
				content: [{ type: "text", text: "ok", cache_control: { type: "ephemeral" } }],
			},
		],
	};

	const call2SameLogical = {
		model: "claude-sonnet-4-6",
		system: [{ type: "text", text: "sys" }],
		tools: [makeTool("string", false)],
		messages: [
			{ role: "user", content: "run" },
			{
				role: "assistant",
				content: "checking",
				tool_calls: [{ id: "tc_1", type: "function", function: { name: "configure_proxy", arguments: '{"cache_control":"no-cache"}' } }],
			},
			{
				role: "tool",
				tool_call_id: "tc_1",
				content: "ok",
			},
			{ role: "user", content: [{ type: "text", text: "next", cache_control: { type: "ephemeral" } }] },
		],
	};

	const f1 = extractWireFingerprint(call1)!;
	const f2 = extractWireFingerprint(call2SameLogical)!;
	assert.equal(f1.toolsHash, f2.toolsHash);
	assert.equal(f1.itemHashes[0], f2.itemHashes[0]);
	assert.equal(f1.itemHashes[1], f2.itemHashes[1]);
	assert.equal(f1.itemHashes[2], f2.itemHashes[2]);

	// Changing input_schema.properties.cache_control MUST change toolsHash!
	const fSchemaChanged = extractWireFingerprint({
		...call2SameLogical,
		tools: [makeTool("integer", false)],
	})!;
	assert.notEqual(f1.toolsHash, fSchemaChanged.toolsHash);

	// Changing tool_call_id or argument named cache_control MUST change itemHashes!
	const fToolIdChanged = extractWireFingerprint({
		...call2SameLogical,
		messages: [
			call2SameLogical.messages[0],
			{
				role: "assistant",
				content: "checking",
				tool_calls: [{ id: "tc_1", type: "function", function: { name: "configure_proxy", arguments: '{"cache_control":"max-age=0"}' } }],
			},
			{ role: "tool", tool_call_id: "tc_2", content: "ok" },
		],
	})!;
	assert.notEqual(f1.itemHashes[1], fToolIdChanged.itemHashes[1]);
	assert.notEqual(f1.itemHashes[2], fToolIdChanged.itemHashes[2]);
});

test("Anthropic output_config and Responses configuration_update effort markers do not trigger false history_rewritten", () => {
	const turnWithEffort = extractWireFingerprint({
		model: "claude-opus-4-7",
		system: [{ type: "text", text: "You are pi." }],
		thinking: { type: "adaptive", display: "summarized" },
		output_config: { effort: "high" },
		messages: [
			{ role: "user", content: "hello" },
			{ role: "system", content: [], output_config: { effort: "high" } },
			{ role: "assistant", content: [{ type: "text", text: "hi" }] },
			{ role: "system", content: [], output_config: { effort: "high" } },
		],
	})!;

	const turnThinkingOff = extractWireFingerprint({
		model: "claude-opus-4-7",
		system: [{ type: "text", text: "You are pi." }],
		messages: [
			{ role: "user", content: "hello" },
			{ role: "assistant", content: [{ type: "text", text: "hi" }] },
			{ role: "user", content: "follow up" },
		],
	})!;

	assert.deepEqual(turnWithEffort.itemHashes, turnThinkingOff.itemHashes.slice(0, 2));
	assert.notEqual(turnWithEffort.effortConfigHash, turnThinkingOff.effortConfigHash);

	const verdict = classifyTurn({
		callIndex: 2,
		modelKey: "anthropic/claude-opus-4-7",
		prevModelKey: "anthropic/claude-opus-4-7",
		promptTotal: 5000,
		cacheRead: 0,
		prevSingleHitPct: 90,
		idleSec: 3,
		prevWire: turnWithEffort,
		currWire: turnThinkingOff,
		ttlThresholdSec: 290,
		minCacheableTokens: 1024,
		locale: "en",
	});
	assert.notEqual(verdict.diagnosis, "history_rewritten");
	assert.equal(verdict.observedChanges.includes("effort_config"), true);

	// OpenAI Responses configuration_update items are likewise excluded from itemHashes.
	const respWithConfig = extractWireFingerprint({
		model: "gpt-5.4",
		instructions: "You are pi.",
		input: [
			{ role: "user", content: [{ type: "input_text", text: "q1" }] },
			{ type: "configuration_update", reasoning: { effort: "high" } },
			{ type: "message", role: "assistant", content: [{ type: "output_text", text: "a1" }] },
			{ type: "configuration_update", reasoning: { effort: "low" } },
		],
	})!;
	assert.equal(respWithConfig.itemHashes.length, 2);
});

test("Responses leading additional_tools (role: developer) classify as tools rather than system text, preserving mid-transcript additions", () => {
	const makeResponsesPayload = (paramType: string, withMidConvoAddition = false) => ({
		model: "gpt-5.4",
		input: [
			{
				type: "additional_tools",
				role: "developer",
				tools: [
					{
						type: "function",
						name: "bash",
						description: "Run shell",
						parameters: { type: "object", properties: { cmd: { type: paramType } } },
					},
				],
			},
			{ role: "developer", content: "Static system prompt" },
			{ role: "user", content: [{ type: "input_text", text: "task 1" }] },
			...(withMidConvoAddition
				? [
						{
							type: "additional_tools",
							role: "developer",
							tools: [{ type: "function", name: "mcp_extra", description: "dynamic", parameters: { type: "object" } }],
						},
					]
				: []),
		],
	});

	const w1 = extractWireFingerprint(makeResponsesPayload("string"))!;
	const w2 = extractWireFingerprint(makeResponsesPayload("number"))!;

	assert.equal(w1.systemHash, w2.systemHash);
	assert.notEqual(w1.toolsHash, w2.toolsHash);

	const verdict = classifyTurn({
		callIndex: 2,
		modelKey: "openai/gpt-5.4",
		prevModelKey: "openai/gpt-5.4",
		promptTotal: 4000,
		cacheRead: 0,
		prevSingleHitPct: 92,
		idleSec: 4,
		prevWire: w1,
		currWire: w2,
		ttlThresholdSec: 290,
		minCacheableTokens: 1024,
		locale: "en",
	});
	assert.equal(verdict.diagnosis, "tools_mutated");
	assert.match(verdict.detail, /~bash/);

	const wMid = extractWireFingerprint(makeResponsesPayload("string", true))!;
	assert.equal(wMid.tools.length, 1);
	assert.equal(wMid.itemHashes.length, 2);
});

test("Anthropic strict-tool fallback and healthy 99% cache hits do not enter anomaly ledger as tools_mutated", () => {
	const strictPayload = {
		model: "claude-sonnet-4-6",
		system: "sys",
		tools: [
			{
				name: "read",
				description: "Read file",
				strict: true,
				input_schema: {
					type: "object",
					properties: {
						path: { type: "string" },
						limit: { anyOf: [{ type: "number" }, { type: "null" }] },
					},
					required: ["path", "limit"],
					additionalProperties: false,
				},
			},
		],
		messages: [{ role: "user", content: "hi" }],
	};
	const fallbackPayload = {
		model: "claude-sonnet-4-6",
		system: "sys",
		tools: [
			{
				name: "read",
				description: "Read file",
				input_schema: {
					type: "object",
					properties: { path: { type: "string" }, limit: { type: "number" } },
					required: ["path"],
				},
			},
		],
		messages: [{ role: "user", content: "hi" }, { role: "user", content: "more" }],
	};

	const wStrict = extractWireFingerprint(strictPayload)!;
	const wFallback = extractWireFingerprint(fallbackPayload)!;
	assert.notEqual(wStrict.toolsHash, wFallback.toolsHash);
	assert.equal(wStrict.logicalToolsHash, wFallback.logicalToolsHash);

	// 1. With 99% hit rate (!sharpDrop), even a real tool or system update is NOT an anomaly!
	const healthyVerdict = classifyTurn({
		callIndex: 3,
		modelKey: "anthropic/claude-sonnet-4-6",
		prevModelKey: "anthropic/claude-sonnet-4-6",
		promptTotal: 10000,
		cacheRead: 9900,
		prevSingleHitPct: 99,
		idleSec: 3,
		prevWire: wStrict,
		currWire: extractWireFingerprint({ ...fallbackPayload, system: "sys updated at tail" })!,
		strictToolsFallback: true,
		ttlThresholdSec: 290,
		minCacheableTokens: 1024,
		locale: "en",
	});
	assert.equal(healthyVerdict.diagnosis, "healthy_hit");
	assert.equal(healthyVerdict.anomaly, false);
	assert.equal(healthyVerdict.shortTag, "");

	// 2. With a cache drop AND anthropic_strict_tools_fallback, classify as provider_strict_fallback rather than tools_mutated.
	const dropVerdict = classifyTurn({
		callIndex: 3,
		modelKey: "anthropic/claude-sonnet-4-6",
		prevModelKey: "anthropic/claude-sonnet-4-6",
		promptTotal: 10000,
		cacheRead: 0,
		prevSingleHitPct: 99,
		idleSec: 3,
		prevWire: wStrict,
		currWire: wFallback,
		strictToolsFallback: true,
		ttlThresholdSec: 290,
		minCacheableTokens: 1024,
		locale: "en",
	});
	assert.equal(dropVerdict.diagnosis, "provider_strict_fallback");
	assert.equal(dropVerdict.shortTag, "!strict");
});

test("extension lifecycle: frozen payload pass-through, no unsupported session_fork, tilde PI_CODING_AGENT_DIR, finalized thinkingLevel, and responseModel fallback", async () => {
	const tmpHome = await makeTempDir("cache-lens-home-");
	const prevEnv = process.env.PI_CODING_AGENT_DIR;
	const relSub = path.basename(tmpHome);
	const parentDir = path.dirname(tmpHome);
	assert.equal(expandTildePath("~/agent-test", "/Users/mock"), "/Users/mock/agent-test");

	process.env.PI_CODING_AGENT_DIR = path.join(parentDir, relSub);
	try {
		await fs.writeFile(
			path.join(tmpHome, "cache-lens.json"),
			JSON.stringify({ locale: "en", ttlThresholdSec: 290 }),
			"utf8",
		);

		const h = createHarness();
		cacheLensExtension(h.pi);

		// Unsupported session_fork hook must not be registered.
		assert.equal(h.handlers.has("session_fork"), false);
		assert.equal(h.handlers.has("session_start"), true);

		await h.emit("session_start", { reason: "startup" });

		// Deeply frozen payload must remain untouched and handler must return undefined.
		const payload1 = Object.freeze({
			model: "claude-opus-4-7",
			system: Object.freeze([Object.freeze({ type: "text", text: "immutable system" })]),
			tools: Object.freeze([]),
			messages: Object.freeze([Object.freeze({ role: "user", content: "hello" })]),
		});
		await h.emit("turn_start", {});
		const hookResult = await h.emit("before_provider_request", { payload: payload1 });
		assert.equal(hookResult, undefined);

		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-opus-4-7",
				api: "anthropic-messages",
				thinkingLevel: "xhigh",
				providerThinkingLevel: "max",
				usage: { input: 200, cacheRead: 0, cacheWrite: 2800, output: 40, cost: { total: 0.03 } },
			},
		});

		// Turn 2: server-side fallback answers with responseModel = claude-sonnet-4-6 while requested model stays claude-opus-4-7!
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", {
			payload: {
				model: "claude-opus-4-7",
				system: [{ type: "text", text: "immutable system" }],
				tools: [],
				messages: [{ role: "user", content: "hello" }, { role: "user", content: "q2" }],
			},
		});
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-opus-4-7",
				responseModel: "claude-sonnet-4-6",
				api: "anthropic-messages",
				thinkingLevel: "high",
				providerThinkingLevel: "high",
				usage: { input: 3200, cacheRead: 0, cacheWrite: 0, output: 35, cost: { total: 0.01 } },
			},
		});

		await h.emit("session_shutdown", {});

		const events = await readRecentJsonl(path.join(tmpHome, "cache-lens", "events.jsonl"), 10);
		assert.equal(events.length, 2);
		assert.equal(events[0]!.thinkingLevel, "xhigh");
		assert.equal(events[0]!.providerThinkingLevel, "max");
		assert.equal(events[1]!.requestedModel, "claude-opus-4-7");
		assert.equal(events[1]!.model, "claude-sonnet-4-6");
		assert.equal(events[1]!.diagnosis, "model_changed");
	} finally {
		if (prevEnv === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = prevEnv;
		await fs.rm(tmpHome, { recursive: true, force: true });
	}
});

test("extension lifecycle: missing/zero prompt usage clears pending wire without fabricating 0% miss, and cancelled CacheWarmer never steals foreground snapshot", async () => {
	const tmpDir = await makeTempDir("cache-lens-pair-");
	const prevEnv = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = tmpDir;
	try {
		await fs.writeFile(path.join(tmpDir, "cache-lens.json"), JSON.stringify({ locale: "en" }), "utf8");
		const h = createHarness();
		cacheLensExtension(h.pi);
		await h.emit("session_start", { reason: "startup" });

		// Turn 1: healthy warm cache baseline
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", {
			payload: {
				model: "claude-sonnet-4-6",
				system: "sys-v1",
				tools: [],
				messages: [{ role: "user", content: "m1" }],
			},
		});
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-sonnet-4-6",
				api: "anthropic-messages",
				usage: { input: 100, cacheRead: 2900, cacheWrite: 0, output: 25, cost: { total: 0.005 } },
			},
		});

		// Aborted turn with output=20 and zero prompt tokens MUST clear pending capture, record usage_unavailable, and keep baseline!
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", {
			payload: {
				model: "claude-sonnet-4-6",
				system: "sys-MUTATED-ABORTED-SHOULD-NOT-BECOME-BASELINE",
				tools: [],
				messages: [{ role: "user", content: "m1" }, { role: "user", content: "aborted" }],
			},
		});
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-sonnet-4-6",
				api: "anthropic-messages",
				stopReason: "aborted",
				usage: { input: 0, cacheRead: 0, cacheWrite: 0, output: 20, cost: { total: 0.0003 } },
			},
		});

		// Overlapping cancelled CacheWarmer payload arriving AFTER foreground before_provider_request (without message_end)
		// must NOT overwrite foreground snapshot with stale 1-message warm context; ambiguous pairing withholds false !hist / !route.
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", {
			payload: {
				model: "claude-sonnet-4-6",
				system: "sys-v1",
				tools: [],
				messages: [{ role: "user", content: "m1" }, { role: "user", content: "m2" }],
			},
		});
		// Late cancelled warm callback fires on the shared onPayload hook with old 1-item context:
		await h.emit("before_provider_request", {
			payload: {
				model: "claude-sonnet-4-6",
				system: "sys-v1",
				tools: [],
				max_tokens: 1,
				messages: [{ role: "user", content: "m1" }],
			},
		});
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-sonnet-4-6",
				api: "anthropic-messages",
				usage: { input: 3500, cacheRead: 0, cacheWrite: 0, output: 30, cost: { total: 0.01 } },
			},
		});

		await h.emit("session_shutdown", {});
		const events = await readRecentJsonl(path.join(tmpDir, "cache-lens", "events.jsonl"), 10);
		assert.equal(events.length, 3);

		assert.equal(events[1]!.diagnosis, "usage_unavailable");
		assert.equal(events[1]!.singleHitPct, null);
		assert.equal(events[1]!.anomaly, false);

		// Event 2 had overlapping foreground + cancelled warm callbacks -> insufficient_evidence, never stolen 1-item snapshot!
		assert.equal(events[2]!.diagnosis, "insufficient_evidence");
		assert.equal(events[2]!.itemCount, null);
	} finally {
		if (prevEnv === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = prevEnv;
		await fs.rm(tmpDir, { recursive: true, force: true });
	}
});

test("resume/fork without prior wire snapshot withholds false Prefix intact, while dispatch timestamps and long retention avoid false TTL expiry", async () => {
	const tmpDir = await makeTempDir("cache-lens-ttl-");
	const prevEnv = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = tmpDir;
	const realNow = Date.now;
	let fakeNow = 1_700_000_000_000;
	Date.now = () => fakeNow;

	try {
		await fs.writeFile(path.join(tmpDir, "cache-lens.json"), JSON.stringify({ locale: "en", ttlThresholdSec: 290 }), "utf8");
		const historicalEntries: any[] = [
			{
				type: "message",
				timestamp: new Date(fakeNow - 10_000).toISOString(),
				message: {
					role: "assistant",
					provider: "openai",
					model: "gpt-5.4",
					timestamp: fakeNow - 10_000,
					usage: { input: 200, cacheRead: 3800, cacheWrite: 0, output: 30 },
				},
			},
		];

		const h = createHarness(historicalEntries);
		h.ctx.model = { provider: "openai", id: "gpt-5.4", api: "openai-responses" };
		cacheLensExtension(h.pi);

		// Simulate resume (or fork via session_start reason: "fork")
		await h.emit("session_start", { reason: "fork" });

		// Turn after fork has no prevWire -> must NOT claim "Prefix intact" (!route); must report insufficient_evidence!
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", {
			payload: {
				model: "gpt-5.4",
				instructions: "sys",
				prompt_cache_retention: "24h",
				input: [{ role: "user", content: [{ type: "input_text", text: "after fork" }] }],
			},
		});
		// Generation takes 400 seconds AFTER dispatch (dispatched only 10s after historical touch!):
		fakeNow += 400_000;
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "openai",
				model: "gpt-5.4",
				api: "openai-responses",
				usage: { input: 4000, cacheRead: 0, cacheWrite: 0, output: 500 },
			},
		});

		// Next request is dispatched 1.1s after previous completion (Wait: 401.1s after previous dispatch, OR with cache_warm refresh 1.1s ago),
		// AND has prompt_cache_retention: "24h" (86400s TTL) + takes 400s to generate!
		fakeNow += 1_100;
		h.entries.push({
			type: "usage",
			kind: "cache_warm",
			provider: "openai",
			model: "gpt-5.4",
			timestamp: new Date(fakeNow - 1_100).toISOString(),
			usage: { input: 0, cacheRead: 4000, cacheWrite: 0, output: 1 },
		});
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", {
			payload: {
				model: "gpt-5.4",
				instructions: "sys",
				prompt_cache_retention: "24h",
				input: [
					{ role: "user", content: [{ type: "input_text", text: "after fork" }] },
					{ role: "user", content: [{ type: "input_text", text: "q3" }] },
				],
			},
		});
		// Simulate 400s generation duration before message_end:
		fakeNow += 400_000;
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "openai",
				model: "gpt-5.4",
				api: "openai-responses",
				usage: { input: 4500, cacheRead: 0, cacheWrite: 0, output: 800 },
			},
		});

		await h.emit("session_shutdown", {});
		const events = await readRecentJsonl(path.join(tmpDir, "cache-lens", "events.jsonl"), 10);
		assert.equal(events.length, 2);
		assert.equal(events[0]!.diagnosis, "insufficient_evidence");
		assert.equal(events[0]!.idleSec, 10);
		assert.equal(events[1]!.idleSec, 1);
		assert.equal(events[1]!.diagnosis, "provider_miss_or_routing");
	} finally {
		Date.now = realNow;
		if (prevEnv === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = prevEnv;
		await fs.rm(tmpDir, { recursive: true, force: true });
	}
});
test("config bounds reject Infinity and sub-second rounding to zero; ledger lock coordinates concurrent rotation and spans .1 history", async () => {
	const tmpDir = await makeTempDir("cache-lens-cfg-");
	try {
		await fs.writeFile(
			path.join(tmpDir, "cache-lens.json"),
			'{"maxLogBytes": 1e999, "minCacheableTokens": 1e999, "ttlThresholdSec": 0.1}',
			"utf8",
		);
		const cfg = loadConfig(tmpDir);
		assert.equal(Number.isFinite(cfg.maxLogBytes), true);
		assert.equal(cfg.maxLogBytes, 10 * 1024 * 1024);
		assert.equal(cfg.minCacheableTokens, 1024);
		assert.equal(cfg.ttlThresholdSec, 290);

		const ledgerDir = path.join(tmpDir, "ledger");
		const makeRec = (idx: number): TurnCacheRecord => ({
			ts: new Date(1_700_000_000_000 + idx * 1000).toISOString(),
			sessionId: `sess-${idx}`,
			cwd: "/tmp/work",
			provider: "anthropic",
			requestedModel: "claude-sonnet-4-6",
			model: "claude-sonnet-4-6",
			api: "anthropic-messages",
			thinkingLevel: "high",
			providerThinkingLevel: "high",
			callIndex: idx,
			idleSec: 2,
			input: 2000,
			cacheRead: 0,
			cacheWrite: 0,
			output: 20,
			promptTotal: 2000,
			singleHitPct: 0,
			sessionHitPct: 0,
			sessionPromptTotal: 2000 * idx,
			sessionCacheRead: 0,
			costUsd: 0.01,
			systemHash: "abcdef123456",
			systemBytes: 1024,
			toolsHash: "123456abcdef",
			toolsBytes: 2048,
			itemCount: idx,
			firstDivergedItemIdx: null,
			promptCacheKey: null,
			hasCacheControl: true,
			observedChanges: [],
			diagnosis: "provider_miss_or_routing",
			anomaly: true,
			shortTag: "!route",
			detail: `padding-${"x".repeat(180)}-${idx}`,
		});

		// Fire 16 concurrent writes with a 2500-byte rotation threshold (~3 records/file) to force racing rotations.
		await Promise.all(Array.from({ length: 16 }, (_, i) => persistRecord(makeRec(i + 1), ledgerDir, 2500, "en")));

		const activeRaw = await fs.readFile(path.join(ledgerDir, "events.jsonl"), "utf8");
		const activeCount = activeRaw.trim().split("\n").filter(Boolean).length;
		// Recent reader MUST span active + .1 rotated file instead of returning only activeCount!
		const recentEvents = await readRecentJsonl(path.join(ledgerDir, "events.jsonl"), 16);
		assert.equal(recentEvents.length > activeCount, true);
		assert.equal(recentEvents.length >= 4, true);

		const report = await fs.readFile(path.join(ledgerDir, "latest-report.md"), "utf8");
		assert.match(report, /^# Pi Prefix KV Cache Diagnostics/m);
		assert.equal(report.endsWith("\n"), true);
	} finally {
		await fs.rm(tmpDir, { recursive: true, force: true });
	}
});

test("persistence failure surfaces a rate-limited UI warning without throwing into the agent loop", async () => {
	const tmpDir = await makeTempDir("cache-lens-err-");
	const prevEnv = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = tmpDir;
	try {
		// Create a regular file where telemetryDir expects a directory so mkdir/persist fails deterministically.
		const blockerFile = path.join(tmpDir, "blocked-telemetry-file");
		await fs.writeFile(blockerFile, "not-a-directory", "utf8");
		await fs.writeFile(
			path.join(tmpDir, "cache-lens.json"),
			JSON.stringify({ locale: "en", telemetryDir: blockerFile }),
			"utf8",
		);

		const h = createHarness();
		cacheLensExtension(h.pi);
		await h.emit("session_start", { reason: "startup" });

		for (let i = 0; i < 3; i++) {
			await h.emit("turn_start", {});
			await h.emit("before_provider_request", {
				payload: { model: "claude-sonnet-4-6", system: "s", messages: [{ role: "user", content: `q${i}` }] },
			});
			await h.emit("message_end", {
				message: {
					role: "assistant",
					provider: "anthropic",
					model: "claude-sonnet-4-6",
					api: "anthropic-messages",
					usage: { input: 2000, cacheRead: 0, cacheWrite: 0, output: 10 },
				},
			});
		}
		await h.emit("session_shutdown", {});

		const warnings = h.notifications.filter((n) => n.level === "warning");
		assert.equal(warnings.length, 1);
		assert.match(warnings[0]!.message, /persistence warning/);
	} finally {
		if (prevEnv === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = prevEnv;
		await fs.rm(tmpDir, { recursive: true, force: true });
	}
});

test("status chip uses aligned muted warmup for first 3 non-anomalous calls and error/accent for drops/healthy", () => {
	const mockTheme = {
		fg: (color: string, text: string) => `<${color}>${text}</${color}>`,
	};
	// Non-anomalous 60% second call stays muted (aligned with <=3 calls warmup doc).
	const secondWarmup = formatStatusChip(
		{
			calls: 2,
			lastSinglePct: 60,
			sessionPromptTotal: 5000,
			sessionCacheRead: 2000,
			lastShortTag: "",
			lastAnomaly: false,
			icon: "\uF0E7",
			locale: "zh",
			healthyColor: "accent",
		},
		mockTheme,
	);
	assert.equal(secondWarmup.includes("<muted>60%</muted>"), true);
	assert.equal(secondWarmup.includes("<muted>40%</muted>"), true);

	// Anomalous drop on call 2 highlights immediately in error!
	const secondAnomaly = formatStatusChip(
		{
			calls: 2,
			lastSinglePct: 0,
			sessionPromptTotal: 5000,
			sessionCacheRead: 2000,
			lastShortTag: "!sys",
			lastAnomaly: true,
			icon: "\uF0E7",
			locale: "zh",
			healthyColor: "accent",
		},
		mockTheme,
	);
	assert.equal(secondAnomaly.includes("<error>0%(!sys)</error>"), true);
});

test("upstream makeStrictJsonSchema nullable optionals, literal 'required' property preservation, and inline tool_addition strict fallback", async () => {
	// Attempt to load actual mounted @earendil-works/pi-ai constrained-sampling if present on host;
	// fall back to exact makeStrictJsonSchema output structure when running standalone.
	let makeStrict: ((schema: any) => any) | null = null;
	try {
		const mod = await import(
			"/opt/homebrew/lib/node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-ai/dist/api/constrained-sampling.js"
		);
		if (typeof mod.makeStrictJsonSchema === "function") {
			makeStrict = mod.makeStrictJsonSchema;
		}
	} catch {
		makeStrict = null;
	}

	const rawParameters = {
		type: "object",
		description: "Root schema description omitted by legacyInputSchema",
		properties: {
			path: { type: "string", description: "Target path" },
			limit: { type: "number", description: "Optional max lines" },
			required: { type: "boolean", description: "Literal property named required" },
			filter: {
				type: "object",
				properties: {
					tag: { type: "string" },
					depth: { type: "integer" },
				},
				required: ["tag"],
			},
		},
		required: ["path"],
	};

	const strictParams = makeStrict
		? makeStrict(rawParameters)
		: {
				type: "object",
				description: "Root schema description omitted by legacyInputSchema",
				properties: {
					path: { type: "string", description: "Target path" },
					limit: { anyOf: [{ type: "number", description: "Optional max lines" }, { type: "null" }] },
					required: {
						anyOf: [{ type: "boolean", description: "Literal property named required" }, { type: "null" }],
					},
					filter: {
						anyOf: [
							{
								type: "object",
								properties: {
									tag: { type: "string" },
									depth: { anyOf: [{ type: "integer" }, { type: "null" }] },
								},
								required: ["tag", "depth"],
								additionalProperties: false,
							},
							{ type: "null" },
						],
					},
				},
				required: ["path", "limit", "required", "filter"],
				additionalProperties: false,
			};

	const legacyInputSchema = {
		type: "object",
		properties: rawParameters.properties,
		required: rawParameters.required,
	};
	const strictInputSchema = {
		...strictParams,
		type: "object",
		properties: strictParams.properties,
		required: strictParams.required,
	};

	const buildAnthropicWire = (isStrict: boolean, requiredPropType = "boolean") => {
		const schemaForBuild =
			requiredPropType === "boolean"
				? isStrict
					? strictInputSchema
					: legacyInputSchema
				: {
						type: "object",
						properties: {
							...rawParameters.properties,
							required: { type: requiredPropType, description: "Literal property named required" },
						},
						required: rawParameters.required,
					};
		const toolDef = {
			name: "inspect_tree",
			description: "Inspect repository tree",
			eager_input_streaming: true,
			...(isStrict ? { strict: true } : {}),
			input_schema: schemaForBuild,
		};
		return {
			model: "claude-opus-4-7",
			max_tokens: 16384,
			betas: ["inline-tools-2026-09-15"],
			system: [{ type: "text", text: "You are pi.", cache_control: { type: "ephemeral" } }],
			tools: [
				{ ...toolDef, cache_control: { type: "ephemeral" } },
				{
					name: "__pi_deferred_placeholder__",
					description: "Reserved placeholder.",
					input_schema: { type: "object", properties: {}, required: [] },
					defer_loading: true,
				},
			],
			messages: [
				{ role: "user", content: "start" },
				{
					role: "system",
					content: [
						{
							type: "tool_addition",
							tool: {
								type: "tool_definition",
								definition: { ...toolDef, name: "inline_inspect" },
							},
						},
					],
				},
				{ role: "assistant", content: [{ type: "text", text: "ready" }] },
				{ role: "user", content: [{ type: "text", text: "continue", cache_control: { type: "ephemeral" } }] },
			],
		};
	};

	const wStrict = extractWireFingerprint(buildAnthropicWire(true))!;
	const wFallback = extractWireFingerprint(buildAnthropicWire(false))!;
	assert.notEqual(wStrict.toolsHash, wFallback.toolsHash);
	assert.equal(wStrict.logicalToolsHash, wFallback.logicalToolsHash);
	assert.notEqual(wStrict.itemHashes[1], wFallback.itemHashes[1]);
	assert.equal(isStrictToolsRepresentationTransition(wStrict.tools, wFallback.tools, true), true);
	assert.equal(isStrictItemRepresentationTransition(wStrict, wFallback, 1, true), true);

	// Genuine mutation to a property literally named "required" MUST NOT be masked by strict fallback!
	const wMutatedRequiredProp = extractWireFingerprint(buildAnthropicWire(false, "string"))!;
	assert.notEqual(wStrict.logicalToolsHash, wMutatedRequiredProp.logicalToolsHash);
	const mutatedVerdict = classifyTurn({
		callIndex: 2,
		modelKey: "anthropic/claude-opus-4-7",
		prevModelKey: "anthropic/claude-opus-4-7",
		promptTotal: 8000,
		cacheRead: 0,
		prevSingleHitPct: 95,
		idleSec: 3,
		prevWire: wStrict,
		currWire: wMutatedRequiredProp,
		strictToolsFallback: true,
		ttlThresholdSec: 290,
		minCacheableTokens: 1024,
		locale: "en",
	});
	assert.equal(mutatedVerdict.diagnosis, "tools_mutated");

	// Full extension lifecycle: Turn 1 strict succeeds -> Turn 2 does 2-attempt strict fallback (with inline tool_addition)
	// -> pairs cleanly (NOT insufficient_evidence) and classifies drop as provider_strict_fallback (NOT history_rewritten)!
	const tmpDir = await makeTempDir("cache-lens-strict-");
	const prevEnv = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = tmpDir;
	try {
		await fs.writeFile(path.join(tmpDir, "cache-lens.json"), JSON.stringify({ locale: "en" }), "utf8");
		const h = createHarness();
		h.ctx.model = { provider: "anthropic", id: "claude-opus-4-7", api: "anthropic-messages" };
		cacheLensExtension(h.pi);
		await h.emit("session_start", { reason: "startup" });

		await h.emit("turn_start", {});
		await h.emit("before_provider_request", { payload: buildAnthropicWire(true) });
		await h.emit("after_provider_response", { status: 200, headers: {} });
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-opus-4-7",
				api: "anthropic-messages",
				usage: { input: 200, cacheRead: 7800, cacheWrite: 0, output: 30 },
			},
		});

		// Turn 2: Attempt 1 (strict) fails 400 before onResponse, Attempt 2 (fallback) succeeds 200 with diagnostic!
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", { payload: buildAnthropicWire(true) });
		await h.emit("before_provider_request", { payload: buildAnthropicWire(false) });
		await h.emit("after_provider_response", { status: 200, headers: {} });
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-opus-4-7",
				api: "anthropic-messages",
				diagnostics: [{ type: "anthropic_strict_tools_fallback" }],
				usage: { input: 8000, cacheRead: 0, cacheWrite: 0, output: 40 },
			},
		});
		await h.emit("session_shutdown", {});

		const events = await readRecentJsonl(path.join(tmpDir, "cache-lens", "events.jsonl"), 10);
		assert.equal(events.length, 2);
		assert.equal(events[1]!.diagnosis, "provider_strict_fallback");
		assert.equal(events[1]!.shortTag, "!strict");
	} finally {
		if (prevEnv === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = prevEnv;
		await fs.rm(tmpDir, { recursive: true, force: true });
	}
});

test("1-token warmer during prefill never matches as retry or zeroes 600s idle; trusted baseline survives ambiguous turn; 9-capture overflow preserves ambiguity", async () => {
	const tmpDir = await makeTempDir("cache-lens-prefill-");
	const prevEnv = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = tmpDir;
	const realNow = Date.now;
	let fakeNow = 1_700_100_000_000;
	Date.now = () => fakeNow;

	try {
		await fs.writeFile(path.join(tmpDir, "cache-lens.json"), JSON.stringify({ locale: "en", ttlThresholdSec: 290 }), "utf8");
		const h = createHarness();
		cacheLensExtension(h.pi);
		await h.emit("session_start", { reason: "startup" });

		const basePayload = (sys: string, maxTokens: number) => ({
			model: "claude-sonnet-4-6",
			max_tokens: maxTokens,
			system: [{ type: "text", text: sys, cache_control: { type: "ephemeral" } }],
			tools: [],
			messages: [{ role: "user", content: [{ type: "text", text: "hello", cache_control: { type: "ephemeral" } }] }],
		});

		// Turn 1: trusted baseline at t=0
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", { payload: basePayload("sys-baseline-v1", 16384) });
		await h.emit("after_provider_response", { status: 200, headers: {} });
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-sonnet-4-6",
				api: "anthropic-messages",
				usage: { input: 100, cacheRead: 3900, cacheWrite: 0, output: 20 },
			},
		});

		// Turn 2: 600s later, foreground starts prefill; before foreground message_start, a 1-token warmer
		// sharing the exact same prefix fires both before_provider_request and after_provider_response + cache_warm entry!
		fakeNow += 600_000;
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", { payload: basePayload("sys-baseline-v1", 16384) });
		fakeNow += 500;
		await h.emit("before_provider_request", { payload: basePayload("sys-baseline-v1", 1) });
		await h.emit("after_provider_response", { status: 200, headers: {} });
		h.entries.push({
			type: "usage",
			kind: "cache_warm",
			provider: "anthropic",
			model: "claude-sonnet-4-6",
			timestamp: new Date(fakeNow).toISOString(),
			usage: { input: 4000, cacheRead: 0, cacheWrite: 0, output: 1 },
		});
		fakeNow += 1_500;
		await h.emit("after_provider_response", { status: 200, headers: {} });
		await h.emit("message_start", { message: { role: "assistant" } });
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-sonnet-4-6",
				api: "anthropic-messages",
				usage: { input: 4000, cacheRead: 0, cacheWrite: 0, output: 30 },
			},
		});

		// Turn 3 (5s later): unambiguous system prompt mutation MUST compare against preserved Turn 1 baseline -> system_mutated!
		fakeNow += 5_000;
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", { payload: basePayload("sys-MUTATED-v2", 16384) });
		await h.emit("after_provider_response", { status: 200, headers: {} });
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-sonnet-4-6",
				api: "anthropic-messages",
				usage: { input: 4000, cacheRead: 0, cacheWrite: 0, output: 30 },
			},
		});

		// Turn 4 (5s later): 9 captures = 1 differing request + 8 identical requests -> sticky overflow ambiguity -> insufficient_evidence!
		fakeNow += 5_000;
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", { payload: basePayload("sys-divergent-evicted", 16384) });
		for (let i = 0; i < 8; i++) {
			await h.emit("before_provider_request", { payload: basePayload("sys-MUTATED-v2", 16384) });
		}
		await h.emit("after_provider_response", { status: 200, headers: {} });
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-sonnet-4-6",
				api: "anthropic-messages",
				usage: { input: 4000, cacheRead: 0, cacheWrite: 0, output: 30 },
			},
		});

		await h.emit("session_shutdown", {});
		const events = await readRecentJsonl(path.join(tmpDir, "cache-lens", "events.jsonl"), 10);
		assert.equal(events.length, 4);
		assert.notEqual(events[1]!.diagnosis, "provider_miss_or_routing");
		assert.equal(events[1]!.diagnosis, "insufficient_evidence");
		assert.equal(events[2]!.diagnosis, "system_mutated");
		assert.equal(events[3]!.diagnosis, "insufficient_evidence");
	} finally {
		Date.now = realNow;
		if (prevEnv === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = prevEnv;
		await fs.rm(tmpDir, { recursive: true, force: true });
	}
});
test("retention semantics: prompt_cache_options 30m (1800s), disabled explicit mode, unknown retention, long model IDs, 99%->60% model switch, and resumed healthy_hit wording", () => {
	// 1. OpenAI Responses prompt_cache_options: { ttl: "30m" } -> 1800s (600s idle is NOT ttl_expired_likely!)
	const w30mPrev = extractWireFingerprint({
		model: "gpt-5.4",
		instructions: "sys",
		prompt_cache_key: "sess-1",
		prompt_cache_options: { ttl: "30m" },
		input: [{ role: "user", content: [{ type: "input_text", text: "q1" }] }],
	})!;
	const w30mCurr = extractWireFingerprint({
		model: "gpt-5.4",
		instructions: "sys",
		prompt_cache_key: "sess-1",
		prompt_cache_options: { ttl: "30m" },
		input: [
			{ role: "user", content: [{ type: "input_text", text: "q1" }] },
			{ role: "user", content: [{ type: "input_text", text: "q2" }] },
		],
	})!;
	assert.equal(w30mCurr.retentionState, "explicit_ttl");
	assert.equal(w30mCurr.retentionTtlSec, 1800);

	const at600s = classifyTurn({
		callIndex: 2,
		modelKey: "openai/gpt-5.4",
		prevModelKey: "openai/gpt-5.4",
		promptTotal: 5000,
		cacheRead: 0,
		prevSingleHitPct: 95,
		idleSec: 600,
		prevWire: w30mPrev,
		currWire: w30mCurr,
		ttlThresholdSec: 290,
		minCacheableTokens: 1024,
		locale: "en",
	});
	assert.equal(at600s.diagnosis, "provider_miss_or_routing");

	const at1850s = classifyTurn({
		callIndex: 2,
		modelKey: "openai/gpt-5.4",
		prevModelKey: "openai/gpt-5.4",
		promptTotal: 5000,
		cacheRead: 0,
		prevSingleHitPct: 95,
		idleSec: 1850,
		prevWire: w30mPrev,
		currWire: w30mCurr,
		ttlThresholdSec: 290,
		minCacheableTokens: 1024,
		locale: "en",
	});
	assert.equal(at1850s.diagnosis, "ttl_expired_likely");

	// 2. Disabled caching (cacheRetention: "none" -> prompt_cache_options: { mode: "explicit" } without cache_control)
	// and unknown retention (no cache markers on wire) withhold ttl_expired_likely at 600s!
	const wDisabled = extractWireFingerprint({
		model: "gpt-5.4",
		instructions: "sys",
		prompt_cache_options: { mode: "explicit" },
		input: [{ role: "user", content: [{ type: "input_text", text: "q1" }] }],
	})!;
	assert.equal(wDisabled.retentionState, "disabled");
	const disabledVerdict = classifyTurn({
		callIndex: 2,
		modelKey: "openai/gpt-5.4",
		prevModelKey: "openai/gpt-5.4",
		promptTotal: 5000,
		cacheRead: 0,
		prevSingleHitPct: 90,
		idleSec: 600,
		prevWire: wDisabled,
		currWire: wDisabled,
		ttlThresholdSec: 290,
		minCacheableTokens: 1024,
		locale: "en",
	});
	assert.equal(disabledVerdict.diagnosis, "insufficient_evidence");

	const wUnknown = extractWireFingerprint({
		model: "custom-vllm",
		messages: [
			{ role: "system", content: "sys" },
			{ role: "user", content: "q1" },
		],
	})!;
	assert.equal(wUnknown.retentionState, "unknown");
	const unknownAt600 = classifyTurn({
		callIndex: 2,
		modelKey: "custom/custom-vllm",
		prevModelKey: "custom/custom-vllm",
		promptTotal: 5000,
		cacheRead: 0,
		prevSingleHitPct: 90,
		idleSec: 600,
		prevWire: wUnknown,
		currWire: wUnknown,
		ttlThresholdSec: 290,
		minCacheableTokens: 1024,
		locale: "en",
	});
	assert.equal(unknownAt600.diagnosis, "insufficient_evidence");

	// 3. Long >96-char model IDs differing only at the suffix AND 99% -> 60% sharp drop on model switch!
	const sharedPrefix = `openai/ft:gpt-5.4:${"org-segment-".repeat(9)}checkpoint-`;
	const modelA = `${sharedPrefix}alpha`;
	const modelB = `${sharedPrefix}beta`;
	assert.equal(modelA.slice(0, 96), modelB.slice(0, 96));

	const modelSwitchDrop = classifyTurn({
		callIndex: 3,
		modelKey: modelB,
		prevModelKey: modelA,
		promptTotal: 10000,
		cacheRead: 6000, // 60% hit rate down from 99% (39pp drop >= 35pp)
		prevSingleHitPct: 99,
		idleSec: 4,
		prevWire: w30mPrev,
		currWire: w30mCurr,
		ttlThresholdSec: 290,
		minCacheableTokens: 1024,
		locale: "en",
	});
	assert.equal(modelSwitchDrop.diagnosis, "model_changed");
	assert.equal(modelSwitchDrop.anomaly, true);
	assert.equal(modelSwitchDrop.shortTag, "!model");
	assert.match(modelSwitchDrop.detail, /alpha/);
	assert.match(modelSwitchDrop.detail, /beta/);

	// 4. Resumed healthy_hit (prevWire === null, 95% hit rate) explicitly notes prefix comparison unavailable.
	const resumedHealthy = classifyTurn({
		callIndex: 2,
		modelKey: "openai/gpt-5.4",
		prevModelKey: "openai/gpt-5.4",
		promptTotal: 4000,
		cacheRead: 3800,
		prevSingleHitPct: 95,
		idleSec: 5,
		prevWire: null,
		currWire: w30mCurr,
		ttlThresholdSec: 290,
		minCacheableTokens: 1024,
		locale: "en",
	});
	assert.equal(resumedHealthy.diagnosis, "healthy_hit");
	assert.equal(resumedHealthy.detail.includes("Prefix cache hit intact"), false);
	assert.match(resumedHealthy.detail, /prefix comparison unavailable/);
});

test("ledger lock liveness, dead-PID reclamation, rotation rename failure propagation, and snapshot-consistent recent reads", async () => {
	const tmpDir = await makeTempDir("cache-lens-lock-");
	try {
		// 1. Live writer with backdated lock directory mtime (>20s old) MUST NOT have its lock stolen,
		// and its release must leave no orphan lock behind.
		const liveDir = path.join(tmpDir, "live-lock");
		let releaseHolder!: () => void;
		const holderGate = new Promise<void>((resolve) => {
			releaseHolder = resolve;
		});
		let holderEntered!: () => void;
		const enteredPromise = new Promise<void>((resolve) => {
			holderEntered = resolve;
		});

		let activeOwners = 0;
		let maxSimultaneousOwners = 0;

		const holderTask = withLedgerLock(liveDir, async () => {
			activeOwners += 1;
			maxSimultaneousOwners = Math.max(maxSimultaneousOwners, activeOwners);
			const lockDir = path.join(liveDir, ".ledger.lock");
			const oldDate = new Date(Date.now() - 30_000);
			try {
				await fs.utimes(lockDir, oldDate, oldDate);
			} catch {
				// utimes may be a no-op under minimal in-memory FS shims
			}
			holderEntered();
			await holderGate;
			activeOwners -= 1;
			return "holder-done";
		});

		await enteredPromise;

		// Contender tries to acquire while live holder's lock is >30s old; fake Date.now past 5s deadline right after first EEXIST sleep
		const realNow = Date.now;
		let nowOffset = 0;
		Date.now = () => realNow() + nowOffset;
		try {
			const timer = setTimeout(() => {
				nowOffset = 6_000;
			}, 40);
			await assert.rejects(
				() =>
					withLedgerLock(liveDir, async () => {
						activeOwners += 1;
						maxSimultaneousOwners = Math.max(maxSimultaneousOwners, activeOwners);
						activeOwners -= 1;
					}),
				/Timed out acquiring cache-lens ledger lock/,
			);
			clearTimeout(timer);
		} finally {
			Date.now = realNow;
		}
		assert.equal(maxSimultaneousOwners, 1);
		releaseHolder();
		assert.equal(await holderTask, "holder-done");

		// 2. Dead PID lock on same host IS reclaimed promptly!
		const deadDir = path.join(tmpDir, "dead-lock");
		const deadLockPath = path.join(deadDir, ".ledger.lock");
		await fs.mkdir(deadLockPath, { recursive: true });
		await fs.writeFile(
			path.join(deadLockPath, "owner.json"),
			JSON.stringify({
				token: "dead-token-1",
				pid: 2_147_483_640,
				host: os.hostname(),
				acquiredAtMs: Date.now() - 20_000,
			}),
			"utf8",
		);
		const reclaimed = await withLedgerLock(deadDir, async () => "reclaimed-ok");
		assert.equal(reclaimed, "reclaimed-ok");

		// 3. Rotation rename failure (when `${eventsFile}.1` is a directory so rename fails) MUST propagate instead of being swallowed!
		const rotFailDir = path.join(tmpDir, "rot-fail");
		await fs.mkdir(path.join(rotFailDir, "events.jsonl.1"), { recursive: true });
		await fs.writeFile(path.join(rotFailDir, "events.jsonl"), `${"x".repeat(500)}\n`, "utf8");
		const sampleRec: TurnCacheRecord = {
			ts: new Date().toISOString(),
			sessionId: "s1",
			cwd: "/tmp",
			provider: "openai",
			requestedModel: "gpt-5.4",
			model: "gpt-5.4",
			api: "openai-responses",
			thinkingLevel: "high",
			providerThinkingLevel: "high",
			callIndex: 1,
			idleSec: null,
			input: 2000,
			cacheRead: 0,
			cacheWrite: 0,
			output: 10,
			promptTotal: 2000,
			singleHitPct: 0,
			sessionHitPct: 0,
			sessionPromptTotal: 2000,
			sessionCacheRead: 0,
			costUsd: 0.01,
			systemHash: "aaa",
			systemBytes: 10,
			toolsHash: "bbb",
			toolsBytes: 10,
			itemCount: 1,
			firstDivergedItemIdx: null,
			promptCacheKey: "s1",
			hasCacheControl: false,
			observedChanges: [],
			diagnosis: "cold_start",
			anomaly: false,
			shortTag: "cold",
			detail: "cold",
		};
		await assert.rejects(() => persistRecord(sampleRec, rotFailDir, 100, "en"));

		// 4. Snapshot-consistent read across active + .1 never duplicates records [1, 2, 1, 2]!
		const snapDir = path.join(tmpDir, "snap");
		await fs.mkdir(snapDir, { recursive: true });
		const snapFile = path.join(snapDir, "anomalies.jsonl");
		const r1 = JSON.stringify({ ...sampleRec, callIndex: 1 });
		const r2 = JSON.stringify({ ...sampleRec, callIndex: 2 });
		const r3 = JSON.stringify({ ...sampleRec, callIndex: 3 });
		await fs.writeFile(`${snapFile}.1`, `${r1}\n${r2}\n`, "utf8");
		await fs.writeFile(snapFile, `${r3}\n`, "utf8");
		const snap = await readRecentJsonlUnlocked(snapFile, 10);
		assert.deepEqual(
			snap.map((r) => r.callIndex),
			[1, 2, 3],
		);
	} finally {
		await fs.rm(tmpDir, { recursive: true, force: true });
	}
});

test("real mounted @earendil-works/pi-ai v1.4.0 builders (Anthropic strict fallback with inline tools & OpenAI Responses prompt_cache_options 30m) integrate end-to-end", async () => {
	let anthropicMod: any = null;
	let responsesMod: any = null;
	try {
		anthropicMod = await import(
			"/opt/homebrew/lib/node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-ai/dist/api/anthropic-messages.js"
		);
		responsesMod = await import(
			"/opt/homebrew/lib/node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-ai/dist/api/openai-responses.js"
		);
	} catch {
		// Standalone environment without host pi installation; covered by unit fixtures above.
		return;
	}

	const tmpDir = await makeTempDir("cache-lens-realbuilder-");
	const prevEnv = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = tmpDir;
	const realNow = Date.now;
	let fakeNow = 1_700_200_000_000;
	Date.now = () => fakeNow;

	try {
		await fs.writeFile(path.join(tmpDir, "cache-lens.json"), JSON.stringify({ locale: "en" }), "utf8");
		const h = createHarness();
		cacheLensExtension(h.pi);
		await h.emit("session_start", { reason: "startup" });

		// 1. Real Anthropic builder with supportsStrictTools + native inline tool changes + 400 strict fallback!
		const anthModel = {
			id: "claude-opus-4-7",
			name: "Claude Opus 4.7",
			api: "anthropic-messages",
			provider: "anthropic",
			baseUrl: "https://api.anthropic.com",
			reasoning: true,
			input: ["text"],
			cost: { input: 15, output: 75, cacheRead: 1.5, cacheWrite: 18.75 },
			contextWindow: 200000,
			maxTokens: 16384,
			compat: {
				supportsStrictTools: true,
				supportsMidConvoSystemMessages: true,
				supportsMidConvoToolChanges: true,
				supportsMidConvoEffort: true,
				forceAdaptiveThinking: true,
			},
		};
		const mkTool = (name: string) => ({
			name,
			description: `Tool ${name}`,
			constrainedSampling: { type: "json_schema", strict: "prefer" },
			parameters: {
				type: "object",
				properties: {
					target: { type: "string" },
					maxDepth: { type: "number" },
					required: { type: "boolean" },
				},
				required: ["target"],
			},
		});
		const anthContext = {
			messages: [
				{ role: "system", content: "Static prompt", toolsAdded: [mkTool("initial_scan")], timestamp: fakeNow },
				{ role: "user", content: "scan repo", timestamp: fakeNow },
				{ role: "system", content: "", toolsAdded: [mkTool("inline_added_tool")], timestamp: fakeNow },
				{
					role: "assistant",
					api: "anthropic-messages",
					provider: "anthropic",
					model: "claude-opus-4-7",
					providerThinkingLevel: "high",
					content: [{ type: "text", text: "scanning" }],
					timestamp: fakeNow,
				},
				{ role: "user", content: "continue", timestamp: fakeNow },
			],
		};

		const sseOk = [
			`event: message_start\ndata: ${JSON.stringify({
				type: "message_start",
				message: {
					id: "msg_1",
					type: "message",
					role: "assistant",
					model: "claude-opus-4-7",
					content: [],
					stop_reason: null,
					usage: { input_tokens: 4000, output_tokens: 1, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 },
				},
			})}\n\n`,
			`event: content_block_start\ndata: ${JSON.stringify({
				type: "content_block_start",
				index: 0,
				content_block: { type: "text", text: "" },
			})}\n\n`,
			`event: content_block_delta\ndata: ${JSON.stringify({
				type: "content_block_delta",
				index: 0,
				delta: { type: "text_delta", text: "ok" },
			})}\n\n`,
			`event: content_block_stop\ndata: ${JSON.stringify({ type: "content_block_stop", index: 0 })}\n\n`,
			`event: message_delta\ndata: ${JSON.stringify({
				type: "message_delta",
				delta: { stop_reason: "end_turn", stop_sequence: null },
				usage: { output_tokens: 5 },
			})}\n\n`,
			`event: message_stop\ndata: ${JSON.stringify({ type: "message_stop" })}\n\n`,
		].join("");

		// Turn 1: strict succeeds directly (95% cache hit)
		const sseHit = sseOk.replace('"input_tokens":4000,"output_tokens":1,"cache_read_input_tokens":0', '"input_tokens":200,"output_tokens":1,"cache_read_input_tokens":3800');
		await h.emit("turn_start", {});
		const s1 = anthropicMod.stream(anthModel, anthContext, {
			apiKey: "sk-ant-api03-testkey",
			sessionId: "sess-real",
			onPayload: async (payload: any) => {
				await h.emit("before_provider_request", { payload });
				return undefined;
			},
			onResponse: async (res: any) => {
				await h.emit("after_provider_response", res);
			},
			fetch: async () =>
				new Response(sseHit, {
					status: 200,
					headers: { "content-type": "text/event-stream" },
				}),
		});
		const msg1 = await s1.result();
		await h.emit("message_end", { message: msg1 });

		// Turn 2: first fetch returns 400 "Too many strict tools (", triggering real anthropic_strict_tools_fallback!
		fakeNow += 5_000;
		let fetchCalls = 0;
		await h.emit("turn_start", {});
		const s2 = anthropicMod.stream(anthModel, anthContext, {
			apiKey: "sk-ant-api03-testkey",
			sessionId: "sess-real",
			onPayload: async (payload: any) => {
				await h.emit("before_provider_request", { payload });
				return undefined;
			},
			onResponse: async (res: any) => {
				await h.emit("after_provider_response", res);
			},
			fetch: async () => {
				fetchCalls += 1;
				if (fetchCalls === 1) {
					return new Response(
						JSON.stringify({
							type: "error",
							error: { type: "invalid_request_error", message: "Too many strict tools (25 > 20)" },
						}),
						{ status: 400, headers: { "content-type": "application/json" } },
					);
				}
				return new Response(sseOk, {
					status: 200,
					headers: { "content-type": "text/event-stream" },
				});
			},
		});
		const msg2 = await s2.result();
		assert.equal(fetchCalls, 2);
		await h.emit("message_end", { message: msg2 });

		// 2. Real OpenAI Responses builder with supportsExplicitPromptCacheMode: true & cacheRetention: "long" -> prompt_cache_options: { ttl: "30m" }
		const respModel = {
			id: "gpt-5.4",
			name: "GPT-5.4",
			api: "openai-responses",
			provider: "openai",
			baseUrl: "https://api.openai.com/v1",
			reasoning: false,
			input: ["text"],
			cost: { input: 2.5, output: 10, cacheRead: 0.25, cacheWrite: 0 },
			contextWindow: 272000,
			maxTokens: 16384,
			compat: {
				supportsExplicitPromptCacheMode: true,
				supportsLongCacheRetention: true,
			},
		};
		const capturedPayloads: any[] = [];
		const respSse = [
			`event: response.completed\ndata: ${JSON.stringify({
				type: "response.completed",
				response: {
					id: "resp_1",
					status: "completed",
					output: [{ type: "message", role: "assistant", content: [{ type: "output_text", text: "done" }] }],
					usage: { input_tokens: 4000, output_tokens: 10, total_tokens: 4010, input_tokens_details: { cached_tokens: 0 } },
				},
			})}\n\n`,
		].join("");

		const rs = responsesMod.stream(
			respModel,
			{
				messages: [
					{ role: "system", content: "Responses prompt", timestamp: fakeNow },
					{ role: "user", content: "hello", timestamp: fakeNow },
				],
			},
			{
				apiKey: "sk-proj-testkey123456",
				sessionId: "sess-resp",
				cacheRetention: "long",
				onPayload: async (payload: any) => {
					capturedPayloads.push(payload);
					return undefined;
				},
				fetch: async () =>
					new Response(respSse, {
						status: 200,
						headers: { "content-type": "text/event-stream" },
					}),
			},
		);
		await rs.result();
		assert.equal(capturedPayloads.length, 1);
		const fpResp = extractWireFingerprint(capturedPayloads[0])!;
		assert.equal(fpResp.retentionState, "explicit_ttl");
		assert.equal(fpResp.retentionTtlSec, 1800);

		await h.emit("session_shutdown", {});
		const events = await readRecentJsonl(path.join(tmpDir, "cache-lens", "events.jsonl"), 10);
		assert.equal(events.length, 2);
		assert.equal(events[1]!.diagnosis, "provider_strict_fallback");
		assert.equal(events[1]!.shortTag, "!strict");
	} finally {
		Date.now = realNow;
		if (prevEnv === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = prevEnv;
		await fs.rm(tmpDir, { recursive: true, force: true });
	}
});

test("Round 3 attribution invariants: unknown retention after short->none, cross-model baseline isolation, ambiguous single-capture multi-response prefill, fallback-to-fallback nullable requiredness, and touch-associated retention transitions", async () => {
	const tmpDir = await makeTempDir("cache-lens-r3-attr-");
	const prevEnv = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = tmpDir;
	const realNow = Date.now;
	let fakeNow = 1_700_300_000_000;
	Date.now = () => fakeNow;

	try {
		await fs.writeFile(
			path.join(tmpDir, "cache-lens.json"),
			JSON.stringify({ locale: "en", ttlThresholdSec: 290 }),
			"utf8",
		);

		// R3-#1: Switching Anthropic cacheRetention from "short" (has cache_control) to "none" (unknown retention,
		// identical normalized prefix) and missing 5s later MUST withhold provider_miss_or_routing!
		const wAnthShort = extractWireFingerprint({
			model: "claude-sonnet-4-6",
			system: [{ type: "text", text: "Static prompt", cache_control: { type: "ephemeral" } }],
			tools: [],
			messages: [{ role: "user", content: [{ type: "text", text: "hello", cache_control: { type: "ephemeral" } }] }],
		})!;
		const wAnthNone = extractWireFingerprint({
			model: "claude-sonnet-4-6",
			system: [{ type: "text", text: "Static prompt" }],
			tools: [],
			messages: [
				{ role: "user", content: "hello" },
				{ role: "user", content: "follow up" },
			],
		})!;
		assert.equal(wAnthShort.retentionState, "short_default");
		assert.equal(wAnthNone.retentionState, "unknown");
		assert.equal(wAnthShort.systemHash, wAnthNone.systemHash);
		assert.equal(wAnthShort.itemHashes[0], wAnthNone.itemHashes[0]);

		const r3_1 = classifyTurn({
			callIndex: 2,
			modelKey: "anthropic/claude-sonnet-4-6",
			prevModelKey: "anthropic/claude-sonnet-4-6",
			promptTotal: 4000,
			cacheRead: 0,
			prevSingleHitPct: 95,
			idleSec: 5,
			prevWire: wAnthShort,
			currWire: wAnthNone,
			priorTouchTtlSec: 290,
			ttlThresholdSec: 290,
			minCacheableTokens: 1024,
			locale: "en",
		});
		assert.equal(r3_1.diagnosis, "insufficient_evidence");
		assert.notEqual(r3_1.diagnosis, "provider_miss_or_routing");

		// R3-#7: Nullable property `p: { anyOf: [string, null] }` changing `required: [] -> ["p"]` when BOTH turns
		// take non-strict fallback MUST report `tools_mutated` (never masked as `provider_strict_fallback`)!
		const makeFallbackNullablePayload = (reqList: string[]) => ({
			model: "claude-opus-4-7",
			system: "sys",
			tools: [
				{
					name: "nullable_tool",
					description: "Non-strict fallback schema",
					input_schema: {
						type: "object",
						properties: {
							p: { anyOf: [{ type: "string" }, { type: "null" }] },
						},
						required: reqList,
					},
				},
			],
			messages: [{ role: "user", content: "hi" }],
		});
		const wNullableOpt = extractWireFingerprint(makeFallbackNullablePayload([]))!;
		const wNullableReq = extractWireFingerprint(makeFallbackNullablePayload(["p"]))!;
		assert.equal(wNullableOpt.logicalToolsHash, wNullableReq.logicalToolsHash);
		assert.notEqual(wNullableOpt.toolsHash, wNullableReq.toolsHash);
		assert.equal(isStrictToolsRepresentationTransition(wNullableOpt.tools, wNullableReq.tools, false), false);

		const r3_7 = classifyTurn({
			callIndex: 3,
			modelKey: "anthropic/claude-opus-4-7",
			prevModelKey: "anthropic/claude-opus-4-7",
			promptTotal: 6000,
			cacheRead: 0,
			prevSingleHitPct: 95,
			idleSec: 4,
			prevWire: wNullableOpt,
			currWire: wNullableReq,
			priorTouchTtlSec: null,
			strictToolsFallback: true,
			ttlThresholdSec: 290,
			minCacheableTokens: 1024,
			locale: "en",
		});
		assert.equal(r3_7.diagnosis, "tools_mutated");

		// R3-#8: Retention associated with the cache touch being evaluated:
		// 1) short (290s) -> 600s idle -> long (3600s) => expired against 290s (`ttl_expired_likely`, NOT `!route`).
		// 2) long (3600s) -> 600s idle -> short (290s) => NOT expired against 3600s, retention changed => `insufficient_evidence`.
		const wLong1h = extractWireFingerprint({
			model: "claude-sonnet-4-6",
			system: [{ type: "text", text: "Static prompt", cache_control: { type: "ephemeral", ttl: "1h" } }],
			tools: [],
			messages: [{ role: "user", content: [{ type: "text", text: "hello", cache_control: { type: "ephemeral", ttl: "1h" } }] }],
		})!;
		assert.equal(wLong1h.retentionTtlSec, 3600);

		const shortToLong600 = classifyTurn({
			callIndex: 2,
			modelKey: "anthropic/claude-sonnet-4-6",
			prevModelKey: "anthropic/claude-sonnet-4-6",
			promptTotal: 5000,
			cacheRead: 0,
			prevSingleHitPct: 95,
			idleSec: 600,
			prevWire: wAnthShort,
			currWire: wLong1h,
			priorTouchTtlSec: 290,
			effectiveTtlSec: 3600,
			ttlThresholdSec: 290,
			minCacheableTokens: 1024,
			locale: "en",
		});
		assert.equal(shortToLong600.diagnosis, "ttl_expired_likely");

		const longToShort600 = classifyTurn({
			callIndex: 2,
			modelKey: "anthropic/claude-sonnet-4-6",
			prevModelKey: "anthropic/claude-sonnet-4-6",
			promptTotal: 5000,
			cacheRead: 0,
			prevSingleHitPct: 95,
			idleSec: 600,
			prevWire: wLong1h,
			currWire: wAnthShort,
			priorTouchTtlSec: 3600,
			effectiveTtlSec: 290,
			ttlThresholdSec: 290,
			minCacheableTokens: 1024,
			locale: "en",
		});
		assert.equal(longToShort600.diagnosis, "insufficient_evidence");

		// R3-#2 & R3-#6 end-to-end through cacheLensExtension:
		const h = createHarness();
		cacheLensExtension(h.pi);
		await h.emit("session_start", { reason: "startup" });

		// Turn 1: Model A / System A hits unambiguously.
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", {
			payload: {
				model: "claude-opus-4-7",
				system: [{ type: "text", text: "System A", cache_control: { type: "ephemeral" } }],
				tools: [],
				messages: [{ role: "user", content: "q1" }],
			},
		});
		await h.emit("after_provider_response", { status: 200, headers: {} });
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-opus-4-7",
				api: "anthropic-messages",
				usage: { input: 200, cacheRead: 3800, cacheWrite: 0, output: 20 },
			},
		});

		// Turn 2 (R3-#2): Model B / System B ambiguous turn hits (2 differing captures).
		fakeNow += 5_000;
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", {
			payload: {
				model: "claude-sonnet-4-6",
				system: [{ type: "text", text: "System B", cache_control: { type: "ephemeral" } }],
				tools: [],
				messages: [{ role: "user", content: "q1" }, { role: "user", content: "q2" }],
			},
		});
		await h.emit("before_provider_request", {
			payload: {
				model: "claude-sonnet-4-6",
				max_tokens: 1,
				system: [{ type: "text", text: "System B", cache_control: { type: "ephemeral" } }],
				tools: [],
				messages: [{ role: "user", content: "q1" }],
			},
		});
		await h.emit("after_provider_response", { status: 200, headers: {} });
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-sonnet-4-6",
				api: "anthropic-messages",
				usage: { input: 200, cacheRead: 3800, cacheWrite: 0, output: 20 },
			},
		});

		// Turn 3 (R3-#2): Model B / System B unambiguous turn misses -> MUST NOT compare against Model A's snapshot (`system_mutated`)!
		fakeNow += 5_000;
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", {
			payload: {
				model: "claude-sonnet-4-6",
				system: [{ type: "text", text: "System B", cache_control: { type: "ephemeral" } }],
				tools: [],
				messages: [{ role: "user", content: "q1" }, { role: "user", content: "q2" }, { role: "user", content: "q3" }],
			},
		});
		await h.emit("after_provider_response", { status: 200, headers: {} });
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-sonnet-4-6",
				api: "anthropic-messages",
				usage: { input: 4000, cacheRead: 0, cacheWrite: 0, output: 20 },
			},
		});

		// Turn 4 (R3-#6): Warmer dispatched BEFORE turn_start delivers late 200 response during a 400s foreground prefill
		// (leaving 1 capture + 2 ok responses).
		fakeNow += 5_000;
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", {
			payload: {
				model: "claude-sonnet-4-6",
				system: [{ type: "text", text: "System B", cache_control: { type: "ephemeral" } }],
				tools: [],
				messages: [
					{ role: "user", content: "q1" },
					{ role: "user", content: "q2" },
					{ role: "user", content: "q3" },
					{ role: "user", content: "q4" },
				],
			},
		});
		// Late response #1 from pre-turn_start warmer:
		fakeNow += 1_000;
		await h.emit("after_provider_response", { status: 200, headers: {} });
		// Foreground prefill finishes 400s after dispatch (response #2):
		fakeNow += 399_000;
		await h.emit("after_provider_response", { status: 200, headers: {} });
		await h.emit("message_start", { message: { role: "assistant" } });
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-sonnet-4-6",
				api: "anthropic-messages",
				usage: { input: 200, cacheRead: 3800, cacheWrite: 0, output: 20 },
			},
		});

		// Turn 5 (R3-#6): 1 second after Turn 4 prefill completed, foreground misses -> MUST NOT report 401s `ttl_expired_likely`!
		fakeNow += 1_000;
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", {
			payload: {
				model: "claude-sonnet-4-6",
				system: [{ type: "text", text: "System B", cache_control: { type: "ephemeral" } }],
				tools: [],
				messages: [
					{ role: "user", content: "q1" },
					{ role: "user", content: "q2" },
					{ role: "user", content: "q3" },
					{ role: "user", content: "q4" },
					{ role: "user", content: "q5" },
				],
			},
		});
		await h.emit("after_provider_response", { status: 200, headers: {} });
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-sonnet-4-6",
				api: "anthropic-messages",
				usage: { input: 4200, cacheRead: 0, cacheWrite: 0, output: 20 },
			},
		});

		await h.emit("session_shutdown", {});
		const events = await readRecentJsonl(path.join(tmpDir, "cache-lens", "events.jsonl"), 10);
		assert.equal(events.length, 5);
		assert.notEqual(events[2]!.diagnosis, "system_mutated");
		assert.equal(events[2]!.diagnosis, "insufficient_evidence");
		assert.notEqual(events[4]!.diagnosis, "ttl_expired_likely");
		assert.equal(events[4]!.diagnosis, "insufficient_evidence");
		assert.equal(events[4]!.idleSec, null);
	} finally {
		Date.now = realNow;
		if (prevEnv === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = prevEnv;
		await fs.rm(tmpDir, { recursive: true, force: true });
	}
});

test("Round 3 ledger concurrency & fault recovery: concurrent stale-lock reclaimers, release failure surfacing + live-PID recovery, and exhausted rotation-retry consistency", async () => {
	const { createRequire, syncBuiltinESMExports } = await import("node:module");
	const req = createRequire(import.meta.url);
	const cjsFs = req("node:fs/promises") as typeof import("node:fs/promises");

	const tmpDir = await makeTempDir("cache-lens-r3-lock-");
	try {
		// 1. R3-#3: Eight concurrent contenders racing to reclaim the same dead-PID lock MUST serialize
		// reclamation + acquisition so maxSimultaneousOwners never exceeds 1.
		const raceDir = path.join(tmpDir, "reclaim-race");
		const raceLockPath = path.join(raceDir, ".ledger.lock");
		await fs.mkdir(raceLockPath, { recursive: true });
		await fs.writeFile(
			path.join(raceLockPath, "owner.json"),
			JSON.stringify({
				token: "dead-owner-race-token",
				pid: 2_147_483_641,
				host: os.hostname(),
				acquiredAtMs: Date.now() - 25_000,
			}),
			"utf8",
		);

		let active = 0;
		let maxSimultaneous = 0;
		const results = await Promise.all(
			Array.from({ length: 8 }, (_, idx) =>
				withLedgerLock(raceDir, async () => {
					active += 1;
					maxSimultaneous = Math.max(maxSimultaneous, active);
					await new Promise((r) => setTimeout(r, 8));
					active -= 1;
					return idx;
				}),
			),
		);
		assert.equal(results.length, 8);
		assert.equal(maxSimultaneous, 1);

		// Deterministic interleaving: force two contenders to BOTH inspect the dead owner.json before either
		// enters reclamation, then hold contender 1 in the critical section while contender 2 attempts acquisition.
		const detDir = path.join(tmpDir, "det-reclaim-race");
		const detLockPath = path.join(detDir, ".ledger.lock");
		const detOwnerFile = path.join(detLockPath, "owner.json");
		await fs.mkdir(detLockPath, { recursive: true });
		await fs.writeFile(
			detOwnerFile,
			JSON.stringify({
				token: "dead-det-token",
				pid: 2_147_483_642,
				host: os.hostname(),
				acquiredAtMs: Date.now() - 25_000,
			}),
			"utf8",
		);

		const origReadForDet = cjsFs.readFile;
		let initialOwnerReads = 0;
		let releaseBothInspectors!: () => void;
		const bothInspected = new Promise<void>((resolve) => {
			releaseBothInspectors = resolve;
		});
		let detActive = 0;
		let detMaxSimultaneous = 0;
		try {
			cjsFs.readFile = (async (target: any, options?: any) => {
				const out = await origReadForDet.call(cjsFs, target, options);
				if (String(target) === detOwnerFile && initialOwnerReads < 2) {
					initialOwnerReads += 1;
					if (initialOwnerReads === 2) {
						releaseBothInspectors();
					}
					await bothInspected;
				}
				return out;
			}) as typeof cjsFs.readFile;
			syncBuiltinESMExports();

			await Promise.all([
				withLedgerLock(detDir, async () => {
					detActive += 1;
					detMaxSimultaneous = Math.max(detMaxSimultaneous, detActive);
					await new Promise((r) => setTimeout(r, 40));
					detActive -= 1;
				}),
				withLedgerLock(detDir, async () => {
					detActive += 1;
					detMaxSimultaneous = Math.max(detMaxSimultaneous, detActive);
					await new Promise((r) => setTimeout(r, 40));
					detActive -= 1;
				}),
			]);
		} finally {
			cjsFs.readFile = origReadForDet;
			syncBuiltinESMExports();
		}
		assert.equal(detMaxSimultaneous, 1);

		// 2. R3-#4: Injecting rm failure on lock release MUST surface the error rather than swallowing it,
		// AND after filesystem recovery a subsequent write in the same live PID MUST reclaim the inactive token!
		const releaseDir = path.join(tmpDir, "release-fail");
		const releaseLockPath = path.join(releaseDir, ".ledger.lock");
		const origRm = cjsFs.rm;
		let failLockRm = true;
		try {
			cjsFs.rm = (async (target: any, options?: any) => {
				if (failLockRm && String(target) === releaseLockPath) {
					const err: any = new Error("injected EIO on lock release");
					err.code = "EIO";
					throw err;
				}
				return await origRm.call(cjsFs, target, options);
			}) as typeof cjsFs.rm;
			syncBuiltinESMExports();

			await assert.rejects(
				() => withLedgerLock(releaseDir, async () => "critical-section-ok"),
				/injected EIO on lock release/,
			);
		} finally {
			failLockRm = false;
			cjsFs.rm = origRm;
			syncBuiltinESMExports();
		}

		// Filesystem recovered, our PID is still alive, and `.ledger.lock` was left behind:
		// next acquisition MUST reclaim the inactive token promptly without timing out!
		const recovered = await withLedgerLock(releaseDir, async () => "recovered-after-rm-failure");
		assert.equal(recovered, "recovered-after-rm-failure");

		// 3. R3-#5: Exhausting all rotation retries in readRecentJsonlUnlocked MUST return an independently
		// valid single-file snapshot rather than merging an inconsistent [rotated, active] pair ([3, 3]).
		const rotDir = path.join(tmpDir, "exhausted-rot");
		await fs.mkdir(rotDir, { recursive: true });
		const rotFile = path.join(rotDir, "anomalies.jsonl");
		const mkLine = (callIndex: number) =>
			`${JSON.stringify({
				ts: new Date().toISOString(),
				sessionId: "s",
				cwd: "/tmp",
				provider: "openai",
				requestedModel: "gpt-5.4",
				model: "gpt-5.4",
				api: "openai-responses",
				thinkingLevel: "high",
				providerThinkingLevel: "high",
				callIndex,
				idleSec: 1,
				input: 2000,
				cacheRead: 0,
				cacheWrite: 0,
				output: 10,
				promptTotal: 2000,
				singleHitPct: 0,
				sessionHitPct: 0,
				sessionPromptTotal: 2000,
				sessionCacheRead: 0,
				costUsd: 0.01,
				systemHash: "aaa",
				systemBytes: 3,
				toolsHash: "bbb",
				toolsBytes: 3,
				itemCount: 1,
				firstDivergedItemIdx: null,
				promptCacheKey: null,
				hasCacheControl: false,
				observedChanges: [],
				diagnosis: "provider_miss_or_routing",
				anomaly: true,
				shortTag: "!route",
				detail: "d",
			})}\n`;

		const origReadFile = cjsFs.readFile;
		let step = 0;
		try {
			cjsFs.readFile = (async (target: any, options?: any) => {
				const p = String(target);
				if (p === rotFile || p === `${rotFile}.1`) {
					// Simulate continuous rotation between active1, rotated, and active2 on every retry attempt:
					// active1 sees record #2, then rotation moves #3 into .1 AND active2 also sees #3!
					const mod = step % 3;
					step += 1;
					if (mod === 0) return mkLine(2) as any;
					return mkLine(3) as any;
				}
				return await origReadFile.call(cjsFs, target, options);
			}) as typeof cjsFs.readFile;
			syncBuiltinESMExports();

			const records = await readRecentJsonlUnlocked(rotFile, 10);
			assert.deepEqual(
				records.map((r) => r.callIndex),
				[3],
			);
		} finally {
			cjsFs.readFile = origReadFile;
			syncBuiltinESMExports();
		}
	} finally {
		await fs.rm(tmpDir, { recursive: true, force: true });
	}
});

test("Round 4 closure: slow initializer vs ownerless stale reclamation fence, all-zero error completion touch invalidation, and API-scoped cache touches", async () => {
	const { createRequire, syncBuiltinESMExports } = await import("node:module");
	const req = createRequire(import.meta.url);
	const cjsFs = req("node:fs/promises") as typeof import("node:fs/promises");

	const tmpDir = await makeTempDir("cache-lens-r4-");
	const prevEnv = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = tmpDir;
	const realNow = Date.now;
	let fakeNow = 1_700_400_000_000;

	try {
		// 1. R4-#1 (Order A & Order B): External/legacy caller creates ownerless `.ledger.lock` via `mkdir` and
		// pauses >15s before publishing `owner.json` via `wx`. Reclaimer 2 inspects the >15s ownerless `.ledger.lock`
		// and acquires the generation reclaim lease; verify both barrier orders ("initializer-wins-fence" and
		// "reclaimer-wins-fence") keep maxSimultaneousOwners strictly equal to 1!
		for (const order of ["initializer-wins-fence", "reclaimer-wins-fence"] as const) {
			const initDir = path.join(tmpDir, `slow-init-${order}`);
			await fs.mkdir(initDir, { recursive: true });
			const initLockPath = path.join(initDir, ".ledger.lock");
			const initOwnerPath = path.join(initLockPath, "owner.json");

			const origRename = cjsFs.rename;
			const origStat = cjsFs.stat;
			const origLink = cjsFs.link;
			const origWriteFile = cjsFs.writeFile;

			let releaseInitializerMkdir!: () => void;
			const initializerMkdirGate = new Promise<void>((resolve) => {
				releaseInitializerMkdir = resolve;
			});
			let notifyMkdirCreated!: () => void;
			const mkdirCreated = new Promise<void>((resolve) => {
				notifyMkdirCreated = resolve;
			});

			let reclaimLeasePublished = false;
			let triggeredBarrier = false;
			let releaseReclaimerBeforeFence!: () => void;
			const reclaimerBeforeFenceGate = new Promise<void>((resolve) => {
				releaseReclaimerBeforeFence = resolve;
			});

			let ownerPublished = false;
			let activeOwners = 0;
			let maxSimultaneousOwners = 0;

			Date.now = () => fakeNow;
			try {
				cjsFs.rename = (async (src: any, dst: any) => {
					const res = await origRename.call(cjsFs, src, dst);
					if (String(dst).includes(path.join(initDir, ".ledger.reclaim."))) {
						reclaimLeasePublished = true;
					}
					return res;
				}) as typeof cjsFs.rename;

				cjsFs.stat = (async (target: any, options?: any) => {
					const st: any = await origStat.call(cjsFs, target, options);
					if (String(target) === initLockPath && !ownerPublished) {
						const patched = Object.assign(Object.create(Object.getPrototypeOf(st)), st, {
							mtimeMs: fakeNow - 20_000,
						});
						if (reclaimLeasePublished && !triggeredBarrier) {
							triggeredBarrier = true;
							if (order === "initializer-wins-fence") {
								releaseInitializerMkdir();
								await reclaimerBeforeFenceGate;
							}
						}
						return patched;
					}
					return st;
				}) as typeof cjsFs.stat;

				cjsFs.link = (async (existingPath: any, newPath: any) => {
					const res = await origLink.call(cjsFs, existingPath, newPath);
					if (String(newPath) === initOwnerPath && order === "reclaimer-wins-fence") {
						ownerPublished = true;
						releaseInitializerMkdir();
					}
					return res;
				}) as typeof cjsFs.link;

				cjsFs.writeFile = (async (target: any, data: any, options?: any) => {
					const res = await origWriteFile.call(cjsFs, target, data, options);
					if (String(target) === initOwnerPath) {
						const parsed = JSON.parse(String(data));
						if (order === "initializer-wins-fence" && !String(parsed.token).startsWith("fence-")) {
							ownerPublished = true;
							releaseReclaimerBeforeFence();
						}
						if (order === "reclaimer-wins-fence" && String(parsed.token).startsWith("fence-")) {
							ownerPublished = true;
							releaseInitializerMkdir();
						}
					}
					return res;
				}) as typeof cjsFs.writeFile;

				syncBuiltinESMExports();

				const externalSlowInitializer = (async () => {
					await fs.mkdir(initLockPath);
					const oldDate = new Date(fakeNow - 20_000);
					await fs.utimes(initLockPath, oldDate, oldDate).catch(() => {});
					notifyMkdirCreated();
					await initializerMkdirGate;

					const extToken = `legacy-ext-${order}`;
					const liveExternalPid = process.ppid > 0 && process.ppid !== process.pid ? process.ppid : 1;
					try {
						await fs.writeFile(
							initOwnerPath,
							JSON.stringify({
								token: extToken,
								pid: liveExternalPid,
								host: os.hostname(),
								acquiredAtMs: fakeNow,
							}),
							{ encoding: "utf8", flag: "wx" },
						);
						// Note: cross-process external writer has a live PID; simulate live holder by holding critical section
						// and keeping mtime fresh once owner.json is published, then removing lock on release.
						activeOwners += 1;
						maxSimultaneousOwners = Math.max(maxSimultaneousOwners, activeOwners);
						await new Promise((r) => setTimeout(r, 35));
						activeOwners -= 1;
						await fs.rm(initLockPath, { recursive: true, force: true });
						return "w1";
					} catch (err: any) {
						if (err?.code === "EEXIST" || err?.code === "ENOENT") {
							return await withLedgerLock(initDir, async () => {
								activeOwners += 1;
								maxSimultaneousOwners = Math.max(maxSimultaneousOwners, activeOwners);
								await new Promise((r) => setTimeout(r, 35));
								activeOwners -= 1;
								return "w1";
							});
						}
						throw err;
					}
				})();

				await mkdirCreated;

				const reclaimer2 = withLedgerLock(initDir, async () => {
					activeOwners += 1;
					maxSimultaneousOwners = Math.max(maxSimultaneousOwners, activeOwners);
					await new Promise((r) => setTimeout(r, 35));
					activeOwners -= 1;
					return "r2";
				});

				const [o1, o2] = await Promise.all([externalSlowInitializer, reclaimer2]);
				assert.equal(o1, "w1");
				assert.equal(o2, "r2");
				assert.equal(maxSimultaneousOwners, 1, `simultaneous owners > 1 for ${order}`);
			} finally {
				Date.now = realNow;
				cjsFs.rename = origRename;
				cjsFs.stat = origStat;
				cjsFs.link = origLink;
				cjsFs.writeFile = origWriteFile;
				syncBuiltinESMExports();
			}
		}

		// 2. R4-#2 & R4-#3 end-to-end through cacheLensExtension:
		Date.now = () => fakeNow;
		await fs.writeFile(
			path.join(tmpDir, "cache-lens.json"),
			JSON.stringify({ locale: "en", ttlThresholdSec: 290 }),
			"utf8",
		);
		const h = createHarness();
		cacheLensExtension(h.pi);
		await h.emit("session_start", { reason: "startup" });

		const mkAnthropicPayload = (sys: string, msgs: string[]) => ({
			model: "claude-sonnet-4-6",
			system: [{ type: "text", text: sys, cache_control: { type: "ephemeral" } }],
			tools: [],
			messages: msgs.map((m, idx) =>
				idx === msgs.length - 1
					? { role: "user", content: [{ type: "text", text: m, cache_control: { type: "ephemeral" } }] }
					: { role: "user", content: m },
			),
		});

		// Turn 1 (t=0): healthy hit on anthropic-messages.
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", { payload: mkAnthropicPayload("sys-stable", ["m1"]) });
		await h.emit("after_provider_response", { status: 200, headers: {} });
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-sonnet-4-6",
				api: "anthropic-messages",
				usage: { input: 100, cacheRead: 3900, cacheWrite: 0, output: 20 },
			},
		});

		// Turn 2 (t=1000s, R4-#2): 1 foreground capture + 2 overlapping 200 responses, then response body fails with ALL-ZERO usage!
		fakeNow += 1_000_000;
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", { payload: mkAnthropicPayload("sys-stable", ["m1", "m2"]) });
		await h.emit("after_provider_response", { status: 200, headers: {} });
		await h.emit("after_provider_response", { status: 200, headers: {} });
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-sonnet-4-6",
				api: "anthropic-messages",
				stopReason: "error",
				errorMessage: "stream terminated mid-body",
				usage: { input: 0, cacheRead: 0, cacheWrite: 0, output: 0, cost: { total: 0 } },
			},
		});

		// Turn 3 (t=1001s, 1s later, R4-#2): miss on unchanged prefix MUST NOT report idleSec=1001 / ttl_expired_likely!
		fakeNow += 1_000;
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", { payload: mkAnthropicPayload("sys-stable", ["m1", "m2"]) });
		await h.emit("after_provider_response", { status: 200, headers: {} });
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-sonnet-4-6",
				api: "anthropic-messages",
				usage: { input: 4000, cacheRead: 0, cacheWrite: 0, output: 20 },
			},
		});

		// Turn 4 (t=1601s, 600s later, R4-#3): same provider/model ("anthropic/claude-sonnet-4-6") switches API from
		// "anthropic-messages" to "openai-completions" (carrying cache_control so currTtlSec=290) and misses ->
		// MUST withhold inherited TTL evidence (idleSec=null, insufficient_evidence, NEVER ttl_expired_likely)!
		fakeNow += 600_000;
		await h.emit("turn_start", {});
		await h.emit("before_provider_request", {
			payload: {
				model: "claude-sonnet-4-6",
				messages: [
					{ role: "system", content: [{ type: "text", text: "sys-stable", cache_control: { type: "ephemeral" } }] },
					{ role: "user", content: [{ type: "text", text: "m1", cache_control: { type: "ephemeral" } }] },
				],
			},
		});
		await h.emit("after_provider_response", { status: 200, headers: {} });
		await h.emit("message_end", {
			message: {
				role: "assistant",
				provider: "anthropic",
				model: "claude-sonnet-4-6",
				api: "openai-completions",
				usage: { input: 4000, cacheRead: 0, cacheWrite: 0, output: 20 },
			},
		});

		// Direct classifyTurn check (R4-#3): !comparableWire precedes TTL branch even if idleSec & priorTouchTtlSec are non-null!
		const wComp = extractWireFingerprint(mkAnthropicPayload("sys-stable", ["m1"]))!;
		const nonComparableTtl = classifyTurn({
			callIndex: 2,
			modelKey: "anthropic/claude-sonnet-4-6",
			prevModelKey: "anthropic/claude-sonnet-4-6",
			promptTotal: 4000,
			cacheRead: 0,
			prevSingleHitPct: 95,
			idleSec: 600,
			prevWire: null,
			currWire: wComp,
			priorTouchTtlSec: 290,
			effectiveTtlSec: 290,
			ttlThresholdSec: 290,
			minCacheableTokens: 1024,
			locale: "en",
		});
		assert.equal(nonComparableTtl.diagnosis, "insufficient_evidence");

		await h.emit("session_shutdown", {});
		const events = await readRecentJsonl(path.join(tmpDir, "cache-lens", "events.jsonl"), 10);
		assert.equal(events.length, 3);
		// Turn 3 (events[1]): after all-zero error completion on ambiguous Turn 2 -> idleSec=null, insufficient_evidence
		assert.equal(events[1]!.idleSec, null);
		assert.notEqual(events[1]!.diagnosis, "ttl_expired_likely");
		assert.equal(events[1]!.diagnosis, "insufficient_evidence");
		// Turn 4 (events[2]): after switching API to openai-completions -> idleSec=null, insufficient_evidence
		assert.equal(events[2]!.api, "openai-completions");
		assert.equal(events[2]!.idleSec, null);
		assert.notEqual(events[2]!.diagnosis, "ttl_expired_likely");
		assert.equal(events[2]!.diagnosis, "insufficient_evidence");
	} finally {
		Date.now = realNow;
		if (prevEnv === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = prevEnv;
		await fs.rm(tmpDir, { recursive: true, force: true });
	}
});

test("Round 5 closure: atomic prepared-directory publication under >15s partial-write pause and detached stale-cleanup EIO isolation", async () => {
	const { createRequire, syncBuiltinESMExports } = await import("node:module");
	const req = createRequire(import.meta.url);
	const cjsFs = req("node:fs/promises") as typeof import("node:fs/promises");

	const tmpDir = await makeTempDir("cache-lens-r5-");
	const realNow = Date.now;
	let fakeNow = 1_700_500_000_000;

	try {
		// 1. R5-#1 (Three-writer partial owner.json publication >15s pause):
		// Writer 1 begins lock acquisition, creates an empty 0-byte `owner.json` (`flag: "wx"`), and pauses >20s
		// before writing its JSON payload. Because publication happens via a private prepared directory,
		// `.ledger.lock` never exposes a partial/empty `owner.json`; Writer 2 acquires `.ledger.lock` cleanly,
		// Writer 1 resumes mid-critical-section while Writer 3 also contends -> maxSimultaneousOwners MUST stay 1!
		const r5aDir = path.join(tmpDir, "partial-owner-pause");
		await fs.mkdir(r5aDir, { recursive: true });
		const r5aLockPath = path.join(r5aDir, ".ledger.lock");

		const origWriteFileA = cjsFs.writeFile;
		let interceptedFirstPrepWrite = false;
		let notifyZeroByteCreated!: () => void;
		const zeroByteCreated = new Promise<void>((resolve) => {
			notifyZeroByteCreated = resolve;
		});
		let releaseWriter1PartialWrite!: () => void;
		const writer1PartialWriteGate = new Promise<void>((resolve) => {
			releaseWriter1PartialWrite = resolve;
		});
		let notifyWriter2InCritA!: () => void;
		const writer2InCritA = new Promise<void>((resolve) => {
			notifyWriter2InCritA = resolve;
		});
		let releaseWriter2CritA!: () => void;
		const writer2CritGateA = new Promise<void>((resolve) => {
			releaseWriter2CritA = resolve;
		});

		let activeA = 0;
		let maxSimultaneousA = 0;

		Date.now = () => fakeNow;
		try {
			cjsFs.writeFile = (async (target: any, data: any, options?: any) => {
				const targetStr = String(target);
				if (
					!interceptedFirstPrepWrite &&
					targetStr.startsWith(`${r5aLockPath}.prep.`) &&
					targetStr.endsWith(`${path.sep}owner.json`)
				) {
					interceptedFirstPrepWrite = true;
					// Step 1 of non-atomic writeFile(..., { flag: "wx" }): create 0-byte file on disk, then pause >20s!
					await origWriteFileA.call(cjsFs, target, "", { encoding: "utf8", flag: "wx" });
					const oldDate = new Date(fakeNow - 25_000);
					await fs.utimes(path.dirname(targetStr), oldDate, oldDate).catch(() => {});
					await fs.utimes(targetStr, oldDate, oldDate).catch(() => {});
					notifyZeroByteCreated();
					await writer1PartialWriteGate;
					// Step 2: finish writing complete JSON contents into the already-created file!
					return await origWriteFileA.call(cjsFs, target, data, "utf8");
				}
				return await origWriteFileA.call(cjsFs, target, data, options);
			}) as typeof cjsFs.writeFile;
			syncBuiltinESMExports();

			const w1 = withLedgerLock(r5aDir, async () => {
				activeA += 1;
				maxSimultaneousA = Math.max(maxSimultaneousA, activeA);
				await new Promise((r) => setTimeout(r, 25));
				activeA -= 1;
				return "w1";
			});

			await zeroByteCreated;
			// While Writer 1 is paused mid-writeFile (>20s stale mtime), `.ledger.lock` MUST NOT exist in partial form!
			await assert.rejects(() => fs.stat(r5aLockPath), { code: "ENOENT" });

			const w2 = withLedgerLock(r5aDir, async () => {
				activeA += 1;
				maxSimultaneousA = Math.max(maxSimultaneousA, activeA);
				notifyWriter2InCritA();
				await writer2CritGateA;
				activeA -= 1;
				return "w2";
			});

			await writer2InCritA;

			// Now Writer 2 holds `.ledger.lock`: resume Writer 1's partial write AND launch Writer 3 simultaneously!
			releaseWriter1PartialWrite();
			const w3 = withLedgerLock(r5aDir, async () => {
				activeA += 1;
				maxSimultaneousA = Math.max(maxSimultaneousA, activeA);
				await new Promise((r) => setTimeout(r, 25));
				activeA -= 1;
				return "w3";
			});

			await new Promise((r) => setTimeout(r, 30));
			assert.equal(activeA, 1);
			assert.equal(maxSimultaneousA, 1);
			releaseWriter2CritA();

			const [res1, res2, res3] = await Promise.all([w1, w2, w3]);
			assert.deepEqual([res1, res2, res3], ["w1", "w2", "w3"]);
			assert.equal(maxSimultaneousA, 1);

			const leftoverEntriesA = await fs.readdir(r5aDir);
			assert.equal(
				leftoverEntriesA.filter((name) => name.startsWith(".ledger.")).length,
				0,
				`unexpected leftover lock artifacts: ${leftoverEntriesA.join(", ")}`,
			);
		} finally {
			Date.now = realNow;
			cjsFs.writeFile = origWriteFileA;
			syncBuiltinESMExports();
		}

		// 2. R5-#2 (Three-writer detached stale-cleanup EIO isolation):
		// Pre-create a >20s stale ownerless `.ledger.lock`. Writer 1 fences and detaches it to `.ledger.lock.gen.*`.
		// Before removing the detached directory, Writer 2 acquires `.ledger.lock` and enters its critical section.
		// Then `fs.rm` on the detached `.gen.*` directory fails with `EIO`.
		// Writer 1's error handler MUST NOT overwrite Writer 2's `.ledger.lock/owner.json`, and Writer 3 arriving
		// while Writer 2 is still in its critical section MUST wait so maxSimultaneousOwners stays strictly 1!
		const r5bDir = path.join(tmpDir, "detached-cleanup-eio");
		const r5bLockPath = path.join(r5bDir, ".ledger.lock");
		await fs.mkdir(r5bLockPath, { recursive: true });
		const staleDate = new Date(fakeNow - 25_000);
		await fs.utimes(r5bLockPath, staleDate, staleDate).catch(() => {});

		const origStatB = cjsFs.stat;
		const origRmB = cjsFs.rm;
		let initialOwnerlessDetached = false;
		let detachedTrashPath: string | null = null;

		let notifyDetachedBeforeRm!: () => void;
		const detachedBeforeRm = new Promise<void>((resolve) => {
			notifyDetachedBeforeRm = resolve;
		});
		let allowDetachedRmThrowEio!: () => void;
		const detachedRmThrowGate = new Promise<void>((resolve) => {
			allowDetachedRmThrowEio = resolve;
		});
		let notifyWriter2InCritB!: () => void;
		const writer2InCritB = new Promise<void>((resolve) => {
			notifyWriter2InCritB = resolve;
		});
		let releaseWriter2CritB!: () => void;
		const writer2CritGateB = new Promise<void>((resolve) => {
			releaseWriter2CritB = resolve;
		});

		let activeB = 0;
		let maxSimultaneousB = 0;

		Date.now = () => fakeNow;
		try {
			cjsFs.stat = (async (target: any, options?: any) => {
				const st: any = await origStatB.call(cjsFs, target, options);
				if (!initialOwnerlessDetached && String(target) === r5bLockPath) {
					return Object.assign(Object.create(Object.getPrototypeOf(st)), st, {
						mtimeMs: fakeNow - 25_000,
					});
				}
				return st;
			}) as typeof cjsFs.stat;

			cjsFs.rm = (async (target: any, options?: any) => {
				const targetStr = String(target);
				if (targetStr.startsWith(`${r5bLockPath}.gen.`) && detachedTrashPath === null) {
					initialOwnerlessDetached = true;
					detachedTrashPath = targetStr;
					notifyDetachedBeforeRm();
					await detachedRmThrowGate;
					const eio: NodeJS.ErrnoException = new Error("injected EIO removing detached stale generation");
					eio.code = "EIO";
					throw eio;
				}
				return await origRmB.call(cjsFs, target, options);
			}) as typeof cjsFs.rm;
			syncBuiltinESMExports();

			const reclaimer1 = withLedgerLock(r5bDir, async () => {
				activeB += 1;
				maxSimultaneousB = Math.max(maxSimultaneousB, activeB);
				activeB -= 1;
				return "r1";
			});

			await detachedBeforeRm;

			// `.ledger.lock` has now been detached to `detachedTrashPath`; Writer 2 acquires `.ledger.lock`!
			const writer2 = withLedgerLock(r5bDir, async () => {
				activeB += 1;
				maxSimultaneousB = Math.max(maxSimultaneousB, activeB);
				notifyWriter2InCritB();
				await writer2CritGateB;
				activeB -= 1;
				return "w2";
			});

			await writer2InCritB;
			const writer2OwnerBeforeEio = JSON.parse(
				await fs.readFile(path.join(r5bLockPath, "owner.json"), "utf8"),
			);
			assert.equal(Boolean(writer2OwnerBeforeEio.released), false);
			assert.equal(String(writer2OwnerBeforeEio.token).startsWith("fence-"), false);

			// Now fail Writer 1's detached cleanup with EIO!
			allowDetachedRmThrowEio();
			await assert.rejects(() => reclaimer1, /injected EIO removing detached stale generation/);

			// Verify Writer 2's live `.ledger.lock/owner.json` was NOT overwritten by Writer 1's catch block!
			const writer2OwnerAfterEio = JSON.parse(
				await fs.readFile(path.join(r5bLockPath, "owner.json"), "utf8"),
			);
			assert.equal(writer2OwnerAfterEio.token, writer2OwnerBeforeEio.token);
			assert.equal(Boolean(writer2OwnerAfterEio.released), false);

			// Meanwhile the detached generation itself carries `released: true`:
			assert.ok(detachedTrashPath !== null);
			const detachedOwnerAfterEio = JSON.parse(
				await fs.readFile(path.join(detachedTrashPath!, "owner.json"), "utf8"),
			);
			assert.equal(detachedOwnerAfterEio.released, true);

			// Launch Writer 3 while Writer 2 is STILL inside its critical section -> Writer 3 MUST NOT evict Writer 2!
			const writer3 = withLedgerLock(r5bDir, async () => {
				activeB += 1;
				maxSimultaneousB = Math.max(maxSimultaneousB, activeB);
				await new Promise((r) => setTimeout(r, 20));
				activeB -= 1;
				return "w3";
			});

			await new Promise((r) => setTimeout(r, 35));
			assert.equal(activeB, 1);
			assert.equal(maxSimultaneousB, 1);

			releaseWriter2CritB();
			const [out2, out3] = await Promise.all([writer2, writer3]);
			assert.equal(out2, "w2");
			assert.equal(out3, "w3");
			assert.equal(maxSimultaneousB, 1);
		} finally {
			Date.now = realNow;
			cjsFs.stat = origStatB;
			cjsFs.rm = origRmB;
			syncBuiltinESMExports();
		}

		// 3. R6-#1 (Three-writer release retry after partial owner.json unlink + EIO):
		// Writer B prepares its directory and passes publication checks, then pauses right before `rename(prepDirB, lockDir)`.
		// Writer A acquires and finishes; its first release `fs.rm(lockDir)` unlinks `owner.json` and fails `rmdir` with `EIO`,
		// leaving an empty `lockDir`. On Writer A's retry, `readFile(ownerFile)` gets `ENOENT` and pauses while Writer B
		// publishes over the empty directory and enters its critical section. Writer A MUST stop removal retries (never
		// deleting or overwriting Writer B's live lock), surface the original `EIO`, and keep maxSimultaneousC === 1 when
		// Writer C contends!
		const r6Dir = path.join(tmpDir, "release-retry-enoent");
		await fs.mkdir(r6Dir, { recursive: true });
		const r6LockPath = path.join(r6Dir, ".ledger.lock");
		const r6OwnerPath = path.join(r6LockPath, "owner.json");

		const origRenameC = cjsFs.rename;
		const origRmC = cjsFs.rm;
		const origReadFileC = cjsFs.readFile;

		let pausedWriterBRename = false;
		let notifyWriterBReadyToPublish!: () => void;
		const writerBReadyToPublish = new Promise<void>((resolve) => {
			notifyWriterBReadyToPublish = resolve;
		});
		let releaseWriterBRename!: () => void;
		const writerBRenameGate = new Promise<void>((resolve) => {
			releaseWriterBRename = resolve;
		});

		let injectedPartialReleaseEio = false;
		let interceptedRetryEnoent = false;
		let releaseWriterAAfterBEntered!: () => void;
		const writerAAfterBEnteredGate = new Promise<void>((resolve) => {
			releaseWriterAAfterBEntered = resolve;
		});

		let notifyWriterBInCrit!: () => void;
		const writerBInCrit = new Promise<void>((resolve) => {
			notifyWriterBInCrit = resolve;
		});
		let releaseWriterBCrit!: () => void;
		const writerBCritGate = new Promise<void>((resolve) => {
			releaseWriterBCrit = resolve;
		});

		let activeC = 0;
		let maxSimultaneousC = 0;

		try {
			cjsFs.rename = (async (src: any, dst: any) => {
				if (
					!pausedWriterBRename &&
					String(dst) === r6LockPath &&
					String(src).startsWith(`${r6LockPath}.prep.`)
				) {
					pausedWriterBRename = true;
					notifyWriterBReadyToPublish();
					await writerBRenameGate;
				}
				return await origRenameC.call(cjsFs, src, dst);
			}) as typeof cjsFs.rename;

			cjsFs.rm = (async (target: any, options?: any) => {
				if (!injectedPartialReleaseEio && String(target) === r6LockPath) {
					injectedPartialReleaseEio = true;
					// Unlink owner.json first, then fail rmdir with EIO, leaving an empty `.ledger.lock` directory!
					await fs.unlink(r6OwnerPath);
					const eio: NodeJS.ErrnoException = new Error("injected partial-release EIO after owner unlink");
					eio.code = "EIO";
					throw eio;
				}
				return await origRmC.call(cjsFs, target, options);
			}) as typeof cjsFs.rm;

			cjsFs.readFile = (async (target: any, options?: any) => {
				if (injectedPartialReleaseEio && !interceptedRetryEnoent && String(target) === r6OwnerPath) {
					try {
						return await origReadFileC.call(cjsFs, target, options);
					} catch (err: any) {
						if (err?.code === "ENOENT") {
							interceptedRetryEnoent = true;
							// Writer A's retry just observed ENOENT on `.ledger.lock/owner.json`:
							// let Writer B publish over the empty `.ledger.lock` and enter its critical section now!
							releaseWriterBRename();
							await writerAAfterBEnteredGate;
						}
						throw err;
					}
				}
				return await origReadFileC.call(cjsFs, target, options);
			}) as typeof cjsFs.readFile;
			syncBuiltinESMExports();

			const writerB = withLedgerLock(r6Dir, async () => {
				activeC += 1;
				maxSimultaneousC = Math.max(maxSimultaneousC, activeC);
				notifyWriterBInCrit();
				await writerBCritGate;
				activeC -= 1;
				return "wB";
			});

			await writerBReadyToPublish;

			const writerA = withLedgerLock(r6Dir, async () => {
				activeC += 1;
				maxSimultaneousC = Math.max(maxSimultaneousC, activeC);
				await new Promise((r) => setTimeout(r, 10));
				activeC -= 1;
				return "wA";
			});

			await writerBInCrit;
			const bOwnerLive = JSON.parse(await origReadFileC.call(cjsFs, r6OwnerPath, "utf8") as unknown as string);
			assert.equal(Boolean(bOwnerLive.released), false);

			// Resume Writer A after its ENOENT probe; Writer A MUST surface EIO without deleting or overwriting Writer B!
			releaseWriterAAfterBEntered();
			await assert.rejects(() => writerA, /injected partial-release EIO after owner unlink/);

			const bOwnerAfterARelease = JSON.parse(
				(await origReadFileC.call(cjsFs, r6OwnerPath, "utf8")) as unknown as string,
			);
			assert.equal(bOwnerAfterARelease.token, bOwnerLive.token);
			assert.equal(Boolean(bOwnerAfterARelease.released), false);

			// Launch Writer C while Writer B remains active -> Writer C MUST wait for Writer B!
			const writerC = withLedgerLock(r6Dir, async () => {
				activeC += 1;
				maxSimultaneousC = Math.max(maxSimultaneousC, activeC);
				await new Promise((r) => setTimeout(r, 15));
				activeC -= 1;
				return "wC";
			});

			await new Promise((r) => setTimeout(r, 35));
			assert.equal(activeC, 1);
			assert.equal(maxSimultaneousC, 1);

			releaseWriterBCrit();
			const [outB, outC] = await Promise.all([writerB, writerC]);
			assert.equal(outB, "wB");
			assert.equal(outC, "wC");
			assert.equal(maxSimultaneousC, 1);
		} finally {
			cjsFs.rename = origRenameC;
			cjsFs.rm = origRmC;
			cjsFs.readFile = origReadFileC;
			syncBuiltinESMExports();
		}
	} finally {
		Date.now = realNow;
		await fs.rm(tmpDir, { recursive: true, force: true });
	}
});
