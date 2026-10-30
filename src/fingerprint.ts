import { createHash } from "node:crypto";
import type { CacheRetentionState, InlineToolItemMeta, ToolDigest, WireFingerprint } from "./types.ts";

export function sha12(text: string): string {
	return createHash("sha256").update(text).digest("hex").slice(0, 12);
}

function sha24(text: string): string {
	return createHash("sha256").update(text).digest("hex").slice(0, 24);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function canonicalJson(value: unknown): string {
	if (value === null || typeof value === "boolean") return String(value);
	if (typeof value === "number") return Number.isFinite(value) ? JSON.stringify(value) : "null";
	if (typeof value === "string") return JSON.stringify(value);
	if (typeof value === "bigint") return JSON.stringify(String(value));
	if (Array.isArray(value)) {
		const parts = value.map((el) =>
			el === undefined || typeof el === "function" || typeof el === "symbol" ? "null" : canonicalJson(el),
		);
		return `[${parts.join(",")}]`;
	}
	if (isPlainObject(value)) {
		const keys = Object.keys(value)
			.filter((k) => {
				const v = value[k];
				return v !== undefined && typeof v !== "function" && typeof v !== "symbol";
			})
			.sort();
		return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
	}
	return JSON.stringify(value) ?? "null";
}

export function parseDurationSeconds(raw: unknown): number | null {
	if (typeof raw === "number") {
		return Number.isFinite(raw) && raw > 0 ? Math.round(raw) : null;
	}
	if (typeof raw !== "string") return null;
	const match = /^\s*(\d+(?:\.\d+)?)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days)?\s*$/i.exec(
		raw,
	);
	if (!match) return null;
	const amount = Number(match[1]);
	if (!Number.isFinite(amount) || amount <= 0) return null;
	const unit = (match[2] ?? "s").toLowerCase();
	const multiplier = unit.startsWith("d")
		? 86_400
		: unit.startsWith("h")
			? 3_600
			: unit.startsWith("m")
				? 60
				: 1;
	const seconds = Math.round(amount * multiplier);
	return Number.isFinite(seconds) && seconds > 0 ? seconds : null;
}

interface CacheMetaObservation {
	hasCacheControl: boolean;
	maxTtlSec: number | null;
	sawUnparsedTtl: boolean;
}

function observeCacheControl(marker: unknown, obs?: CacheMetaObservation): void {
	if (!isPlainObject(marker) || !obs) return;
	obs.hasCacheControl = true;
	if (marker.ttl !== undefined && marker.ttl !== null) {
		const parsed = parseDurationSeconds(marker.ttl);
		if (parsed !== null) {
			obs.maxTtlSec = Math.max(obs.maxTtlSec ?? 0, parsed);
		} else {
			obs.sawUnparsedTtl = true;
		}
	}
}

function omitOwnCacheControl(
	obj: Record<string, unknown>,
	obs?: CacheMetaObservation,
): Record<string, unknown> {
	if (!Object.prototype.hasOwnProperty.call(obj, "cache_control")) {
		return obj;
	}
	observeCacheControl(obj.cache_control, obs);
	const out: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(obj)) {
		if (k === "cache_control") continue;
		out[k] = v;
	}
	return out;
}

/**
 * Strip provider `cache_control` breakpoint markers ONLY at wire metadata positions
 * (system blocks, top-level tool wrappers, message envelopes, and message content blocks),
 * never inside JSON schemas (`input_schema` / `parameters`) or tool call `input` / `arguments`.
 */
export function stripSystemMeta(systemValue: unknown, obs?: CacheMetaObservation): unknown {
	if (Array.isArray(systemValue)) {
		return systemValue.map((block) => (isPlainObject(block) ? omitOwnCacheControl(block, obs) : block));
	}
	if (isPlainObject(systemValue)) {
		return omitOwnCacheControl(systemValue, obs);
	}
	return systemValue;
}

export function stripToolMeta(tool: unknown, obs?: CacheMetaObservation): unknown {
	if (!isPlainObject(tool)) return tool;
	const top = omitOwnCacheControl(tool, obs);
	if (isPlainObject(top.function) && Object.prototype.hasOwnProperty.call(top.function, "cache_control")) {
		return {
			...top,
			function: omitOwnCacheControl(top.function, obs),
		};
	}
	return top;
}

function stripContentPartMeta(part: unknown, obs?: CacheMetaObservation): unknown {
	if (!isPlainObject(part)) return part;
	const base = omitOwnCacheControl(part, obs);
	if (base.type === "tool_result" && Array.isArray(base.content)) {
		return {
			...base,
			content: base.content.map((sub) => (isPlainObject(sub) ? omitOwnCacheControl(sub, obs) : sub)),
		};
	}
	return base;
}

const SINGLE_TEXT_WRAPPER_ROLES = new Set(["user", "system", "developer", "assistant", "tool"]);

/**
 * Providers using Anthropic-style rolling breakpoints (Anthropic Messages and OpenAI
 * Completions compat) wrap a string `content` into `[{ type: "text", text, cache_control }]`
 * on the tail turn and replay it as a plain string on subsequent turns. Canonicalize
 * metadata-only single-text wrappers back to string `content` while keeping all semantic
 * fields (`tool_call_id`, `tool_calls`, `name`, schemas, and tool inputs) intact.
 */
export function normalizeConvItemForHash(item: unknown, obs?: CacheMetaObservation): unknown {
	if (!isPlainObject(item)) return item;
	const rec = omitOwnCacheControl(item, obs);
	if (!Array.isArray(rec.content)) return rec;

	const strippedContent = rec.content.map((part) => stripContentPartMeta(part, obs));
	if (
		typeof rec.role === "string" &&
		SINGLE_TEXT_WRAPPER_ROLES.has(rec.role) &&
		strippedContent.length === 1 &&
		isPlainObject(strippedContent[0])
	) {
		const block = strippedContent[0];
		if (
			block.type === "text" &&
			typeof block.text === "string" &&
			Object.keys(block).every((k) => k === "type" || k === "text")
		) {
			return { ...rec, content: block.text };
		}
	}
	return { ...rec, content: strippedContent };
}

const UNSUPPORTED_STRICT_SCHEMA_KEYS = [
	"$ref",
	"$defs",
	"definitions",
	"allOf",
	"oneOf",
	"patternProperties",
	"dependentSchemas",
	"dependencies",
	"unevaluatedProperties",
	"propertyNames",
	"contains",
	"prefixItems",
	"not",
	"if",
	"then",
	"else",
];

function schemaAllowsNull(schema: unknown): boolean {
	if (!isPlainObject(schema)) return false;
	if (schema.type === "null" || (Array.isArray(schema.type) && schema.type.includes("null"))) {
		return true;
	}
	if (schema.const === null || (Array.isArray(schema.enum) && schema.enum.includes(null))) {
		return true;
	}
	return Array.isArray(schema.anyOf) && schema.anyOf.some((variant) => schemaAllowsNull(variant));
}

function makeSchemaNodeStrictInPlace(schema: unknown): void {
	if (!isPlainObject(schema)) {
		throw new Error("non-object schema node");
	}
	for (const key of UNSUPPORTED_STRICT_SCHEMA_KEYS) {
		if (schema[key] !== undefined) {
			throw new Error(`unsupported strict keyword: ${key}`);
		}
	}
	if (schema.anyOf !== undefined) {
		if (!Array.isArray(schema.anyOf) || schema.anyOf.length === 0) {
			throw new Error("invalid anyOf");
		}
		for (const variant of schema.anyOf) {
			makeSchemaNodeStrictInPlace(variant);
		}
	}
	if (schema.items !== undefined) {
		if (Array.isArray(schema.items)) {
			throw new Error("tuple items unsupported");
		}
		makeSchemaNodeStrictInPlace(schema.items);
	}
	const isObjectSchema = schema.type === "object";
	if (schema.properties !== undefined && !isObjectSchema) {
		throw new Error("properties without type object");
	}
	if (!isObjectSchema) return;

	if (schema.additionalProperties !== undefined && schema.additionalProperties !== false) {
		throw new Error("non-false additionalProperties");
	}
	if (schema.properties !== undefined && !isPlainObject(schema.properties)) {
		throw new Error("non-object properties map");
	}
	if (
		schema.required !== undefined &&
		(!Array.isArray(schema.required) || schema.required.some((k) => typeof k !== "string"))
	) {
		throw new Error("invalid required array");
	}
	const properties = (schema.properties ?? {}) as Record<string, unknown>;
	const propertyNames = Object.keys(properties);
	const required = new Set(Array.isArray(schema.required) ? (schema.required as string[]) : []);
	if ([...required].some((key) => !propertyNames.includes(key))) {
		throw new Error("required references missing property");
	}
	for (const [key, property] of Object.entries(properties)) {
		makeSchemaNodeStrictInPlace(property);
		if (!required.has(key) && !schemaAllowsNull(property)) {
			properties[key] = { anyOf: [property, { type: "null" }] };
		}
	}
	schema.required = propertyNames;
	schema.additionalProperties = false;
}

/**
 * Canonicalize a tool parameter JSON schema using the exact upstream `makeStrictJsonSchema`
 * forward transformation (`@earendil-works/pi-ai` `constrained-sampling.js`).
 *
 * Projecting root object schemas to `{ type: "object", properties, required }` before applying
 * `makeSchemaNodeStrictInPlace` makes strict Attempt 1 (`{ ...makeStrictJsonSchema(S), ...legacy }`)
 * and fallback Attempt 2 (`legacyInputSchema`) converge to the exact same canonical representation,
 * while preserving literal properties named `"required"` or `"additionalProperties"` and catching
 * genuine optional/required or property-type changes.
 */
export function canonicalizeSchemaForStrictFallback(schema: unknown): unknown {
	if (!isPlainObject(schema) || schema.type !== "object") return schema;
	try {
		const rootClone: Record<string, unknown> = {
			type: "object",
			properties: isPlainObject(schema.properties) ? structuredClone(schema.properties) : {},
			required: Array.isArray(schema.required) ? [...schema.required] : [],
		};
		makeSchemaNodeStrictInPlace(rootClone);
		return rootClone;
	} catch {
		return schema;
	}
}

function omitStrictFlag(obj: Record<string, unknown>): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(obj)) {
		if (k === "strict" && typeof v === "boolean") continue;
		out[k] = v;
	}
	return out;
}

export function extractLogicalToolShape(tool: unknown): unknown {
	if (!isPlainObject(tool)) return tool;
	if (isPlainObject(tool.function)) {
		const fn = omitStrictFlag(tool.function);
		if (fn.parameters !== undefined) {
			fn.parameters = canonicalizeSchemaForStrictFallback(fn.parameters);
		}
		return { ...omitStrictFlag(tool), function: fn };
	}
	if (isPlainObject(tool.toolSpec)) {
		const spec = { ...tool.toolSpec };
		if (isPlainObject(spec.inputSchema) && spec.inputSchema.json !== undefined) {
			spec.inputSchema = {
				...spec.inputSchema,
				json: canonicalizeSchemaForStrictFallback(spec.inputSchema.json),
			};
		}
		return { ...tool, toolSpec: spec };
	}
	const out = omitStrictFlag(tool);
	if (out.input_schema !== undefined) {
		out.input_schema = canonicalizeSchemaForStrictFallback(out.input_schema);
	}
	if (out.parameters !== undefined) {
		out.parameters = canonicalizeSchemaForStrictFallback(out.parameters);
	}
	return out;
}

function isToolDefinitionStrict(tool: unknown): boolean {
	if (!isPlainObject(tool)) return false;
	if (tool.strict === true) return true;
	if (isPlainObject(tool.function) && tool.function.strict === true) return true;
	return false;
}

function buildToolDigest(strippedTool: unknown, idx: number): ToolDigest {
	const obj = (isPlainObject(strippedTool) ? strippedTool : {}) as Record<string, any>;
	const name =
		(typeof obj.name === "string" && obj.name) ||
		(typeof obj.function?.name === "string" && obj.function.name) ||
		(typeof obj.custom?.name === "string" && obj.custom.name) ||
		(typeof obj.toolSpec?.name === "string" && obj.toolSpec.name) ||
		`tool_${idx}`;
	const serialized = canonicalJson(strippedTool);
	const logicalSerialized = canonicalJson(extractLogicalToolShape(strippedTool));
	return {
		name,
		hash: sha12(serialized),
		logicalHash: sha12(logicalSerialized),
		isStrict: isToolDefinitionStrict(strippedTool),
		bytes: Buffer.byteLength(serialized, "utf8"),
	};
}

function extractInlineToolItemMeta(normalizedItem: unknown): InlineToolItemMeta | null {
	if (!isPlainObject(normalizedItem)) return null;
	if (
		(normalizedItem.type === "additional_tools" || normalizedItem.type === "tool_search_output") &&
		Array.isArray(normalizedItem.tools) &&
		normalizedItem.tools.length > 0
	) {
		const digests = normalizedItem.tools.map((t, idx) => buildToolDigest(stripToolMeta(t), idx));
		const envelope = {
			...normalizedItem,
			tools: normalizedItem.tools.map((_t, idx) => ({ __inline_tool_slot__: idx })),
		};
		return {
			envelopeHash: sha12(canonicalJson(envelope)),
			tools: digests,
		};
	}
	if (Array.isArray(normalizedItem.content)) {
		const digests: ToolDigest[] = [];
		const nextContent = normalizedItem.content.map((part) => {
			if (
				isPlainObject(part) &&
				part.type === "tool_addition" &&
				isPlainObject(part.tool) &&
				part.tool.type === "tool_definition" &&
				isPlainObject(part.tool.definition)
			) {
				const slot = digests.length;
				digests.push(buildToolDigest(stripToolMeta(part.tool.definition), slot));
				return {
					...part,
					tool: {
						...part.tool,
						definition: { __inline_tool_slot__: slot },
					},
				};
			}
			return part;
		});
		if (digests.length > 0) {
			return {
				envelopeHash: sha12(canonicalJson({ ...normalizedItem, content: nextContent })),
				tools: digests,
			};
		}
	}
	return null;
}

/**
 * Returns true iff two tool lists differ ONLY by verified strict <-> fallback representation
 * transitions. Any tool whose `isStrict` state did NOT change (e.g. both requests used fallback
 * non-strict schemas, or both used strict schemas) must match by exact raw `hash`, preventing
 * nullable-property `required` mutations from being masked when both turns take strict fallback.
 */
export function isStrictToolsRepresentationTransition(
	prevTools: ToolDigest[],
	currTools: ToolDigest[],
	downgradeOnly = false,
): boolean {
	if (prevTools.length !== currTools.length) return false;
	let sawTransition = false;
	for (let i = 0; i < prevTools.length; i++) {
		const p = prevTools[i]!;
		const c = currTools[i]!;
		if (p.name !== c.name) return false;
		if (p.hash === c.hash) continue;
		const validStateChange = downgradeOnly ? p.isStrict && !c.isStrict : p.isStrict !== c.isStrict;
		if (!validStateChange) return false;
		if (p.logicalHash !== c.logicalHash) return false;
		sawTransition = true;
	}
	return sawTransition;
}

export function isStrictItemRepresentationTransition(
	prevWire: WireFingerprint,
	currWire: WireFingerprint,
	idx: number,
	downgradeOnly = false,
): boolean {
	const pHash = prevWire.itemHashes[idx];
	const cHash = currWire.itemHashes[idx];
	if (pHash === undefined || cHash === undefined || pHash === cHash) return false;
	const pMeta = prevWire.inlineToolItems?.[idx] ?? null;
	const cMeta = currWire.inlineToolItems?.[idx] ?? null;
	if (!pMeta || !cMeta) return false;
	if (pMeta.envelopeHash !== cMeta.envelopeHash) return false;
	return isStrictToolsRepresentationTransition(pMeta.tools, cMeta.tools, downgradeOnly);
}

const SECRET_TOKEN_RE =
	/\b(?:Bearer\s+[A-Za-z0-9._~+/=-]{10,}|sk-[A-Za-z0-9_-]{10,}|gh[pousr]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{12,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,})/gi;
const KV_SECRET_RE = /\b(api[_-]?key|token|secret|password|authorization)\s*([:=])\s*([^\s"',;]+)/gi;

export function redactSecrets(text: string): string {
	return text
		.replace(SECRET_TOKEN_RE, "[REDACTED]")
		.replace(KV_SECRET_RE, (_m, key: string, sep: string) => `${key}${sep}[REDACTED]`);
}

export function sanitizeFreeText(text: string, maxLen = 240): string {
	return redactSecrets(text).replace(/[\r\n\t]+/g, " ").slice(0, maxLen);
}

/**
 * Redact secrets and bound identifier length while preserving both prefix and suffix
 * so long fine-tuned or gateway-routed model IDs remain distinguishable when displayed.
 */
export function sanitizeIdentifierKeepTail(text: string, maxLen = 96): string {
	const cleaned = redactSecrets(text).replace(/[\r\n\t]+/g, " ");
	if (cleaned.length <= maxLen || maxLen < 12) {
		return cleaned.slice(0, maxLen);
	}
	const tailLen = Math.floor((maxLen - 3) / 2);
	const headLen = maxLen - 3 - tailLen;
	return `${cleaned.slice(0, headLen)}...${cleaned.slice(cleaned.length - tailLen)}`;
}

/**
 * Compute deterministic structural diff metadata between two system prompts WITHOUT
 * returning or persisting any raw prompt characters (preventing credential leakage).
 * Numeric character and UTF-8 byte offsets are measured on the original unredacted text.
 */
export function firstDiffSummary(prevText: string, nextText: string): string {
	const prevBytes = Buffer.byteLength(prevText, "utf8");
	const nextBytes = Buffer.byteLength(nextText, "utf8");
	const byteDelta = nextBytes - prevBytes;
	const limit = Math.min(prevText.length, nextText.length);
	let idx = 0;
	while (idx < limit && prevText.charCodeAt(idx) === nextText.charCodeAt(idx)) {
		idx++;
	}
	if (idx > 0 && idx < limit) {
		const prevCode = prevText.charCodeAt(idx - 1);
		if (prevCode >= 0xd800 && prevCode <= 0xdbff) {
			idx--;
		}
	}
	const byteOffset = Buffer.byteLength(prevText.slice(0, idx), "utf8");
	const sign = byteDelta >= 0 ? `+${byteDelta}` : `${byteDelta}`;
	return `char@${idx} byte@${byteOffset} (${sign}B, ${prevBytes}B->${nextBytes}B, ${sha12(prevText)}->${sha12(nextText)})`;
}

export function diffTools(prevTools: ToolDigest[], nextTools: ToolDigest[]): string {
	const prevMap = new Map(prevTools.map((t) => [t.name, t]));
	const nextMap = new Map(nextTools.map((t) => [t.name, t]));
	const added: string[] = [];
	const removed: string[] = [];
	const modified: string[] = [];
	for (const [name, t] of nextMap) {
		const old = prevMap.get(name);
		if (!old) added.push(`+${sanitizeFreeText(name, 64)}`);
		else if (old.hash !== t.hash) {
			const delta = t.bytes - old.bytes;
			modified.push(`~${sanitizeFreeText(name, 64)}(${delta >= 0 ? "+" : ""}${delta}B)`);
		}
	}
	for (const name of prevMap.keys()) {
		if (!nextMap.has(name)) removed.push(`-${sanitizeFreeText(name, 64)}`);
	}
	return [...added, ...removed, ...modified].join(", ") || "tool order changed";
}

function isSyntheticEffortItem(item: unknown): boolean {
	if (!isPlainObject(item)) return false;
	if (item.type === "configuration_update") return true;
	if (
		item.role === "system" &&
		item.output_config !== undefined &&
		(item.content === "" || (Array.isArray(item.content) && item.content.length === 0)) &&
		Object.keys(item).every(
			(k) => k === "role" || k === "content" || k === "output_config" || k === "cache_control",
		)
	) {
		return true;
	}
	return false;
}

function resolveWireRetention(
	payload: Record<string, unknown>,
	obs: CacheMetaObservation,
	promptCacheKey: string | null,
): { retentionState: CacheRetentionState; retentionTtlSec: number | null } {
	let explicitTtlSec: number | null = obs.maxTtlSec;
	let sawUnrecognized = obs.sawUnparsedTtl;
	let sawDisabled = false;

	const rawRetention = payload.prompt_cache_retention;
	if (rawRetention !== undefined && rawRetention !== null) {
		if (rawRetention === false || rawRetention === "none" || rawRetention === "disabled" || rawRetention === "off") {
			sawDisabled = true;
		} else {
			const parsed = parseDurationSeconds(rawRetention);
			if (parsed !== null) {
				explicitTtlSec = Math.max(explicitTtlSec ?? 0, parsed);
			} else {
				sawUnrecognized = true;
			}
		}
	}

	const rawOpts = payload.prompt_cache_options;
	if (rawOpts !== undefined && rawOpts !== null) {
		if (rawOpts === false) {
			sawDisabled = true;
		} else if (isPlainObject(rawOpts)) {
			const mode = rawOpts.mode;
			if (rawOpts.enabled === false || mode === "none" || mode === "disabled" || mode === "off") {
				sawDisabled = true;
			} else if (mode === "explicit" && !obs.hasCacheControl && (rawOpts.ttl === undefined || rawOpts.ttl === null)) {
				sawDisabled = true;
			}
			if (rawOpts.ttl !== undefined && rawOpts.ttl !== null) {
				const parsed = parseDurationSeconds(rawOpts.ttl);
				if (parsed !== null) {
					explicitTtlSec = Math.max(explicitTtlSec ?? 0, parsed);
				} else {
					sawUnrecognized = true;
				}
			}
		} else {
			sawUnrecognized = true;
		}
	}

	if (sawDisabled && explicitTtlSec === null) {
		return { retentionState: "disabled", retentionTtlSec: null };
	}
	if (sawUnrecognized) {
		return { retentionState: "unrecognized", retentionTtlSec: null };
	}
	if (explicitTtlSec !== null) {
		return { retentionState: "explicit_ttl", retentionTtlSec: explicitTtlSec };
	}
	if (obs.hasCacheControl || (promptCacheKey !== null && promptCacheKey.length > 0)) {
		return { retentionState: "short_default", retentionTtlSec: null };
	}
	return { retentionState: "unknown", retentionTtlSec: null };
}

export function resolveEffectiveTtlSec(wire: WireFingerprint | null, ttlThresholdSec: number): number | null {
	if (!wire) return null;
	if (wire.retentionState === "explicit_ttl") return wire.retentionTtlSec;
	if (wire.retentionState === "short_default") return ttlThresholdSec;
	return null;
}

function computeNonToolEnvelopeHash(payload: Record<string, unknown>): string {
	const envelope: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(payload)) {
		if (k === "tools" || k === "messages" || k === "input" || k === "system" || k === "instructions") {
			continue;
		}
		envelope[k] = v;
	}
	return sha24(canonicalJson(envelope));
}

export function extractWireFingerprint(payload: unknown, nowMs = Date.now()): WireFingerprint | null {
	if (!isPlainObject(payload)) return null;
	const p = payload;
	const modelInPayload = typeof p.model === "string" ? p.model : "unknown";
	const fullRequestHash = sha24(canonicalJson(p));
	const nonToolEnvelopeHash = computeNonToolEnvelopeHash(p);
	const obs: CacheMetaObservation = { hasCacheControl: false, maxTtlSec: null, sawUnparsedTtl: false };

	let systemRaw = "";
	const convItems: unknown[] = [];
	const inlineLeadTools: unknown[] = [];
	const effortItems: unknown[] = [];

	if (p.system !== undefined) {
		systemRaw = JSON.stringify(stripSystemMeta(p.system, obs));
		if (Array.isArray(p.messages)) {
			for (const item of p.messages) {
				if (isSyntheticEffortItem(item)) {
					effortItems.push(omitOwnCacheControl(item as Record<string, unknown>, obs));
				} else {
					convItems.push(item);
				}
			}
		}
	} else if (Array.isArray(p.input)) {
		const hasTopInstructions = typeof p.instructions === "string" && p.instructions.length > 0;
		const sysLead: unknown[] = [];
		let inLead = true;
		for (const item of p.input) {
			if (isSyntheticEffortItem(item)) {
				effortItems.push(isPlainObject(item) ? omitOwnCacheControl(item, obs) : item);
				continue;
			}
			const rec = isPlainObject(item) ? item : null;
			const itemType = rec?.type;
			const role = rec?.role;
			if (inLead && itemType === "additional_tools" && Array.isArray(rec?.tools)) {
				inlineLeadTools.push(...rec.tools);
				continue;
			}
			if (
				inLead &&
				(role === "developer" || role === "system") &&
				itemType !== "tool_search_call" &&
				itemType !== "tool_search_output"
			) {
				sysLead.push(normalizeConvItemForHash(rec, obs));
				continue;
			}
			inLead = false;
			convItems.push(item);
		}
		systemRaw = hasTopInstructions
			? sysLead.length > 0
				? JSON.stringify({ instructions: p.instructions, lead: sysLead })
				: (p.instructions as string)
			: JSON.stringify(sysLead);
	} else if (typeof p.instructions === "string") {
		systemRaw = p.instructions;
	} else if (Array.isArray(p.messages)) {
		const sysLead: unknown[] = [];
		let inLead = true;
		for (const item of p.messages) {
			if (isSyntheticEffortItem(item)) {
				effortItems.push(isPlainObject(item) ? omitOwnCacheControl(item, obs) : item);
				continue;
			}
			const role = isPlainObject(item) ? item.role : undefined;
			if (inLead && (role === "developer" || role === "system")) {
				sysLead.push(normalizeConvItemForHash(item, obs));
			} else {
				inLead = false;
				convItems.push(item);
			}
		}
		systemRaw = JSON.stringify(sysLead);
	}

	const rawTools = [...(Array.isArray(p.tools) ? p.tools : []), ...inlineLeadTools];
	const strippedTools = rawTools.map((t) => stripToolMeta(t, obs));
	const tools: ToolDigest[] = strippedTools.map((t, idx) => buildToolDigest(t, idx));
	const toolsSerialized = canonicalJson(strippedTools);
	const logicalToolsSerialized = JSON.stringify(tools.map((t) => `${t.name}:${t.logicalHash}`));

	const normalizedConvItems = convItems.map((item) => normalizeConvItemForHash(item, obs));
	const itemHashes = normalizedConvItems.map((norm) => sha12(canonicalJson(norm)));
	const inlineToolItems = normalizedConvItems.map((norm) => extractInlineToolItemMeta(norm));

	const effortConfigHash = sha12(
		canonicalJson({
			thinking: p.thinking ?? null,
			output_config: p.output_config ?? null,
			reasoning: p.reasoning ?? null,
			reasoning_effort: p.reasoning_effort ?? null,
			effortItems,
		}),
	);

	const promptCacheKey = typeof p.prompt_cache_key === "string" ? p.prompt_cache_key : null;
	const { retentionState, retentionTtlSec } = resolveWireRetention(p, obs, promptCacheKey);

	return {
		capturedAtMs: nowMs,
		modelInPayload,
		fullRequestHash,
		nonToolEnvelopeHash,
		systemHash: sha12(systemRaw),
		systemBytes: Buffer.byteLength(systemRaw, "utf8"),
		systemTextSample: systemRaw,
		toolsHash: sha12(toolsSerialized),
		logicalToolsHash: sha12(logicalToolsSerialized),
		toolsBytes: Buffer.byteLength(toolsSerialized, "utf8"),
		tools,
		itemHashes,
		inlineToolItems,
		effortConfigHash,
		retentionState,
		retentionTtlSec,
		promptCacheKey,
		hasCacheControl: obs.hasCacheControl,
	};
}
