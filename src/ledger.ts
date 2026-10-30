import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { sanitizeFreeText, sanitizeIdentifierKeepTail, sha12 } from "./fingerprint.ts";
import type { Locale, TurnCacheRecord } from "./types.ts";

const LOCK_STALE_MS = 15_000;
const REMOTE_LOCK_STALE_MS = 300_000;
const LOCK_TIMEOUT_MS = 5_000;
const RELEASE_RETRY_COUNT = 3;
const CURRENT_HOST = os.hostname();

let tmpSeq = 0;
let lockSeq = 0;
const activeInProcessLocks = new Set<string>();
const activeInProcessReclaims = new Set<string>();

interface LockOwnerMeta {
	token: string;
	pid: number;
	host: string;
	acquiredAtMs: number;
	released?: boolean;
}

type LockInspection =
	| { state: "live" | "vanished" }
	| {
			state: "stale";
			expectedToken: string | null;
			rawOwnerPresent: boolean;
			expectedMtimeMs: number | null;
	  };

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

function isProcessAlive(pid: number): boolean {
	if (!Number.isInteger(pid) || pid <= 0) return false;
	if (pid === process.pid) return true;
	try {
		process.kill(pid, 0);
		return true;
	} catch (err: any) {
		if (err?.code === "EPERM") return true;
		return false;
	}
}

function parseLockOwner(raw: string): LockOwnerMeta | null {
	try {
		const parsed = JSON.parse(raw) as Record<string, unknown>;
		if (
			parsed &&
			typeof parsed === "object" &&
			typeof parsed.token === "string" &&
			parsed.token.length > 0 &&
			typeof parsed.pid === "number" &&
			typeof parsed.host === "string" &&
			typeof parsed.acquiredAtMs === "number"
		) {
			return {
				token: parsed.token,
				pid: parsed.pid,
				host: parsed.host,
				acquiredAtMs: parsed.acquiredAtMs,
				released: parsed.released === true,
			};
		}
	} catch {
		// malformed owner metadata
	}
	return null;
}

function makeEexistError(targetDir: string): NodeJS.ErrnoException {
	const err: NodeJS.ErrnoException = new Error(`Lock directory already exists: ${targetDir}`);
	err.code = "EEXIST";
	return err;
}

async function pathExists(targetPath: string): Promise<boolean> {
	try {
		await fs.stat(targetPath);
		return true;
	} catch (err: any) {
		if (err?.code === "ENOENT") return false;
		throw err;
	}
}

async function inspectLockDir(targetDir: string, activeSet: Set<string>): Promise<LockInspection> {
	const ownerFile = path.join(targetDir, "owner.json");
	let rawOwner: string | null = null;
	try {
		rawOwner = await fs.readFile(ownerFile, "utf8");
	} catch (err: any) {
		if (err?.code !== "ENOENT") {
			throw err;
		}
	}

	if (rawOwner !== null) {
		const owner = parseLockOwner(rawOwner);
		if (owner) {
			if (owner.released === true) {
				return {
					state: "stale",
					expectedToken: owner.token,
					rawOwnerPresent: true,
					expectedMtimeMs: null,
				};
			}
			if (activeSet.has(owner.token)) {
				return { state: "live" };
			}
			if (owner.host === CURRENT_HOST) {
				if (owner.pid === process.pid) {
					return {
						state: "stale",
						expectedToken: owner.token,
						rawOwnerPresent: true,
						expectedMtimeMs: null,
					};
				}
				return isProcessAlive(owner.pid)
					? { state: "live" }
					: {
							state: "stale",
							expectedToken: owner.token,
							rawOwnerPresent: true,
							expectedMtimeMs: null,
						};
			}
			try {
				const st = await fs.stat(targetDir);
				return Date.now() - st.mtimeMs > REMOTE_LOCK_STALE_MS
					? {
							state: "stale",
							expectedToken: owner.token,
							rawOwnerPresent: true,
							expectedMtimeMs: null,
						}
					: { state: "live" };
			} catch (err: any) {
				if (err?.code === "ENOENT") return { state: "vanished" };
				throw err;
			}
		}
	}

	let st: Awaited<ReturnType<typeof fs.stat>>;
	try {
		st = await fs.stat(targetDir);
	} catch (err: any) {
		if (err?.code === "ENOENT") return { state: "vanished" };
		throw err;
	}

	if (Date.now() - st.mtimeMs > LOCK_STALE_MS) {
		return {
			state: "stale",
			expectedToken: null,
			rawOwnerPresent: rawOwner !== null,
			expectedMtimeMs: st.mtimeMs,
		};
	}
	return { state: "live" };
}

async function stillMatchesStaleInspection(
	targetDir: string,
	activeSet: Set<string>,
	expected: { expectedToken: string | null; rawOwnerPresent: boolean; expectedMtimeMs: number | null },
): Promise<boolean> {
	const current = await inspectLockDir(targetDir, activeSet);
	if (current.state !== "stale") return false;
	if (expected.expectedToken !== null) {
		return current.expectedToken === expected.expectedToken;
	}
	return (
		current.expectedToken === null &&
		current.rawOwnerPresent === expected.rawOwnerPresent &&
		(expected.expectedMtimeMs === null || current.expectedMtimeMs === expected.expectedMtimeMs)
	);
}

interface DetachState {
	detached: boolean;
	holderDir: string;
}

async function detachAndRemoveLockGeneration(
	targetDir: string,
	expectedToken: string | null,
	tag: string,
	state: DetachState,
): Promise<boolean> {
	if (expectedToken !== null) {
		try {
			const pre = parseLockOwner(await fs.readFile(path.join(targetDir, "owner.json"), "utf8"));
			if (!pre || pre.token !== expectedToken) {
				return false;
			}
		} catch (err: any) {
			if (err?.code === "ENOENT") return false;
			throw err;
		}
	} else {
		try {
			const pre = parseLockOwner(await fs.readFile(path.join(targetDir, "owner.json"), "utf8"));
			if (pre !== null) {
				return false;
			}
		} catch (err: any) {
			if (err?.code !== "ENOENT") throw err;
		}
	}

	const trashDir = `${targetDir}.gen.${process.pid}.${++tmpSeq}.${tag}`;
	try {
		await fs.rename(targetDir, trashDir);
		state.detached = true;
		state.holderDir = trashDir;
	} catch (err: any) {
		if (err?.code === "ENOENT") {
			if (!(await pathExists(targetDir))) {
				return false;
			}
		}
		// Fall back to direct removal only when running under a file-only rename shim.
	}

	if (state.detached) {
		try {
			await fs.rm(trashDir, { recursive: true });
		} catch (err: any) {
			if (err?.code !== "ENOENT") throw err;
		}
		return true;
	}

	if (expectedToken !== null) {
		try {
			const current = parseLockOwner(await fs.readFile(path.join(targetDir, "owner.json"), "utf8"));
			if (!current || current.token !== expectedToken) {
				return false;
			}
		} catch (err: any) {
			if (err?.code === "ENOENT") return false;
			throw err;
		}
	} else {
		try {
			const current = parseLockOwner(await fs.readFile(path.join(targetDir, "owner.json"), "utf8"));
			if (current !== null) {
				return false;
			}
		} catch (err: any) {
			if (err?.code !== "ENOENT") throw err;
		}
	}

	try {
		await fs.rm(targetDir, { recursive: true, maxRetries: 0 });
		return true;
	} catch (err: any) {
		if (err?.code === "ENOENT") return false;
		throw err;
	}
}

/**
 * Atomically publish a lock directory with complete, verified `owner.json` metadata already
 * inside by preparing a private staging directory first and renaming it into `targetDir`.
 * Because `prepDir` is non-empty, POSIX `rename(prepDir, targetDir)` atomically fails with
 * `ENOTEMPTY` / `EEXIST` if another non-empty `targetDir` wins a race, and pre-checking
 * `pathExists(targetDir)` prevents replacing an existing empty external directory.
 */
async function createOwnedLockDir(
	targetDir: string,
	token: string,
	activeSet: Set<string>,
): Promise<boolean> {
	if (await pathExists(targetDir)) {
		throw makeEexistError(targetDir);
	}

	const prepDir = `${targetDir}.prep.${process.pid}.${++tmpSeq}-${Math.random().toString(36).slice(2, 8)}`;
	await fs.mkdir(prepDir);
	try {
		const prepOwnerFile = path.join(prepDir, "owner.json");
		const meta: LockOwnerMeta = {
			token,
			pid: process.pid,
			host: CURRENT_HOST,
			acquiredAtMs: Date.now(),
		};
		await fs.writeFile(prepOwnerFile, JSON.stringify(meta), { encoding: "utf8", flag: "wx" });
		const verified = parseLockOwner(await fs.readFile(prepOwnerFile, "utf8"));
		if (!verified || verified.token !== token || verified.released === true) {
			await fs.rm(prepDir, { recursive: true, force: true }).catch(() => {});
			return false;
		}

		if (await pathExists(targetDir)) {
			await fs.rm(prepDir, { recursive: true, force: true }).catch(() => {});
			throw makeEexistError(targetDir);
		}

		const freshDate = new Date(Date.now());
		await fs.utimes(prepDir, freshDate, freshDate).catch(() => {});

		activeSet.add(token);
		try {
			await fs.rename(prepDir, targetDir);
			return true;
		} catch (renErr: any) {
			activeSet.delete(token);
			await fs.rm(prepDir, { recursive: true, force: true }).catch(() => {});
			if (
				renErr?.code === "EEXIST" ||
				renErr?.code === "ENOTEMPTY" ||
				((renErr?.code === "EBUSY" || renErr?.code === "EISDIR") &&
					(await pathExists(targetDir).catch(() => false)))
			) {
				throw makeEexistError(targetDir);
			}
			throw renErr;
		}
	} catch (err) {
		await fs.rm(prepDir, { recursive: true, force: true }).catch(() => {});
		throw err;
	}
}

/**
 * Atomically claim `owner.json` inside an existing ownerless `targetDir` without exposing a
 * 0-byte `owner.json`. Prepares a complete temp file in `dir`, then hard-links it to
 * `targetDir/owner.json` (`EEXIST` if another writer published `owner.json` first). Falls back
 * to `writeFile(..., { flag: "wx" })` only when hard links are unsupported by the filesystem.
 */
async function fenceOwnerlessLockDir(
	dir: string,
	targetDir: string,
	fenceMeta: LockOwnerMeta,
): Promise<void> {
	const ownerFile = path.join(targetDir, "owner.json");
	const payload = JSON.stringify(fenceMeta);
	const tmpFence = path.join(
		dir,
		`.ledger.fence.${process.pid}.${++tmpSeq}-${Math.random().toString(36).slice(2, 8)}.tmp`,
	);
	await fs.writeFile(tmpFence, payload, { encoding: "utf8", flag: "wx" });
	try {
		await fs.link(tmpFence, ownerFile);
	} catch (linkErr: any) {
		if (
			linkErr?.code === "ENOSYS" ||
			linkErr?.code === "EXDEV" ||
			linkErr?.code === "EPERM" ||
			linkErr?.code === "ENOTSUP" ||
			linkErr?.code === "EOPNOTSUPP"
		) {
			await fs.writeFile(ownerFile, payload, { encoding: "utf8", flag: "wx" });
		} else {
			throw linkErr;
		}
	} finally {
		await fs.rm(tmpFence, { force: true }).catch(() => {});
	}
}

/**
 * Best-effort mark a specific lock directory generation (`holderDir`) as `released: true`
 * only if `holderDir` still exists and either still carries `expectedMeta.token` or lost its
 * `owner.json` mid-`rm` without acquiring another owner's metadata. Never writes to the
 * reusable lock path once a generation has been detached to `trashDir`.
 */
async function markHolderReleasedIfOwned(
	holderDir: string,
	expectedMeta: LockOwnerMeta,
): Promise<void> {
	if (!(await pathExists(holderDir).catch(() => false))) {
		return;
	}
	const ownerFile = path.join(holderDir, "owner.json");
	const releasedPayload = JSON.stringify({ ...expectedMeta, released: true });
	try {
		const cur = parseLockOwner(await fs.readFile(ownerFile, "utf8"));
		if (!cur || cur.token !== expectedMeta.token) {
			return;
		}
		const tmpRel = path.join(
			holderDir,
			`.owner.rel.${process.pid}.${++tmpSeq}-${Math.random().toString(36).slice(2, 8)}.tmp`,
		);
		try {
			await fs.writeFile(tmpRel, releasedPayload, { encoding: "utf8", flag: "wx" });
			const recheck = parseLockOwner(await fs.readFile(ownerFile, "utf8"));
			if (!recheck || recheck.token !== expectedMeta.token) {
				await fs.rm(tmpRel, { force: true }).catch(() => {});
				return;
			}
			await fs.rename(tmpRel, ownerFile);
		} catch {
			await fs.rm(tmpRel, { force: true }).catch(() => {});
		}
	} catch (err: any) {
		if (err?.code === "ENOENT" && (await pathExists(holderDir).catch(() => false))) {
			await fenceOwnerlessLockDir(path.dirname(holderDir), holderDir, {
				...expectedMeta,
				released: true,
			}).catch(() => {});
		}
	}
}

/**
 * Reclaim a specific stale lock generation using a generation-addressed lease directory
 * (`.ledger.reclaim.<genHash>`). When reclaiming an external ownerless directory
 * (`expectedToken === null` and `owner.json` absent), atomically claims `owner.json` before
 * detachment, and carries `detachState.holderDir` into cleanup error handling so post-detachment
 * errors never touch the reusable `targetDir`.
 */
async function reclaimStaleLockGeneration(
	dir: string,
	targetDir: string,
	targetActiveSet: Set<string>,
	stale: { expectedToken: string | null; rawOwnerPresent: boolean; expectedMtimeMs: number | null },
	replacementToken: string | null,
	depth = 0,
): Promise<"acquired" | "reclaimed" | "retry"> {
	const genKey =
		stale.expectedToken !== null ? `tok:${stale.expectedToken}` : `uninit:${targetDir}`;
	const reclaimDir = path.join(dir, `.ledger.reclaim.${sha12(genKey)}`);
	const claimToken = `reclaim-${process.pid}-${++lockSeq}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

	let wonLease = false;
	try {
		wonLease = await createOwnedLockDir(reclaimDir, claimToken, activeInProcessReclaims);
	} catch (err: any) {
		if (err?.code !== "EEXIST") throw err;
		if (depth < 2) {
			const leaseInspection = await inspectLockDir(reclaimDir, activeInProcessReclaims);
			if (leaseInspection.state === "stale") {
				await reclaimStaleLockGeneration(
					dir,
					reclaimDir,
					activeInProcessReclaims,
					leaseInspection,
					null,
					depth + 1,
				);
			}
		}
		return "retry";
	}

	if (!wonLease) {
		return "retry";
	}

	let fenceMeta: LockOwnerMeta | null = null;
	const detachState: DetachState = { detached: false, holderDir: targetDir };
	try {
		const stillStale = await stillMatchesStaleInspection(targetDir, targetActiveSet, stale);
		if (!stillStale) {
			return "retry";
		}

		let fencedExpectedToken = stale.expectedToken;
		if (fencedExpectedToken === null && !stale.rawOwnerPresent) {
			const tombstoneToken = `fence-${process.pid}-${++lockSeq}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
			const candidateFence: LockOwnerMeta = {
				token: tombstoneToken,
				pid: process.pid,
				host: CURRENT_HOST,
				acquiredAtMs: Date.now(),
			};
			targetActiveSet.add(tombstoneToken);
			try {
				await fenceOwnerlessLockDir(dir, targetDir, candidateFence);
				fenceMeta = candidateFence;
				fencedExpectedToken = tombstoneToken;
			} catch (fenceErr: any) {
				targetActiveSet.delete(tombstoneToken);
				if (fenceErr?.code === "EEXIST" || fenceErr?.code === "ENOENT") {
					return "retry";
				}
				throw fenceErr;
			}
		}

		let removed = false;
		try {
			removed = await detachAndRemoveLockGeneration(
				targetDir,
				fencedExpectedToken,
				"stale",
				detachState,
			);
		} catch (rmErr) {
			if (fenceMeta !== null) {
				await markHolderReleasedIfOwned(detachState.holderDir, fenceMeta);
			}
			throw rmErr;
		}
		if (!removed) {
			if (fenceMeta !== null) {
				await markHolderReleasedIfOwned(detachState.holderDir, fenceMeta);
			}
			return "retry";
		}
		if (replacementToken === null) {
			return "reclaimed";
		}
		try {
			const ok = await createOwnedLockDir(targetDir, replacementToken, targetActiveSet);
			return ok ? "acquired" : "retry";
		} catch (acqErr: any) {
			if (acqErr?.code === "EEXIST") return "retry";
			throw acqErr;
		}
	} finally {
		if (fenceMeta !== null) {
			targetActiveSet.delete(fenceMeta.token);
		}
		await releaseOwnedLockDir(reclaimDir, claimToken, activeInProcessReclaims, 1, false);
	}
}

async function releaseOwnedLockDir(
	lockDir: string,
	myToken: string,
	activeSet: Set<string>,
	retryCount: number,
	rethrowOnFailure: boolean,
): Promise<void> {
	const ownerFile = path.join(lockDir, "owner.json");
	try {
		let initialOwner: LockOwnerMeta | null = null;
		try {
			initialOwner = parseLockOwner(await fs.readFile(ownerFile, "utf8"));
		} catch (err: any) {
			if (err?.code === "ENOENT") return;
			if (!rethrowOnFailure) return;
			throw err;
		}
		if (!initialOwner || initialOwner.token !== myToken) {
			return;
		}

		let lastErr: unknown = null;
		for (let attempt = 0; attempt < retryCount; attempt++) {
			if (attempt > 0) {
				if (!(await pathExists(lockDir).catch(() => false))) {
					break;
				}
				try {
					const cur = parseLockOwner(await fs.readFile(ownerFile, "utf8"));
					if (!cur || cur.token !== myToken) {
						break;
					}
				} catch (probeErr: any) {
					if (probeErr?.code !== "ENOENT") {
						lastErr = probeErr;
					}
					break;
				}
			}

			try {
				await fs.rm(lockDir, { recursive: true, maxRetries: 0 });
				return;
			} catch (rmErr: any) {
				if (rmErr?.code === "ENOENT") return;
				lastErr = rmErr;
				if (attempt + 1 < retryCount) {
					await sleep(5 * (attempt + 1));
				}
			}
		}

		await markHolderReleasedIfOwned(lockDir, initialOwner);
		if (rethrowOnFailure && lastErr !== null) {
			throw lastErr;
		}
	} finally {
		activeSet.delete(myToken);
	}
}

async function releaseOwnedLock(lockDir: string, myToken: string): Promise<void> {
	await releaseOwnedLockDir(lockDir, myToken, activeInProcessLocks, RELEASE_RETRY_COUNT, true);
}

export async function withLedgerLock<T>(dir: string, fn: () => Promise<T>): Promise<T> {
	await fs.mkdir(dir, { recursive: true });
	const lockDir = path.join(dir, ".ledger.lock");
	const myToken = `${process.pid}-${++lockSeq}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
	const deadline = Date.now() + LOCK_TIMEOUT_MS;

	while (true) {
		try {
			const ok = await createOwnedLockDir(lockDir, myToken, activeInProcessLocks);
			if (ok) break;
		} catch (err: any) {
			if (err?.code !== "EEXIST") throw err;
		}

		const inspection = await inspectLockDir(lockDir, activeInProcessLocks);
		let outcome: "acquired" | "reclaimed" | "retry" | "live" = "live";
		if (inspection.state === "vanished") {
			outcome = "retry";
		} else if (inspection.state === "stale") {
			outcome = await reclaimStaleLockGeneration(
				dir,
				lockDir,
				activeInProcessLocks,
				inspection,
				myToken,
			);
			if (outcome === "acquired") {
				break;
			}
		}

		const now = Date.now();
		if (now >= deadline) {
			throw new Error(`Timed out acquiring cache-lens ledger lock at ${lockDir}`);
		}
		const maxWait = outcome === "retry" ? 2 : 10 + Math.floor(Math.random() * 25);
		await sleep(Math.min(maxWait, Math.max(1, deadline - now)));
	}

	let fnFailed = false;
	try {
		return await fn();
	} catch (err) {
		fnFailed = true;
		throw err;
	} finally {
		if (fnFailed) {
			await releaseOwnedLock(lockDir, myToken).catch(() => {});
		} else {
			await releaseOwnedLock(lockDir, myToken);
		}
	}
}

/**
 * Redact secrets and bound length across all caller- or wire-derived string fields
 * before writing to disk. Producer-generated ISO timestamps, hex SHA prefixes, and
 * enum `diagnosis` codes pass through structurally intact.
 */
export function sanitizeRecordForPersistence(record: TurnCacheRecord): TurnCacheRecord {
	return {
		...record,
		sessionId: sanitizeFreeText(record.sessionId, 128),
		cwd: sanitizeFreeText(record.cwd, 512),
		provider: sanitizeFreeText(record.provider, 96),
		requestedModel: sanitizeIdentifierKeepTail(record.requestedModel, 160),
		model: sanitizeIdentifierKeepTail(record.model, 160),
		api: sanitizeFreeText(record.api, 96),
		thinkingLevel: sanitizeFreeText(record.thinkingLevel, 64),
		providerThinkingLevel:
			record.providerThinkingLevel !== null ? sanitizeFreeText(record.providerThinkingLevel, 64) : null,
		promptCacheKey: record.promptCacheKey !== null ? sanitizeFreeText(record.promptCacheKey, 128) : null,
		observedChanges: record.observedChanges.map((c) => sanitizeFreeText(c, 48)),
		shortTag: sanitizeFreeText(record.shortTag, 32),
		detail: sanitizeFreeText(record.detail, 320),
	};
}

async function rotateIfHuge(filePath: string, maxLogBytes: number): Promise<void> {
	let st: Awaited<ReturnType<typeof fs.stat>>;
	try {
		st = await fs.stat(filePath);
	} catch (err: any) {
		if (err?.code === "ENOENT") return;
		throw err;
	}
	if (st.size > maxLogBytes) {
		await fs.rename(filePath, `${filePath}.1`);
	}
}

function parseJsonlContent(raw: string): TurnCacheRecord[] {
	if (!raw) return [];
	return raw
		.split("\n")
		.filter(Boolean)
		.map((line) => {
			try {
				return JSON.parse(line) as TurnCacheRecord;
			} catch {
				return null;
			}
		})
		.filter((x): x is TurnCacheRecord => x !== null);
}

async function readTextIfExists(filePath: string): Promise<string | null> {
	try {
		return await fs.readFile(filePath, "utf8");
	} catch (err: any) {
		if (err?.code === "ENOENT") return null;
		throw err;
	}
}

export async function readRecentJsonlUnlocked(filePath: string, maxLines: number): Promise<TurnCacheRecord[]> {
	if (maxLines <= 0) return [];
	let fallbackSingle: TurnCacheRecord[] = [];
	for (let attempt = 0; attempt < 4; attempt++) {
		const rawActive1 = await readTextIfExists(filePath);
		const active1 = rawActive1 !== null ? parseJsonlContent(rawActive1) : [];
		if (active1.length >= maxLines) {
			return active1.slice(-maxLines);
		}
		const rawRotated = await readTextIfExists(`${filePath}.1`);
		const rawActive2 = await readTextIfExists(filePath);
		const active2 = rawActive2 !== null ? parseJsonlContent(rawActive2) : [];
		const rotated = rawRotated !== null ? parseJsonlContent(rawRotated) : [];

		if (active2.length > 0) fallbackSingle = active2;
		else if (active1.length > 0) fallbackSingle = active1;
		else if (rotated.length > 0) fallbackSingle = rotated;

		const consistent =
			(rawActive1 === null && rawActive2 === null) ||
			(rawActive1 !== null &&
				rawActive2 !== null &&
				rawActive2.startsWith(rawActive1) &&
				(rawRotated === null || rawActive1.length === 0 || rawRotated !== rawActive1));

		if (consistent) {
			const active = rawActive2 !== null ? active2 : active1;
			if (active.length >= maxLines) {
				return active.slice(-maxLines);
			}
			if (rotated.length === 0) return active;
			const needed = maxLines - active.length;
			return [...rotated.slice(-needed), ...active];
		}
	}
	return fallbackSingle.slice(-maxLines);
}

export async function readRecentJsonl(filePath: string, maxLines: number): Promise<TurnCacheRecord[]> {
	if (maxLines <= 0) return [];
	const dir = path.dirname(filePath);
	try {
		await fs.stat(dir);
	} catch (err: any) {
		if (err?.code === "ENOENT") return [];
		throw err;
	}
	try {
		return await withLedgerLock(dir, () => readRecentJsonlUnlocked(filePath, maxLines));
	} catch (err: any) {
		if (err?.code === "EACCES" || err?.code === "EPERM" || err?.code === "EROFS") {
			return await readRecentJsonlUnlocked(filePath, maxLines);
		}
		throw err;
	}
}

async function refreshMarkdownReportUnlocked(
	dir: string,
	eventsFile: string,
	anomaliesFile: string,
	locale: Locale,
): Promise<void> {
	const zh = locale === "zh";
	const recentEvents = await readRecentJsonlUnlocked(eventsFile, 500);
	const recentAnomalies = await readRecentJsonlUnlocked(anomaliesFile, 25);

	const byModel = new Map<
		string,
		{ calls: number; promptTotal: number; cacheRead: number; anomalies: number; costUsd: number }
	>();
	for (const ev of recentEvents) {
		const key = `${ev.provider}/${ev.model}`;
		const cur = byModel.get(key) ?? { calls: 0, promptTotal: 0, cacheRead: 0, anomalies: 0, costUsd: 0 };
		cur.calls += 1;
		cur.promptTotal += ev.promptTotal;
		cur.cacheRead += ev.cacheRead;
		cur.costUsd += ev.costUsd;
		if (ev.anomaly) cur.anomalies += 1;
		byModel.set(key, cur);
	}

	const lines: string[] = zh
		? [
				"# Pi Prefix KV Cache 诊断账本",
				"",
				`更新时间: ${new Date().toISOString()}`,
				`数据目录: \`${sanitizeFreeText(dir, 512)}\` (\`events.jsonl\` 全量流水 / \`anomalies.jsonl\` 异常掉缓存专表)`,
				"",
				"## 按模型汇总（最近 500 次调用）",
				"",
				"| 模型 | 调用次数 | 累计输入 Tokens | 累计命中 Tokens | 综合缓存命中率 | 异常掉缓存次数 | 累计费用 |",
				"|---|---:|---:|---:|---:|---:|---:|",
			]
		: [
				"# Pi Prefix KV Cache Diagnostics",
				"",
				`Updated: ${new Date().toISOString()}`,
				`Directory: \`${sanitizeFreeText(dir, 512)}\` (\`events.jsonl\` full log / \`anomalies.jsonl\` cache drops)`,
				"",
				"## Summary by Model (Last 500 Calls)",
				"",
				"| Model | Calls | Prompt Tokens | Cache Read Tokens | Hit Rate | Anomalies | Cost |",
				"|---|---:|---:|---:|---:|---:|---:|",
			];

	for (const [model, s] of [...byModel.entries()].sort((a, b) => b[1].promptTotal - a[1].promptTotal)) {
		const rate = s.promptTotal > 0 ? ((s.cacheRead * 100) / s.promptTotal).toFixed(1) : "0.0";
		const safeModel = sanitizeIdentifierKeepTail(model, 160).replace(/\|/g, "\\|");
		lines.push(
			`| \`${safeModel}\` | ${s.calls} | ${s.promptTotal.toLocaleString()} | ${s.cacheRead.toLocaleString()} | **${rate}%** | ${s.anomalies} | $${s.costUsd.toFixed(4)} |`,
		);
	}

	lines.push("", zh ? "## 最近 25 次掉缓存异常根因" : "## Latest 25 Cache-Drop Anomalies", "");
	if (recentAnomalies.length === 0) {
		lines.push(zh ? "暂无异常掉缓存记录。" : "No cache-drop anomalies recorded.");
	} else {
		lines.push(
			zh
				? "| 时间 | 会话 | 轮次 | 模型 | 单次 / 会话命中率 | 根因分类 | 详细证据 |"
				: "| Time | Session | Call | Model | Single / Session | Cause | Detail |",
		);
		lines.push("|---|---|---:|---|---:|---|---|");
		for (const a of [...recentAnomalies].reverse()) {
			const shortSid = sanitizeFreeText(a.sessionId, 32).slice(0, 8).replace(/\|/g, "\\|");
			const safeModel = sanitizeIdentifierKeepTail(a.model, 128).replace(/\|/g, "\\|");
			const safeDetail = sanitizeFreeText(a.detail, 320).replace(/\|/g, "\\|");
			const singleCell = a.singleHitPct !== null ? `${a.singleHitPct.toFixed(1)}%` : "n/a";
			lines.push(
				`| ${a.ts.slice(0, 19).replace("T", " ")} | \`${shortSid}\` | #${a.callIndex} | \`${safeModel}\` | ${singleCell} / ${a.sessionHitPct.toFixed(1)}% | \`${a.diagnosis}\` | ${safeDetail} |`,
			);
		}
	}
	lines.push("");

	const reportPath = path.join(dir, "latest-report.md");
	const tmpPath = path.join(dir, `.latest-report.${process.pid}.${++tmpSeq}.tmp`);
	try {
		await fs.writeFile(tmpPath, lines.join("\n"), "utf8");
		await fs.rename(tmpPath, reportPath);
	} catch (err) {
		await fs.rm(tmpPath, { force: true }).catch(() => {});
		throw err;
	}
}

export async function refreshMarkdownReport(
	dir: string,
	eventsFile: string,
	anomaliesFile: string,
	locale: Locale,
): Promise<void> {
	await withLedgerLock(dir, () => refreshMarkdownReportUnlocked(dir, eventsFile, anomaliesFile, locale));
}

export async function persistRecord(
	record: TurnCacheRecord,
	dir: string,
	maxLogBytes: number,
	locale: Locale,
): Promise<void> {
	const safeRecord = sanitizeRecordForPersistence(record);
	const serialized = `${JSON.stringify(safeRecord)}\n`;
	await withLedgerLock(dir, async () => {
		const eventsFile = path.join(dir, "events.jsonl");
		const anomaliesFile = path.join(dir, "anomalies.jsonl");
		await rotateIfHuge(eventsFile, maxLogBytes);
		await fs.appendFile(eventsFile, serialized, "utf8");
		if (safeRecord.anomaly) {
			await rotateIfHuge(anomaliesFile, maxLogBytes);
			await fs.appendFile(anomaliesFile, serialized, "utf8");
		}
		await refreshMarkdownReportUnlocked(dir, eventsFile, anomaliesFile, locale);
	});
}
