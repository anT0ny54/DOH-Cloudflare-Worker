// Test-only harness. Worker.js ships no test hooks; this file appends them to a
// temporary copy so tests can reach module-private helpers and reset state.
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const hooks = `
function getDNSCacheTTL(responseBuffer) {
  return validateDNSMessage(responseBuffer).metadata?.ttl ?? 0;
}
function resetResolverState() {
  // Test hook: tests within a file share RESOLVER_NODES, so score-sensitive
  // tests reset it via beforeEach instead of snapshotting around mutations.
  for (const node of RESOLVER_NODES) {
    node.score = CONFIG.SCORE_START;
    node.ok = 0;
    node.fail = 0;
    node.timeout = 0;
    node.lastLatencyMs = null;
    node.ewmaLatencyMs = null;
    node.lastError = null;
  }
  for (const node of RESOLVER_NODES) node.lastScoreUpdateAt = 0;
}

// Test-only hook: in addition to resolver statistics, clears every
// module-level map (L1 cache, throttle, penalty, in-flight jobs) and resets
// the resolver rotation cursor and sweep timestamp. Tests must await all
// pending asynchronous work before this runs.
function resetAppState() {
  resetResolverState();
  APP_STATE.cache.clear();
  APP_STATE.cacheBytes = 0;
  APP_STATE.throttle.clear();
  APP_STATE.penalty.clear();
  APP_STATE.inflight.clear();
  APP_STATE.primaryCursor = 0;
  APP_STATE.lastSweepAt = 0;
}
export const __internals = {
  CONFIG, rateLimitKey, cacheKeyBytes, recoverScore, fallbackPriority, getHealthSnapshot,
  parseDNSQuestion,
  validateDNSResponse: (body, id, query) => validateDNSMessage(body, { expectedID: id, queryBytes: query }),
  validateDNSMessage,
  decodeBase64Url,
  makeCacheKey,
  getDNSCacheTTL,
  patchDNSResponseForAge,
  toExactArrayBuffer,
  readCappedBody,
  getHedgeDelay,
  localRateLimit,
  selectRacers,
  setCache,
  resetAppState,
  hasInflight: (key) => APP_STATE.inflight.has(key)
};
`;
const source = await readFile(new URL('./Worker.js', import.meta.url), 'utf8');
const file = join(await mkdtemp(join(tmpdir(), 'doh-worker-test-')), 'Worker.test.mjs');
await writeFile(file, `${source}\n${hooks}`);
const module = await import(pathToFileURL(file));
export default module.default;
export const __internals = module.__internals;
