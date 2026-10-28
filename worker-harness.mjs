// Test-only harness. Worker.js ships no test hooks; this file appends them to a
// temporary copy so tests can reach module-private helpers and reset state.
// The temporary copy is removed as soon as it has been imported.
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const hooks = `
function questionEndOf(query) {
  return parseDNSQuestion(query instanceof Uint8Array ? query : new Uint8Array(query)).questionEnd;
}
function metadataOf(body) {
  return validateDNSMessage(body).metadata;
}
function getDNSCacheTTL(responseBuffer) {
  return validateDNSMessage(responseBuffer).metadata?.ttl ?? 0;
}
function localKeyOf(query) {
  return localCacheKey(cacheKeyBytes(query, questionEndOf(query)));
}
// Test hook: in addition to resolver statistics, clears every module-level
// map (L1 cache, throttle, penalty, in-flight jobs) and resets the resolver
// rotation cursor and sweep timestamp. Tests must await all pending
// asynchronous work before this runs.
function resetAppState() {
  for (const node of RESOLVER_NODES) {
    node.score = CONFIG.SCORE_START;
    node.ok = 0;
    node.fail = 0;
    node.timeout = 0;
    node.slow = 0;
    node.lastLatencyMs = null;
    node.ewmaLatencyMs = null;
    node.lastError = null;
    node.lastScoreUpdateAt = 0;
  }
  APP_STATE.cache.clear();
  APP_STATE.cacheBytes = 0;
  APP_STATE.throttle.clear();
  APP_STATE.penalty.clear();
  APP_STATE.inflight.clear();
  APP_STATE.primaryCursor = 0;
  APP_STATE.lastSweepAt = 0;
}
export const __internals = {
  CONFIG, RESOLVER_NODES, rateLimitKey, recoverScore, fallbackPriority, getHealthSnapshot,
  parseDNSQuestion,
  validateDNSResponse: (body, id, query) => validateDNSMessage(body, {
    expectedID: id ?? null, queryBytes: query ?? null, questionEnd: query ? questionEndOf(query) : null
  }),
  validateDNSMessage,
  decodeBase64Url,
  cacheKeyBytes: (query, qe) => cacheKeyBytes(query, qe ?? questionEndOf(query)),
  localKeyOf,
  // L2 (edge) key of a query, as used in the Cache API URL.
  makeCacheKey: (query) => edgeCacheKey(cacheKeyBytes(query, questionEndOf(query))),
  getDNSCacheTTL,
  patchDNSResponseForAge: (body, id, age, query = null, metadata = null) =>
    patchDNSResponseForAge(body, id, age, query, metadata ?? metadataOf(body)),
  toExactArrayBuffer,
  readCappedBody,
  getHedgeDelay,
  localRateLimit: (ip) => localRateLimit(rateLimitKey(ip)),
  rateLimitState: (ip) => ({
    throttle: APP_STATE.throttle.has(rateLimitKey(ip)),
    penalty: APP_STATE.penalty.has(rateLimitKey(ip))
  }),
  selectRacers,
  setCache: (key, body, ttl, storedAt = Date.now(), metadata = null) =>
    setCache(key, body, ttl, storedAt, metadata ?? metadataOf(body)),
  resetAppState,
  hasInflight: (query) => APP_STATE.inflight.has(localKeyOf(query)),
  joinerCount: (query) => APP_STATE.inflight.get(localKeyOf(query))?.joiners ?? 0,
  inflightEntry: (query) => APP_STATE.inflight.get(localKeyOf(query)) ?? null,
  injectInflight: (query, entry) => APP_STATE.inflight.set(localKeyOf(query), entry)
};
`;
const source = await readFile(new URL('./Worker.js', import.meta.url), 'utf8');
const dir = await mkdtemp(join(tmpdir(), 'doh-worker-test-'));
const file = join(dir, 'Worker.test.mjs');
await writeFile(file, `${source}\n${hooks}`);
let module;
try {
  module = await import(pathToFileURL(file));
} finally {
  await rm(dir, { recursive: true, force: true });
}
export default module.default;
export const __internals = module.__internals;
