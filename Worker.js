const VERSION = '0.5.3';
const CONFIG = {
  DNS_PATH: '/dns-query',
  EDGE_CACHE_ENABLED: true,
  EDGE_CACHE_PATH: '/__doh-cache/v1',
  LOCAL_CACHE_MAX_TTL_SECONDS: 300,
  EDGE_CACHE_MAX_TTL_SECONDS: 86_400,
  MAX_CACHE_ENTRIES: 512,
  MAX_CACHE_BYTES: 8 * 1024 * 1024,
  SCORE_RECOVERY_INTERVAL_MS: 60_000,
  MAX_INFLIGHT_ENTRIES: 128,
  // A joiner waits at most this long for another request's resolution, and an
  // in-flight entry older than this is treated as lost (its owner may have
  // been cancelled). Attempts overlap through hedging, so a real resolution
  // ends well within 3 x UPSTREAM_TIMEOUT_MS = 3600 ms (a conservative bound);
  // the join timeout must stay above that, or every joiner duplicates a full
  // resolution exactly when the upstreams are degraded.
  INFLIGHT_JOIN_TIMEOUT_MS: 4000,
  // Must match [ratelimits.simple] in wrangler.toml (a test enforces this).
  RATE_LIMIT_WINDOW_MS: 60_000,
  RATE_LIMIT_MAX_REQUESTS: 100,
  MAX_THROTTLE_ENTRIES: 2048,
  MAX_PENALTY_ENTRIES: 256,
  STATE_SWEEP_INTERVAL_MS: 60_000,
  MAX_DNS_MESSAGE_BYTES: 4096,
  MAX_GET_DNS_CHARS: 5462,
  MAX_UPSTREAM_DNS_MESSAGE_BYTES: 65_535,
  UPSTREAM_TIMEOUT_MS: 1200,
  HEDGE_MIN_MS: 80,
  HEDGE_MAX_MS: 220,
  SECONDARY_HEDGE_MS: 150,
  SCORE_START: 100,
  SCORE_MIN: 0,
  SCORE_MAX: 100,
  SCORE_SUCCESS_DELTA: 1,
  SCORE_FAILURE_DELTA: 12,
  SCORE_TIMEOUT_DELTA: 8,
  // Penalty for an attempt that was overtaken by a later-started hedge.
  SCORE_SLOW_DELTA: 2,
  // Resolvers scoring strictly more than (best - window) form the first-choice
  // pool. Keep it <= SCORE_TIMEOUT_DELTA so one timeout leaves the pool.
  PRIMARY_POOL_SCORE_WINDOW: 8,
  // Every Nth upstream resolution starts with a non-fastest pool member so
  // the latency estimates of the others stay fresh.
  PRIMARY_EXPLORE_EVERY: 10
};
const HAGEZI_UPSTREAMS = [
  'https://root.hagezi.org/dns-query',
  'https://wurzn.hagezi.org/dns-query',
  'https://juuri.hagezi.org/dns-query'
];
const RESOLVER_NODES = HAGEZI_UPSTREAMS.map((url, order) => ({
  url,
  order,
  score: CONFIG.SCORE_START,
  ok: 0,
  fail: 0,
  timeout: 0,
  slow: 0,
  lastLatencyMs: null,
  ewmaLatencyMs: null,
  lastScoreUpdateAt: 0,
  lastError: null
}));
const APP_STATE = {
  cache: new Map(),
  cacheBytes: 0,
  throttle: new Map(),
  penalty: new Map(),
  inflight: new Map(),
  primaryCursor: 0,
  lastSweepAt: 0
};
const CORS_HEADERS = {
  'access-control-allow-origin': '*',
  'access-control-expose-headers': 'x-cache, x-edge-cache, x-upstreams, x-winner, x-winner-lat, x-dns-degraded'
};
export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (url.pathname === CONFIG.DNS_PATH) {
      // CORS preflight carries no DNS query: answer it before the limiter so
      // browser clients do not spend a rate-limit token per preflight.
      if (req.method === 'OPTIONS') return preflightResponse();
      maybeSweepState();
      if (!(await allowDNSRequest(getClientIP(req), env))) {
        return dnsErrorResponse('Rate limit exceeded', 429, { 'retry-after': '60' });
      }
      return handleDNS(req, url, ctx);
    }
    if (url.pathname === '/health') {
      maybeSweepState();
      return jsonResponse(getHealthSnapshot(), 200, {
        'cache-control': 'no-store'
      });
    }
    if (url.pathname === '/' || url.pathname === '/index.html') {
      return renderUI(url.host);
    }
    return textResponse('Not found', 404);
  }
};
async function handleDNS(req, url, ctx) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    return dnsErrorResponse('Method not allowed', 405, { allow: 'GET, POST, OPTIONS' });
  }
  let payload;
  try {
    payload = await readDNSPayload(req, url);
  } catch (err) {
    return dnsErrorResponse(err.status ? err.message : 'Invalid DNS query', err.status || 400);
  }
  const parsed = parseDNSQuestion(payload);
  if (!parsed.ok) return dnsErrorResponse(parsed.error, 400);
  const keyBytes = cacheKeyBytes(payload, parsed.questionEnd);
  const key = localCacheKey(keyBytes);
  const localHit = getCache(key);
  if (localHit) return l1Response(localHit, parsed.id, payload);
  const existing = getLiveInflight(key);
  if (existing) {
    existing.joiners += 1;
    const outcome = await settleWithin(existing.job, CONFIG.INFLIGHT_JOIN_TIMEOUT_MS);
    if (outcome.status === 'fulfilled') return sharedDNSResponse(outcome.value, parsed, payload, 'COALESCED');
    if (outcome.status === 'rejected') return upstreamFailureResponse(0);
    // Timed out: the owner of that job is presumed lost (e.g. its request was
    // cancelled). Resolve independently; startJob() replaces the stale entry.
  }
  const entry = startJob(key, keyBytes, payload, parsed, url.origin, ctx);
  try {
    const shared = await entry.job;
    return sharedDNSResponse(shared, parsed, payload, shared.source);
  } catch (err) {
    // resolveWithHedging always attaches the real attempt count; 0 covers a
    // pathological throw instead of reporting phantom attempts.
    return upstreamFailureResponse(err?.attempts ?? 0);
  }
}
// Registers the resolution synchronously (so concurrent misses coalesce onto
// it) and detaches it from the creating request with ctx.waitUntil: if that
// request is cancelled, the job still settles, joiners are released and the
// in-flight entry is removed.
function startJob(key, keyBytes, payload, parsed, origin, ctx) {
  // `joiners` is bookkeeping read only by the test harness (it lets tests wait
  // deterministically until requests have attached to this job).
  const entry = { job: null, createdAt: Date.now(), joiners: 0 };
  entry.job = resolveShared(key, keyBytes, payload, parsed, origin, ctx).finally(() => {
    if (APP_STATE.inflight.get(key) === entry) APP_STATE.inflight.delete(key);
  });
  APP_STATE.inflight.set(key, entry);
  trimMap(APP_STATE.inflight, CONFIG.MAX_INFLIGHT_ENTRIES);
  // The swallowed copy also keeps a failed job with no joiners from surfacing
  // as an unhandled rejection, even when ctx has no waitUntil.
  runInBackground(ctx, entry.job.catch(() => {}));
  return entry;
}
function getLiveInflight(key) {
  const entry = APP_STATE.inflight.get(key);
  if (!entry) return null;
  if (Date.now() - entry.createdAt < CONFIG.INFLIGHT_JOIN_TIMEOUT_MS) return entry;
  APP_STATE.inflight.delete(key);
  return null;
}
async function settleWithin(promise, timeoutMs) {
  let timeoutId;
  const timer = new Promise((resolve) => {
    timeoutId = setTimeout(() => resolve({ status: 'timeout' }), timeoutMs);
  });
  try {
    return await Promise.race([
      promise.then((value) => ({ status: 'fulfilled', value }), (reason) => ({ status: 'rejected', reason })),
      timer
    ]);
  } finally {
    clearTimeout(timeoutId);
  }
}
async function resolveShared(key, keyBytes, payload, parsed, origin, ctx) {
  let edgeKey = null;
  if (CONFIG.EDGE_CACHE_ENABLED) {
    edgeKey = await edgeCacheKey(keyBytes);
    const edgeHit = await getEdgeCache(edgeKey, origin, payload, parsed.questionEnd, ctx);
    if (edgeHit) {
      setCache(
        key,
        edgeHit.body,
        Math.min(edgeHit.remainingSeconds, CONFIG.LOCAL_CACHE_MAX_TTL_SECONDS),
        edgeHit.storedAt,
        edgeHit.metadata
      );
      // No write-back on an L2 hit: re-putting the entry with its remaining
      // TTL would expire at the same instant and only cost a subrequest.
      return {
        source: 'L2-HIT',
        body: edgeHit.body,
        metadata: edgeHit.metadata,
        storedAt: edgeHit.storedAt,
        url: null,
        latencyMs: 0,
        attempts: 0,
        degraded: false
      };
    }
  }
  const resolvers = selectRacers(RESOLVER_NODES);
  const result = await resolveWithHedging(resolvers, payload, parsed.id, parsed.questionEnd);
  const storedAt = Date.now();
  const ttlSeconds = result.metadata.ttl;
  if (ttlSeconds > 0) {
    setCache(
      key,
      result.body,
      Math.min(ttlSeconds, CONFIG.LOCAL_CACHE_MAX_TTL_SECONDS),
      storedAt,
      result.metadata
    );
    if (edgeKey) {
      runInBackground(ctx, putEdgeCache(edgeKey, result.body, ttlSeconds, storedAt, origin));
    }
  }
  return {
    source: 'MISS',
    body: result.body,
    metadata: result.metadata,
    storedAt,
    url: result.url,
    latencyMs: result.latencyMs,
    attempts: result.attempts,
    degraded: result.degraded
  };
}
function runInBackground(ctx, promise) {
  // Scheduling background work must never fail the client request; the
  // scheduled promises already swallow their own errors.
  try { ctx?.waitUntil?.(promise); } catch (_) {}
}
function cacheAgeSeconds(storedAt) {
  return Math.max(0, Math.floor((Date.now() - storedAt) / 1000));
}
function l1Response(entry, queryID, queryBytes) {
  return dnsResponse(patchDNSResponseForAge(entry.body, queryID, cacheAgeSeconds(entry.storedAt), queryBytes, entry.metadata), {
    'x-cache': 'L1-HIT',
    'x-edge-cache': 'SKIP',
    'x-upstreams': '0'
  });
}
// Builds the per-client response from a shared resolution. The shared body is
// never modified: every client gets a copy with its own transaction ID,
// QNAME letter case and age-adjusted TTLs.
function sharedDNSResponse(shared, parsed, queryBytes, tag) {
  const responseBody = patchDNSResponseForAge(shared.body, parsed.id, cacheAgeSeconds(shared.storedAt), queryBytes, shared.metadata);
  const own = tag === shared.source;
  const headers = {
    'x-cache': tag,
    'x-edge-cache': tag === 'L2-HIT' ? 'HIT' : tag === 'MISS' ? (CONFIG.EDGE_CACHE_ENABLED ? 'MISS' : 'DISABLED') : 'SKIP',
    'x-upstreams': String(own ? shared.attempts : 0)
  };
  if (shared.url) {
    headers['x-winner'] = shared.url;
    headers['x-winner-lat'] = `${shared.latencyMs}ms`;
  }
  if (shared.degraded) headers['x-dns-degraded'] = '1';
  return dnsResponse(responseBody, headers);
}
function upstreamFailureResponse(attempts) {
  return dnsErrorResponse('Global resolving failed', 502, { 'x-upstreams': String(attempts) });
}
async function readDNSPayload(req, url) {
  if (req.method === 'GET') {
    const q = url.searchParams.get('dns');
    if (!q) throw httpError('Missing dns query parameter', 400);
    if (q.length > CONFIG.MAX_GET_DNS_CHARS) {
      throw httpError('DNS query too large', 413);
    }
    return decodeBase64Url(q);
  }
  const mediaType = (req.headers.get('content-type') || '')
    .split(';', 1)[0]
    .trim()
    .toLowerCase();
  if (mediaType !== 'application/dns-message') {
    throw httpError('POST requires content-type: application/dns-message', 415);
  }
  const contentLength = req.headers.get('content-length');
  if (contentLength !== null) {
    const n = Number(contentLength);
    if (Number.isFinite(n) && n > CONFIG.MAX_DNS_MESSAGE_BYTES) {
      throw httpError('DNS message too large', 413);
    }
  }
  return readCappedBody(
    req,
    CONFIG.MAX_DNS_MESSAGE_BYTES,
    'DNS message too large'
  );
}
async function readCappedBody(source, maxBytes, tooLargeMessage) {
  const reader = source.body?.getReader();
  if (!reader) {
    const buffer = await source.arrayBuffer();
    if (buffer.byteLength > maxBytes) {
      throw httpError(tooLargeMessage, 413);
    }
    return new Uint8Array(buffer);
  }
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        try { await reader.cancel('message-too-large'); } catch (_) {}
        throw httpError(tooLargeMessage, 413);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  // Fast path: a lone chunk is returned as-is. Callers convert it with
  // toExactArrayBuffer(), which preserves the view's exact byte range when the
  // chunk is a subarray of a larger backing buffer.
  if (chunks.length === 1) return chunks[0];
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}
function decodeBase64Url(input) {
  if (!/^[A-Za-z0-9_-]+$/.test(input)) {
    throw httpError('Invalid base64url DNS query', 400);
  }
  let normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  normalized += '='.repeat((4 - (normalized.length % 4)) % 4);
  try {
    const decoded = atob(normalized);
    const bytes = new Uint8Array(decoded.length);
    for (let i = 0; i < decoded.length; i++) bytes[i] = decoded.charCodeAt(i);
    return bytes;
  } catch (_) {
    throw httpError('Invalid base64url DNS query', 400);
  }
}
function encodeBase64Url(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function parseDNSQuestion(packet) {
  const bytes = packet instanceof Uint8Array ? packet : new Uint8Array(packet);
  if (bytes.byteLength < 12) {
    return { ok: false, error: 'DNS message too short' };
  }
  const id = (bytes[0] << 8) | bytes[1];
  const flags = (bytes[2] << 8) | bytes[3];
  const qdcount = (bytes[4] << 8) | bytes[5];
  const ancount = (bytes[6] << 8) | bytes[7];
  const nscount = (bytes[8] << 8) | bytes[9];
  if ((flags & 0x8000) !== 0) {
    return { ok: false, error: 'DNS query expected, got response' };
  }
  if ((flags & 0x7800) !== 0) {
    return { ok: false, error: 'Unsupported DNS opcode' };
  }
  if (qdcount !== 1 || ancount !== 0 || nscount !== 0) {
    return { ok: false, error: 'Invalid DNS query section counts' };
  }
  const arcount = (bytes[10] << 8) | bytes[11];
  const questionEnd = skipDNSName(bytes, 12, false);
  if (questionEnd < 0 || questionEnd + 4 > bytes.length) {
    return { ok: false, error: 'Incomplete DNS question' };
  }
  // Walk the declared additional records (valid EDNS OPT stays supported) and
  // require the message to end exactly where they end.
  let offset = questionEnd + 4;
  let optCount = 0;
  for (let i = 0; i < arcount; i++) {
    const rr = readResourceRecord(bytes, offset);
    if (!rr) return { ok: false, error: 'Malformed DNS additional record' };
    if (rr.type === 41) {
      // OPT: owner name must be the root and only one is allowed (RFC 6891).
      if (bytes[offset] !== 0 || ++optCount > 1) {
        return { ok: false, error: 'Invalid EDNS OPT record' };
      }
      // cacheKeyBytes() walks the options, so their framing must be exact here.
      if (!optionsWellFormed(bytes, rr.rdataOffset, rr.rdEnd)) {
        return { ok: false, error: 'Malformed EDNS options' };
      }
    }
    offset = rr.rdEnd;
  }
  if (offset !== bytes.length) {
    return { ok: false, error: 'Unexpected trailing bytes in DNS query' };
  }
  return { ok: true, id, questionEnd };
}
// EDNS RDATA is a sequence of (code u16, length u16, data) options that must
// tile the RDATA exactly.
function optionsWellFormed(bytes, start, end) {
  for (let p = start; p < end;) {
    if (p + 4 > end) return false;
    p += 4 + ((bytes[p + 2] << 8) | bytes[p + 3]);
    if (p > end) return false;
  }
  return true;
}
function recoverScore(node, now = Date.now()) {
  if (!node.lastScoreUpdateAt) { node.lastScoreUpdateAt = now; return; }
  const steps = Math.floor((now - node.lastScoreUpdateAt) / CONFIG.SCORE_RECOVERY_INTERVAL_MS);
  if (steps > 0) {
    node.score = Math.min(CONFIG.SCORE_MAX, node.score + steps);
    node.lastScoreUpdateAt += steps * CONFIG.SCORE_RECOVERY_INTERVAL_MS;
  }
}
function compareLatency(a, b) {
  return (a.ewmaLatencyMs ?? Number.MAX_SAFE_INTEGER) - (b.ewmaLatencyMs ?? Number.MAX_SAFE_INTEGER)
    || a.order - b.order;
}
// First-choice pool: resolvers scoring strictly above (best - window). Inside
// the pool the lowest learned latency goes first; every PRIMARY_EXPLORE_EVERY
// resolutions another pool member leads so its latency estimate stays fresh.
// Resolvers outside the pool follow by score, then latency.
function selectRacers(resolvers) {
  for (const node of resolvers) recoverScore(node);
  const ranked = [...resolvers].sort((a, b) => b.score - a.score || compareLatency(a, b));
  const floor = ranked[0].score - CONFIG.PRIMARY_POOL_SCORE_WINDOW;
  let poolSize = 1;
  while (poolSize < ranked.length && ranked[poolSize].score > floor) poolSize++;
  const pool = ranked.slice(0, poolSize).sort(compareLatency);
  const turn = ++APP_STATE.primaryCursor;
  if (pool.length > 1 && turn % CONFIG.PRIMARY_EXPLORE_EVERY === 0) {
    const index = 1 + (Math.floor(turn / CONFIG.PRIMARY_EXPLORE_EVERY) % (pool.length - 1));
    pool.unshift(pool.splice(index, 1)[0]);
  }
  return pool.concat(ranked.slice(poolSize));
}
const HEDGE_TIMER = Symbol('hedge-timer');
async function resolveWithHedging(nodes, packet, expectedID, questionEnd) {
  if (!nodes.length) throw new Error('No upstreams configured');
  const encodedQuery = encodeBase64Url(packet);
  const controllers = new Map();
  const active = new Map();
  const startedAt = new Map();
  let attempts = 0;
  let nextIndex = 0;
  let fallback = null;
  const unusable = [];
  const startAttempt = (node) => {
    const controller = new AbortController();
    controllers.set(node, controller);
    startedAt.set(node, Date.now());
    const promise = relay(node, packet, encodedQuery, expectedID, controller.signal, questionEnd)
      .then((value) => ({ ok: true, node, value }))
      .catch((error) => ({ ok: false, node, error }));
    active.set(node, promise);
    attempts += 1;
  };
  startAttempt(nodes[nextIndex++]);
  let hedgeDelay = getHedgeDelay(nodes[0]);
  try {
    while (active.size) {
      const result = await raceAttempts(active, nextIndex >= nodes.length ? null : hedgeDelay);
      if (result === HEDGE_TIMER) {
        startAttempt(nodes[nextIndex++]);
        hedgeDelay = CONFIG.SECONDARY_HEDGE_MS;
        continue;
      }
      active.delete(result.node);
      if (result.ok) {
        const value = result.value;
        if (value.usable) {
          // An error RCODE or a truncated answer is the resolver's fault only
          // if another resolver answered usefully. If all of them fail that
          // way, the domain is the problem and nobody is penalised.
          for (const bad of unusable) {
            penalize(bad.node, CONFIG.SCORE_FAILURE_DELTA, bad.truncated ? 'Truncated DNS response' : `DNS RCODE ${bad.rcode}`);
          }
          // Attempts still running that started before the winner were
          // overtaken by a hedge: record how long they had already taken.
          const now = Date.now();
          const winnerStart = startedAt.get(result.node);
          for (const loser of active.keys()) {
            const loserStart = startedAt.get(loser);
            if (loserStart < winnerStart) noteOvertaken(loser, now - loserStart);
          }
          return {
            ...value,
            attempts
          };
        }
        unusable.push(value);
        if (!fallback || fallbackPriority(value) > fallbackPriority(fallback)) fallback = value;
      }
      if (nextIndex < nodes.length) {
        if (active.size === 0) startAttempt(nodes[nextIndex++]);
        hedgeDelay = CONFIG.SECONDARY_HEDGE_MS;
      }
    }
    if (fallback) {
      return {
        ...fallback,
        attempts
      };
    }
    const err = new Error('All DNS upstreams failed');
    err.attempts = attempts;
    throw err;
  } finally {
    // Only attempts that are still running need to be aborted.
    abortAttempts(controllers, active);
  }
}
async function raceAttempts(active, timeoutMs) {
  const racers = [...active.values()];
  if (timeoutMs == null) return Promise.race(racers);
  let timeoutId;
  const timer = new Promise((resolve) => {
    timeoutId = setTimeout(() => resolve(HEDGE_TIMER), timeoutMs);
  });
  try {
    return await Promise.race([timer, ...racers]);
  } finally {
    clearTimeout(timeoutId);
  }
}
function abortAttempts(controllers, active) {
  for (const node of active.keys()) controllers.get(node).abort('winner-selected');
}
function getHedgeDelay(node) {
  const learned = node.ewmaLatencyMs ?? 120;
  return clamp(Math.round(learned * 1.5), CONFIG.HEDGE_MIN_MS, CONFIG.HEDGE_MAX_MS);
}
function fallbackPriority(value) {
  return value.rcode === 0 ? 3 : value.rcode === 3 ? 2 : value.rcode === 2 ? 1 : 0;
}
// Upstream queries use RFC 8484 GET. Aborting a fetch that has a request body
// (POST) makes the Workers runtime log an uncaught abort error from its body
// pump even though the rejection is handled; a body-less GET aborts cleanly.
async function relay(node, packet, encodedQuery, expectedID, signal, questionEnd) {
  const started = Date.now();
  const timeoutSignal = AbortSignal.timeout(CONFIG.UPSTREAM_TIMEOUT_MS);
  const combinedSignal = AbortSignal.any([signal, timeoutSignal]);
  try {
    const res = await fetch(`${node.url}?dns=${encodedQuery}`, {
      method: 'GET',
      headers: { accept: 'application/dns-message' },
      // A DNS privacy proxy must not silently follow a redirect and forward
      // the query to a different host. Workers rejects
      // redirect: 'error' at runtime (only 'follow' and 'manual' exist), so use
      // 'manual': a 3xx is then a non-ok response, counted as a resolver
      // failure, and the failover logic tries the next resolver.
      redirect: 'manual',
      signal: combinedSignal
    });
    if (!res.ok) {
      discardBody(res);
      throw new Error(`Upstream HTTP ${res.status}`);
    }
    const declaredLength = Number(res.headers.get('content-length'));
    if (
      Number.isFinite(declaredLength)
      && declaredLength > CONFIG.MAX_UPSTREAM_DNS_MESSAGE_BYTES
    ) {
      discardBody(res);
      throw new Error('Upstream DNS response too large');
    }
    const bodyBytes = await readCappedBody(
      res,
      CONFIG.MAX_UPSTREAM_DNS_MESSAGE_BYTES,
      'Upstream DNS response too large'
    );
    // A Uint8Array can be a subarray of a larger backing buffer; slice to the
    // exact view so no foreign bytes are validated, cached, or returned, and
    // the upstream size cap is never undermined by buffer slack.
    const body = toExactArrayBuffer(bodyBytes);
    const validation = validateDNSMessage(body, { expectedID, queryBytes: packet, questionEnd });
    if (!validation.ok) {
      throw new Error(validation.error);
    }
    const latencyMs = Date.now() - started;
    const rcode = validation.rcode;
    // A truncated (TC) answer is incomplete: mark it unusable so it loses the
    // resolver race and a complete resolver can win. It is penalised only if
    // another resolver answers usefully (see resolveWithHedging). If every
    // upstream truncates, the truncated fallback is still returned degraded
    // (RFC 8484 permits the TC bit in DoH) and the validator assigns it TTL 0.
    const truncated = validation.truncated;
    const usable = !truncated && (rcode === 0 || rcode === 3);
    if (usable) reward(node, latencyMs);
    return {
      url: node.url,
      body,
      latencyMs,
      rcode,
      metadata: validation.metadata,
      node,
      truncated,
      usable,
      degraded: !usable
    };
  } catch (err) {
    if (signal.aborted && !timeoutSignal.aborted) throw err;
    if (timeoutSignal.aborted) {
      node.timeout += 1;
      penalize(node, CONFIG.SCORE_TIMEOUT_DELTA, 'timeout', false);
    } else {
      penalize(node, CONFIG.SCORE_FAILURE_DELTA, err && err.message ? err.message : err);
    }
    throw err;
  }
}
function discardBody(res) {
  try { res.body?.cancel().catch(() => {}); } catch (_) {}
}
// Structural validator shared by the upstream path and the L2 cache path.
// `expectedID` may be null for L2 bodies: their transaction ID is rewritten
// per request in patchDNSResponseForAge(), so any stored ID is acceptable.
function validateDNSMessage(responseBuffer, { expectedID = null, queryBytes = null, questionEnd = null } = {}) {
  const bytes = responseBuffer instanceof Uint8Array
    ? responseBuffer
    : new Uint8Array(responseBuffer);
  if (bytes.length < 12) return { ok: false, error: 'DNS response too short' };
  const id = (bytes[0] << 8) | bytes[1];
  const flags = (bytes[2] << 8) | bytes[3];
  let rcode = flags & 0x000f;
  if ((flags & 0x7800) !== 0) return { ok: false, error: 'Unsupported DNS response opcode' };
  const truncated = (flags & 0x0200) !== 0;
  if ((flags & 0x8000) === 0) return { ok: false, error: 'Expected a DNS response, got a query' };
  if (expectedID !== null && id !== expectedID) {
    return { ok: false, error: 'DNS response ID mismatch' };
  }
  const qdcount = (bytes[4] << 8) | bytes[5];
  const ancount = (bytes[6] << 8) | bytes[7];
  const nscount = (bytes[8] << 8) | bytes[9];
  const arcount = (bytes[10] << 8) | bytes[11];
  // Queries are always single-question, so a response may carry at most one
  // question (zero is tolerated for error responses only, see below).
  if (qdcount > 1) return { ok: false, error: 'DNS response has too many questions' };
  let offset = 12;
  let question = null;
  for (let i = 0; i < qdcount; i++) {
    const nameStart = offset;
    offset = skipDNSName(bytes, offset);
    if (offset < 0 || offset + 4 > bytes.length) {
      return { ok: false, error: 'Truncated DNS question section' };
    }
    if (i === 0) {
      question = {
        nameStart,
        nameEnd: offset,
        qtype: (bytes[offset] << 8) | bytes[offset + 1],
        qclass: (bytes[offset + 2] << 8) | bytes[offset + 3]
      };
    }
    offset += 4;
  }
  // A questionless response can be accepted only if its final RCODE is an
  // error; the extended RCODE is not known until OPT has been parsed below.
  if (question && queryBytes) {
    // Callers pass the parsed question end of the original query.
    const match = matchQuestion(bytes, question, queryBytes, questionEnd);
    if (!match.ok) return match;
  }
  // Walk every declared resource record. Error responses may omit their
  // question, but their declared records must still be structurally valid,
  // and no response may carry undeclared trailing bytes.
  const records = [];
  let optCount = 0;
  let soaMin = Infinity;
  let recordMin = Infinity;
  const counts = [ancount, nscount, arcount];
  for (let section = 0; section < counts.length; section++) {
    for (let i = 0; i < counts[section]; i++) {
      const rr = readResourceRecord(bytes, offset);
      if (!rr) return { ok: false, error: 'Truncated DNS resource record' };
      if (rr.type === 41) {
        if (section !== 2 || bytes[offset] !== 0 || ++optCount > 1) {
          return { ok: false, error: 'Invalid EDNS OPT record' };
        }
        if (!optionsWellFormed(bytes, rr.rdataOffset, rr.rdEnd)) {
          return { ok: false, error: 'Malformed EDNS options' };
        }
        rcode |= bytes[rr.rdataOffset - 6] << 4;
      } else {
        if (!validateKnownRdata(bytes, rr)) {
          return { ok: false, error: `Malformed DNS RDATA for type ${rr.type}` };
        }
        let recordTtl = rr.ttl;
        if (rr.type === 6) {
          const mo = findSOAMinimumOffset(bytes, rr.rdataOffset, rr.rdEnd);
          if (mo < 0) return { ok: false, error: 'Malformed DNS SOA record' };
          if (section === 1) {
            const minimum = readUint32(bytes, mo);
            const cappedMinimum = minimum > 0x7fffffff ? 0 : minimum;
            soaMin = Math.min(soaMin, cappedMinimum);
            recordTtl = Math.min(recordTtl, cappedMinimum);
          }
        }
        recordMin = Math.min(recordMin, recordTtl);
        records.push({ offset: rr.rdataOffset - 6, ttl: recordTtl });
      }
      offset = rr.rdEnd;
    }
  }
  if (offset !== bytes.length) return { ok: false, error: 'Unexpected trailing bytes in DNS response' };
  // Check the final RCODE after OPT has contributed any extended RCODE bits.
  // Otherwise a questionless BADVERS (base RCODE 0, extended RCODE 1) would
  // be mistaken for a usable NOERROR answer and rejected incorrectly.
  if (!question && (rcode === 0 || rcode === 3)) {
    return { ok: false, error: 'DNS response missing question section' };
  }
  let ttl = Math.min(recordMin, soaMin);
  if (truncated || (rcode !== 0 && rcode !== 3)
      || ((rcode === 3 || ancount === 0) && soaMin === Infinity)
      || !Number.isFinite(ttl)) ttl = 0;
  ttl = Math.max(0, Math.min(ttl, CONFIG.EDGE_CACHE_MAX_TTL_SECONDS));
  return { ok: true, rcode, truncated, metadata: { ttl, records } };
}

function lowerAscii(value) { return value >= 65 && value <= 90 ? value + 32 : value; }
// Compares a response's echoed question against the original query: QNAME
// case-insensitively (an upstream may re-case labels, cf. 0x20 randomization),
// QTYPE and QCLASS exactly.
function matchQuestion(responseBytes, question, queryBytes, queryEnd) {
  if (queryEnd == null || queryEnd < 0 || queryEnd + 4 > queryBytes.length) {
    return { ok: false, error: 'Original DNS query is unparseable' };
  }
  const qnameLength = queryEnd - 12;
  if (question.nameEnd - question.nameStart !== qnameLength) {
    return { ok: false, error: 'DNS response QNAME mismatch' };
  }
  for (let i = 0; i < qnameLength; i++) {
    if (lowerAscii(responseBytes[question.nameStart + i]) !== lowerAscii(queryBytes[12 + i])) {
      return { ok: false, error: 'DNS response QNAME mismatch' };
    }
  }
  const qtype = (queryBytes[queryEnd] << 8) | queryBytes[queryEnd + 1];
  const qclass = (queryBytes[queryEnd + 2] << 8) | queryBytes[queryEnd + 3];
  if (question.qtype !== qtype) return { ok: false, error: 'DNS response QTYPE mismatch' };
  if (question.qclass !== qclass) return { ok: false, error: 'DNS response QCLASS mismatch' };
  return { ok: true };
}

// Converts a typed-array chunk to an ArrayBuffer covering exactly the view's
// bytes. A chunk's backing buffer may extend beyond the view (non-zero
// byteOffset or trailing slack), so reading .buffer directly can expose,
// validate, cache, and return bytes that were never part of the response.
function toExactArrayBuffer(view) {
  if (view.byteOffset === 0 && view.byteLength === view.buffer.byteLength) {
    return view.buffer;
  }
  return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength);
}
function blendLatency(node, ms) {
  node.ewmaLatencyMs = node.ewmaLatencyMs == null
    ? ms
    : Math.round(node.ewmaLatencyMs * 0.8 + ms * 0.2);
}
function reward(node, latencyMs) {
  node.ok += 1;
  node.lastLatencyMs = latencyMs;
  blendLatency(node, latencyMs);
  node.lastError = null;
  adjustScore(node, CONFIG.SCORE_SUCCESS_DELTA);
}
function adjustScore(node, delta) {
  node.score = clamp(node.score + delta, CONFIG.SCORE_MIN, CONFIG.SCORE_MAX);
  node.lastScoreUpdateAt = Date.now();
}
// The attempt was still running when a later-started hedge won. Its elapsed
// time is a lower bound on its latency, so it may only raise the estimate.
function noteOvertaken(node, elapsedMs) {
  node.slow += 1;
  if (node.ewmaLatencyMs == null || elapsedMs > node.ewmaLatencyMs) blendLatency(node, elapsedMs);
  node.lastError = 'overtaken by hedge';
  adjustScore(node, -CONFIG.SCORE_SLOW_DELTA);
}
function penalize(node, amount, error, countFailure = true) {
  if (countFailure) node.fail += 1;
  node.lastError = String(error || 'unknown').slice(0, 80);
  adjustScore(node, -amount);
}
// Cache-key bytes: the query with transaction ID zeroed, the question name
// lower-cased and every EDNS Padding option (RFC 7830) replaced by an empty
// one. Padding length never changes the answer, but whether the client asked
// for padding does (padded responses are only for padding clients), so its
// presence stays in the key. parseDNSQuestion() has already validated every
// record and the framing of every OPT option, so the walk below cannot throw
// for a query that passed it (the throws are a last-resort invariant check).
function cacheKeyBytes(bytes, questionEnd) {
  const end = questionEnd + 4;
  const out = new Uint8Array(bytes.length);
  out.set(bytes.subarray(0, end));
  out[0] = 0;
  out[1] = 0;
  // Question names are uncompressed (pointers are rejected) and label length
  // bytes are <= 63, below 'A' (65), so lower-casing the whole range only
  // touches label characters.
  for (let i = 12; i < questionEnd; i++) out[i] = lowerAscii(out[i]);
  let length = end;
  let offset = end;
  const arcount = (bytes[10] << 8) | bytes[11];
  for (let i = 0; i < arcount; i++) {
    const rr = readResourceRecord(bytes, offset);
    if (!rr) throw new Error('cacheKeyBytes: unvalidated query');
    if (rr.type !== 41) {
      out.set(bytes.subarray(offset, rr.rdEnd), length);
      length += rr.rdEnd - offset;
    } else {
      const header = rr.rdataOffset - 2 - offset;
      out.set(bytes.subarray(offset, rr.rdataOffset - 2), length);
      const rdLengthAt = length + header;
      length = rdLengthAt + 2;
      const rdStart = length;
      for (let p = rr.rdataOffset; p < rr.rdEnd;) {
        if (p + 4 > rr.rdEnd) throw new Error('cacheKeyBytes: unvalidated OPT');
        const code = (bytes[p] << 8) | bytes[p + 1];
        const next = p + 4 + ((bytes[p + 2] << 8) | bytes[p + 3]);
        if (next > rr.rdEnd) throw new Error('cacheKeyBytes: unvalidated OPT');
        if (code === 12) {
          out[length] = 0; out[length + 1] = 12; out[length + 2] = 0; out[length + 3] = 0;
          length += 4;
        } else {
          out.set(bytes.subarray(p, next), length);
          length += next - p;
        }
        p = next;
      }
      const rdLength = length - rdStart;
      out[rdLengthAt] = rdLength >> 8;
      out[rdLengthAt + 1] = rdLength & 0xff;
    }
    offset = rr.rdEnd;
  }
  return out.subarray(0, length);
}
// L1 and in-flight key: the key bytes themselves as a binary string, so the
// hot path needs no hashing.
function localCacheKey(keyBytes) {
  let out = '';
  for (let i = 0; i < keyBytes.length; i += 4096) {
    out += String.fromCharCode.apply(null, keyBytes.subarray(i, i + 4096));
  }
  return out;
}
// L2 key: first 128 bits of SHA-256 over the key bytes, computed only after
// an L1 miss.
async function edgeCacheKey(keyBytes) {
  const digest = await crypto.subtle.digest('SHA-256', keyBytes);
  const view = new Uint8Array(digest, 0, 16);
  let out = '';
  for (let i = 0; i < view.length; i++) out += view[i].toString(16).padStart(2, '0');
  return out;
}
function deleteCache(key) {
  const entry = APP_STATE.cache.get(key);
  if (entry) APP_STATE.cacheBytes -= entry.body.byteLength;
  APP_STATE.cache.delete(key);
}
function getCache(key) {
  const item = APP_STATE.cache.get(key);
  if (!item) return null;
  if (Date.now() >= item.expiresAt) { deleteCache(key); return null; }
  APP_STATE.cache.delete(key);
  APP_STATE.cache.set(key, item);
  return item;
}
function setCache(key, body, ttlSeconds, storedAt, metadata) {
  if (ttlSeconds <= 0 || body.byteLength > CONFIG.MAX_CACHE_BYTES) return;
  deleteCache(key);
  APP_STATE.cache.set(key, {
    body, storedAt, metadata,
    expiresAt: Date.now() + Math.floor(ttlSeconds) * 1000
  });
  APP_STATE.cacheBytes += body.byteLength;
  while (APP_STATE.cache.size > CONFIG.MAX_CACHE_ENTRIES || APP_STATE.cacheBytes > CONFIG.MAX_CACHE_BYTES) {
    deleteCache(APP_STATE.cache.keys().next().value);
  }
}
function skipDNSName(bytes, offset, allowPointer = true) {
  let pos = offset;
  let wireLength = 1;
  while (pos < bytes.length) {
    const len = bytes[pos];
    if (len === 0) return pos + 1;
    if ((len & 0xc0) === 0xc0) {
      if (!allowPointer || pos + 1 >= bytes.length) return -1;
      const target = ((len & 0x3f) << 8) | bytes[pos + 1];
      if (!isValidNamePointerTarget(bytes, target, pos, wireLength)) return -1;
      return pos + 2;
    }
    if ((len & 0xc0) !== 0 || pos + 1 + len > bytes.length) return -1;
    wireLength += len + 1;
    if (wireLength > 255) return -1;
    pos += 1 + len;
  }
  return -1;
}
// A compression pointer must point backwards into the message body (never
// into the header, itself or forward, which also rules out loops) at a
// well-formed name: labels in bounds, terminating in a root label or another
// valid backward pointer, within the 255-byte wire limit.
function isValidNamePointerTarget(bytes, target, pointerPos, wireLength = 1) {
  let from = pointerPos;
  let pos = target;
  for (let hops = 0; hops < 128; hops++) {
    if (pos < 12) return false;
    for (;;) {
      // The complete target name must be encoded before the pointer that
      // references it. Checking only the first byte allowed a label or a
      // nested pointer to consume bytes at/after the referencing pointer.
      if (pos >= from || pos >= bytes.length) return false;
      const len = bytes[pos];
      if (len === 0) return true;
      if ((len & 0xc0) === 0xc0) {
        if (pos + 2 > from || pos + 1 >= bytes.length) return false;
        from = pos;
        pos = ((len & 0x3f) << 8) | bytes[pos + 1];
        break;
      }
      if ((len & 0xc0) !== 0 || pos + 1 + len > from || pos + 1 + len > bytes.length) {
        return false;
      }
      wireLength += len + 1;
      if (wireLength > 255) return false;
      pos += 1 + len;
    }
  }
  return false;
}
function readResourceRecord(bytes, offset) {
  const nameEnd = skipDNSName(bytes, offset);
  if (nameEnd < 0 || nameEnd + 10 > bytes.length) return null;
  const type = (bytes[nameEnd] << 8) | bytes[nameEnd + 1];
  let ttl = readUint32(bytes, nameEnd + 4);
  if (ttl > 0x7fffffff) ttl = 0;
  const rdLength = (bytes[nameEnd + 8] << 8) | bytes[nameEnd + 9];
  const rdataOffset = nameEnd + 10;
  const rdEnd = rdataOffset + rdLength;
  if (rdEnd > bytes.length) return null;
  return { type, ttl, rdataOffset, rdEnd };
}
function findSOAMinimumOffset(bytes, rdataOffset, rdEnd) {
  let pos = skipDNSName(bytes, rdataOffset);
  if (pos < 0 || pos >= rdEnd) return -1;
  pos = skipDNSName(bytes, pos);
  // Require exactly the five 32-bit fields after the two names. Trailing or
  // missing bytes mean malformed SOA data that must never drive the negative-
  // cache lifetime; MINIMUM is the last of those five fixed fields.
  if (pos < 0 || pos + 20 !== rdEnd) return -1;
  return pos + 16;
}
// These helpers are shared across records to avoid allocating several small
// closures for every RR in an upstream response.
function rdataNameEndAt(bytes, offset, end, allowPointer = true) {
  if (offset < 0 || offset >= end) return -1;
  const next = skipDNSName(bytes, offset, allowPointer);
  return next >= 0 && next <= end ? next : -1;
}
function rdataOneName(bytes, start, end, offset = start, allowPointer = true) {
  return rdataNameEndAt(bytes, offset, end, allowPointer) === end;
}
function rdataTwoNames(bytes, start, end, offset = start, allowPointer = true) {
  const first = rdataNameEndAt(bytes, offset, end, allowPointer);
  if (first < 0) return false;
  return rdataNameEndAt(bytes, first, end, allowPointer) === end;
}
function rdataCharStringEnd(bytes, offset, end) {
  if (offset < 0 || offset >= end) return -1;
  const next = offset + 1 + bytes[offset];
  return next <= end ? next : -1;
}
function validRdataTypeBitmap(bytes, offset, end) {
  let pos = offset;
  let previousWindow = -1;
  while (pos < end) {
    if (pos + 2 > end) return false;
    const window = bytes[pos++];
    const bitmapLength = bytes[pos++];
    if (window <= previousWindow || bitmapLength < 1 || bitmapLength > 32
        || pos + bitmapLength > end || bytes[pos + bitmapLength - 1] === 0) return false;
    previousWindow = window;
    pos += bitmapLength;
  }
  return pos === end && pos > offset;
}

// Validate RDATA formats that have well-defined framing. Unknown RR types stay
// opaque (their formats may be defined by extensions the Worker does not know),
// but common fixed-size and domain-name-bearing records must not smuggle a
// malformed name or field sequence into a response that can be relayed/cached.
function validateKnownRdata(bytes, rr) {
  const { type, rdataOffset: start, rdEnd: end } = rr;
  const length = end - start;
  switch (type) {
    case 1: return length === 4; // A
    case 28: case 29: return length === 16; // AAAA, LOC
    case 108: return length === 6; // EUI48
    case 109: return length === 8; // EUI64

    // RFC 1035 name-only RRs permit compression. NSAP-PTR is a later type
    // without a compression exception, so its target must remain uncompressed.
    case 2: case 3: case 4: case 5: case 7: case 8: case 9: case 12:
      return rdataOneName(bytes, start, end);
    case 23: case 39: // NSAP-PTR; DNAME target names must not be compressed.
      return rdataOneName(bytes, start, end, start, false);

    // Legacy MINFO/RP records permit compressed names. TALINK was defined
    // later and has no compression exception.
    case 14: case 17:
      return rdataTwoNames(bytes, start, end);
    case 58:
      return rdataTwoNames(bytes, start, end, start, false);

    // Preference field followed by a compression-permitted domain name.
    case 15: case 18: case 21:
      return length >= 3 && rdataOneName(bytes, start, end, start + 2);
    // KX and LP targets must not be compressed.
    case 36: case 107:
      return length >= 3 && rdataOneName(bytes, start, end, start + 2, false);

    case 26: // PX: preference, MAP822 name, MAPX400 name
      return length >= 4 && rdataTwoNames(bytes, start, end, start + 2);

    case 33: // SRV: priority, weight, port, uncompressed target
      return length >= 7 && rdataOneName(bytes, start, end, start + 6, false);

    case 35: { // NAPTR: order, preference, three character strings, replacement
      if (length < 8) return false;
      let pos = start + 4;
      for (let i = 0; i < 3; i++) {
        pos = rdataCharStringEnd(bytes, pos, end);
        if (pos < 0) return false;
      }
      return rdataOneName(bytes, start, end, pos, false);
    }

    case 13: { // HINFO has exactly two character strings.
      if (length < 2) return false;
      const first = rdataCharStringEnd(bytes, start, end);
      if (first < 0) return false;
      return rdataCharStringEnd(bytes, first, end) === end;
    }
    case 16: case 99: { // TXT/SPF is one or more length-prefixed character strings.
      if (length < 1) return false;
      let pos = start;
      while (pos < end) {
        pos = rdataCharStringEnd(bytes, pos, end);
        if (pos < 0) return false;
      }
      return pos === end;
    }

    case 24: { // SIG: tolerate historical compression for receiver compatibility.
      if (length < 20) return false;
      const signerEnd = rdataNameEndAt(bytes, start + 18, end);
      return signerEnd >= 0 && signerEnd < end;
    }
    case 46: { // RRSIG: signer name must not be compressed.
      if (length < 20) return false;
      const signerEnd = rdataNameEndAt(bytes, start + 18, end, false);
      return signerEnd >= 0 && signerEnd < end;
    }
    case 30: { // NXT: next name and legacy bitmap; tolerate historical compression.
      const nextName = rdataNameEndAt(bytes, start, end);
      return nextName >= 0 && nextName < end;
    }
    case 47: { // NSEC: uncompressed next name followed by type bitmaps.
      const nextName = rdataNameEndAt(bytes, start, end, false);
      return nextName >= 0 && validRdataTypeBitmap(bytes, nextName, end);
    }

    case 43: case 59: // DS/CDS: key tag, algorithm, digest type, digest
      return length >= 5;
    case 44: // SSHFP: algorithm, fingerprint type, fingerprint
      return length >= 3;
    case 48: case 60: // DNSKEY/CDNSKEY: flags, protocol, algorithm, public key
    case 49: // DHCID: identifier type, digest type, digest
    case 52: case 53: // TLSA/SMIMEA: usage, selector, matching type, association data
      return length >= 4;
    case 45: { // IPSECKEY: validate the defined gateway field framing.
      if (length < 3) return false;
      const gatewayType = bytes[start + 1];
      const gatewayStart = start + 3;
      if (gatewayType === 0) return true;
      if (gatewayType === 1) return gatewayStart + 4 <= end;
      if (gatewayType === 2) return gatewayStart + 16 <= end;
      if (gatewayType === 3) return rdataNameEndAt(bytes, gatewayStart, end, false) >= 0;
      // Leave unrecognized gateway types opaque for future extensions.
      return true;
    }

    case 257: { // CAA: flags, non-empty ASCII alphanumeric tag, value
      if (length < 2) return false;
      const tagLength = bytes[start + 1];
      const tagEnd = start + 2 + tagLength;
      if (tagLength === 0 || tagEnd > end) return false;
      for (let pos = start + 2; pos < tagEnd; pos++) {
        const ch = bytes[pos];
        if (!((ch >= 0x30 && ch <= 0x39) || (ch >= 0x41 && ch <= 0x5a)
            || (ch >= 0x61 && ch <= 0x7a))) return false;
      }
      return true;
    }

    case 64: case 65: { // SVCB/HTTPS: priority, uncompressed target, sorted SvcParams
      if (length < 3) return false;
      const targetEnd = rdataNameEndAt(bytes, start + 2, end, false);
      if (targetEnd < 0) return false;
      let pos = targetEnd;
      let previousKey = -1;
      const keys = new Set();
      let mandatoryKeys = null;
      let hasNoDefaultAlpn = false;
      let hasAlpn = false;
      while (pos < end) {
        if (pos + 4 > end) return false;
        const key = (bytes[pos] << 8) | bytes[pos + 1];
        const valueLength = (bytes[pos + 2] << 8) | bytes[pos + 3];
        pos += 4;
        const valueStart = pos;
        const valueEnd = pos + valueLength;
        if (key <= previousKey || key === 65535 || valueEnd > end) return false;
        previousKey = key;
        keys.add(key);

        switch (key) {
          case 0: { // mandatory: sorted list of keys, excluding key 0 itself
            if (valueLength < 2 || valueLength % 2 !== 0) return false;
            mandatoryKeys = [];
            let lastMandatory = -1;
            for (let item = valueStart; item < valueEnd; item += 2) {
              const mandatoryKey = (bytes[item] << 8) | bytes[item + 1];
              if (mandatoryKey === 0 || mandatoryKey <= lastMandatory) return false;
              lastMandatory = mandatoryKey;
              mandatoryKeys.push(mandatoryKey);
            }
            break;
          }
          case 1: { // alpn: one or more non-empty length-prefixed IDs
            if (valueLength < 2) return false;
            let item = valueStart;
            while (item < valueEnd) {
              const itemLength = bytes[item++];
              if (itemLength === 0 || item + itemLength > valueEnd) return false;
              item += itemLength;
            }
            if (item !== valueEnd) return false;
            hasAlpn = true;
            break;
          }
          case 2: // no-default-alpn is an empty flag and requires alpn.
            if (valueLength !== 0) return false;
            hasNoDefaultAlpn = true;
            break;
          case 3: // port is exactly one unsigned 16-bit value.
            if (valueLength !== 2) return false;
            break;
          case 4: // ipv4hint contains one or more IPv4 addresses.
            if (valueLength === 0 || valueLength % 4 !== 0) return false;
            break;
          case 6: // ipv6hint contains one or more IPv6 addresses.
            if (valueLength === 0 || valueLength % 16 !== 0) return false;
            break;
          case 8: // ohttp is an empty flag.
            if (valueLength !== 0) return false;
            break;
          default:
            // Unknown SvcParamKeys are preserved as opaque values.
            break;
        }
        pos = valueEnd;
      }
      if (pos !== end || (hasNoDefaultAlpn && !hasAlpn)) return false;
      if (mandatoryKeys && mandatoryKeys.some((key) => !keys.has(key))) return false;
      return true;
    }
    default:
      return true;
  }
}
function readUint32(bytes, offset) {
  return (((bytes[offset] * 0x100 + bytes[offset + 1]) * 0x100 + bytes[offset + 2]) * 0x100 + bytes[offset + 3]) >>> 0;
}
function writeUint32(bytes, offset, value) {
  bytes[offset] = (value >>> 24) & 0xff;
  bytes[offset + 1] = (value >>> 16) & 0xff;
  bytes[offset + 2] = (value >>> 8) & 0xff;
  bytes[offset + 3] = value & 0xff;
}
function restoreQuestionCase(target, query) {
  let offset = 12;
  while (offset < query.length && offset < target.length) {
    const len = query[offset];
    if (len === 0) return;
    if ((len & 0xc0) !== 0 || target[offset] !== len) return;
    if (offset + 1 + len > query.length || offset + 1 + len > target.length) return;
    for (let i = offset + 1; i <= offset + len; i++) {
      if (lowerAscii(query[i]) !== lowerAscii(target[i])) return;
    }
    for (let i = offset + 1; i <= offset + len; i++) target[i] = query[i];
    offset += 1 + len;
  }
}
function patchDNSResponseForAge(responseBuffer, queryID, ageSeconds, queryBytes, metadata) {
  const source = responseBuffer instanceof Uint8Array ? responseBuffer : new Uint8Array(responseBuffer);
  const copy = source.slice();
  copy[0] = (queryID >> 8) & 0xff;
  copy[1] = queryID & 0xff;
  if (queryBytes) restoreQuestionCase(copy, queryBytes);
  const age = Math.max(0, ageSeconds);
  for (const record of metadata.records) {
    writeUint32(copy, record.offset, Math.max(0, record.ttl - age));
  }
  // Only RR TTLs change. SOA MINIMUM is signed RDATA and must stay intact.
  return copy.buffer;
}
function makeEdgeCacheRequest(origin, key) {
  return new Request(`${origin}${CONFIG.EDGE_CACHE_PATH}/${key}`, { method: 'GET' });
}
async function getEdgeCache(key, origin, queryBytes, questionEnd, ctx) {
  try {
    const cache = caches.default;
    const cacheKey = makeEdgeCacheRequest(origin, key);
    const hit = await cache.match(cacheKey);
    if (!hit) return null;
    const storedAt = Number(hit.headers.get('x-doh-stored-at'));
    const ttlSeconds = Number(hit.headers.get('x-doh-ttl'));
    // Bookkeeping headers are checked before the body is read, so an entry
    // that is about to be purged never costs a body read.
    if (!Number.isFinite(storedAt) || storedAt > Date.now() + 5000
        || !Number.isInteger(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > CONFIG.EDGE_CACHE_MAX_TTL_SECONDS) {
      discardBody(hit);
      runInBackground(ctx, purgeEdgeCache(cache, cacheKey));
      return null;
    }
    const ageSeconds = cacheAgeSeconds(storedAt);
    if (ageSeconds >= ttlSeconds) {
      discardBody(hit);
      runInBackground(ctx, purgeEdgeCache(cache, cacheKey));
      return null;
    }
    const body = await hit.arrayBuffer();
    // Bookkeeping alone is not enough: validate the DNS message itself
    // (structure plus echoed question) so a corrupt body with plausible
    // headers is purged and re-resolved upstream instead of being served.
    // The stored transaction ID is rewritten per request, so it is not part
    // of this check.
    const validation = validateDNSMessage(new Uint8Array(body), { queryBytes, questionEnd });
    if (!validation.ok || validation.metadata.ttl <= 0 || ttlSeconds > validation.metadata.ttl) {
      runInBackground(ctx, purgeEdgeCache(cache, cacheKey));
      return null;
    }
    return {
      body,
      storedAt,
      metadata: validation.metadata,
      remainingSeconds: ttlSeconds - ageSeconds
    };
  } catch (_) {
    return null;
  }
}
async function purgeEdgeCache(cache, cacheKey) {
  // Best-effort: drop corrupt/expired entries so requests stop paying a
  // cache.match + full body read until Cloudflare evicts them.
  try { await cache.delete(cacheKey); } catch (_) {}
}
async function putEdgeCache(key, body, ttlSeconds, storedAt, origin) {
  try {
    const cache = caches.default;
    const cacheKey = makeEdgeCacheRequest(origin, key);
    const response = new Response(body, {
      status: 200,
      headers: {
        'content-type': 'application/dns-message',
        'cache-control': `public, s-maxage=${ttlSeconds}`,
        'x-doh-stored-at': String(storedAt),
        'x-doh-ttl': String(ttlSeconds)
      }
    });
    await cache.put(cacheKey, response);
  } catch (_) {}
}
function maybeSweepState() {
  const now = Date.now();
  if (now - APP_STATE.lastSweepAt < CONFIG.STATE_SWEEP_INTERVAL_MS) return;
  for (const [key, item] of APP_STATE.cache) {
    if (now >= item.expiresAt) deleteCache(key);
  }
  for (const [ip, stats] of APP_STATE.throttle) {
    if (now >= stats.resetAt) APP_STATE.throttle.delete(ip);
  }
  for (const [ip, stats] of APP_STATE.penalty) {
    if (now >= stats.resetAt) APP_STATE.penalty.delete(ip);
  }
  APP_STATE.lastSweepAt = now;
}
async function allowDNSRequest(ip, env) {
  ip = rateLimitKey(ip);
  if (env?.DNS_RATE_LIMITER?.limit) {
    try {
      const result = await env.DNS_RATE_LIMITER.limit({ key: ip });
      if (typeof result?.success === 'boolean') return result.success;
      // Malformed binding response: fall through to the local limiter below.
    } catch (_) {
      // Binding unavailable/throwing: fall back to the local limiter.
    }
  }
  return localRateLimit(ip);
}
// `ip` must already be normalised by rateLimitKey() (allowDNSRequest does it).
function localRateLimit(ip) {
  const now = Date.now();
  // Rejected requests must not re-touch the entry: a flooding client would
  // otherwise stay hot in the LRU table and evict legitimate clients.
  const live = APP_STATE.throttle.get(ip);
  if (live && now < live.resetAt && live.count >= CONFIG.RATE_LIMIT_MAX_REQUESTS) {
    return false;
  }
  // A window evicted by an LRU overflow survives in the penalty map, so
  // flooding the table (e.g. IPv6 /64 scanning) cannot reset a client's count.
  let stats = live || APP_STATE.penalty.get(ip);
  if (!live) APP_STATE.penalty.delete(ip);
  if (!stats || now >= stats.resetAt) {
    stats = { count: 0, resetAt: now + CONFIG.RATE_LIMIT_WINDOW_MS };
  }
  stats.count += 1;
  APP_STATE.throttle.delete(ip);
  APP_STATE.throttle.set(ip, stats);
  trimThrottleMap();
  return stats.count <= CONFIG.RATE_LIMIT_MAX_REQUESTS;
}
function trimThrottleMap() {
  while (APP_STATE.throttle.size > CONFIG.MAX_THROTTLE_ENTRIES) {
    const oldestKey = APP_STATE.throttle.keys().next().value;
    const stats = APP_STATE.throttle.get(oldestKey);
    const now = Date.now();
    APP_STATE.throttle.delete(oldestKey);
    if (stats && now < stats.resetAt) {
      APP_STATE.penalty.delete(oldestKey);
      APP_STATE.penalty.set(oldestKey, stats);
      if (APP_STATE.penalty.size > CONFIG.MAX_PENALTY_ENTRIES) {
        APP_STATE.penalty.delete(APP_STATE.penalty.keys().next().value);
      }
    }
  }
}
function trimMap(map, maxEntries) {
  while (map.size > maxEntries) {
    const oldestKey = map.keys().next().value;
    map.delete(oldestKey);
  }
}
function rateLimitKey(ip) {
  if (!ip.includes(':') || ip.endsWith('/64')) return ip;
  const halves = ip.toLowerCase().split('::');
  if (halves.length > 2 || ip.includes('.')) return ip; // trusted CF header; mapped IPv4 unchanged
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const groups = halves.length === 2 ? [...left, ...Array(Math.max(0, 8-left.length-right.length)).fill('0'), ...right] : left;
  if (groups.length !== 8 || groups.some(g => !/^[0-9a-f]{1,4}$/.test(g))) return ip;
  return groups.slice(0, 4).map(g => parseInt(g, 16).toString(16)).join(':') + '::/64';
}
function getClientIP(req) {
  return req.headers.get('CF-Connecting-IP') || 'unknown';
}
function getHealthSnapshot() {
  for (const node of RESOLVER_NODES) recoverScore(node);
  return {
    version: VERSION,
    upstreams: RESOLVER_NODES.map((node) => ({
      url: node.url,
      score: node.score,
      ok: node.ok,
      fail: node.fail,
      timeout: node.timeout,
      slow: node.slow,
      ewmaLatencyMs: node.ewmaLatencyMs,
      lastLatencyMs: node.lastLatencyMs,
      lastError: node.lastError
    })),
    cacheEntries: APP_STATE.cache.size,
    cacheBytes: APP_STATE.cacheBytes,
    inflightEntries: APP_STATE.inflight.size,
    throttleEntries: APP_STATE.throttle.size,
    penaltyEntries: APP_STATE.penalty.size,
    rateLimit: {
      maxRequests: CONFIG.RATE_LIMIT_MAX_REQUESTS,
      windowSeconds: CONFIG.RATE_LIMIT_WINDOW_MS / 1000,
      preferredBinding: 'DNS_RATE_LIMITER',
      invalidBindingFallback: 'per-isolate local limiter',
      ipv6Grouping: '/64'
    },
    maxUpstreamDNSMessageBytes: CONFIG.MAX_UPSTREAM_DNS_MESSAGE_BYTES,
    stateSweepIntervalSeconds: CONFIG.STATE_SWEEP_INTERVAL_MS / 1000,
    maxSimultaneousUpstreams: RESOLVER_NODES.length,
    cache: {
      l1: 'in-memory LRU',
      l2: CONFIG.EDGE_CACHE_ENABLED ? 'Cloudflare Cache API (data-center-local)' : 'disabled',
      maxBytes: CONFIG.MAX_CACHE_BYTES,
      localMaxTTLSeconds: CONFIG.LOCAL_CACHE_MAX_TTL_SECONDS,
      edgeMaxTTLSeconds: CONFIG.EDGE_CACHE_MAX_TTL_SECONDS
    }
  };
}
function dnsResponse(body, extraHeaders) {
  return new Response(body, {
    status: 200,
    headers: {
      'content-type': 'application/dns-message',
      'cache-control': 'no-store',
      ...CORS_HEADERS,
      ...extraHeaders
    }
  });
}
function dnsErrorResponse(text, status, extraHeaders = {}) {
  return textResponse(text, status, { 'cache-control': 'no-store', ...CORS_HEADERS, ...extraHeaders });
}
function preflightResponse() {
  return new Response(null, {
    status: 204,
    headers: {
      ...CORS_HEADERS,
      'access-control-allow-methods': 'GET, POST, OPTIONS',
      'access-control-allow-headers': 'content-type, accept',
      'access-control-max-age': '86400'
    }
  });
}
function textResponse(text, status, headers = {}) {
  return new Response(text, {
    status,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      ...headers
    }
  });
}
function jsonResponse(data, status, headers = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      ...headers
    }
  });
}
function httpError(message, status) {
  const err = new Error(message);
  err.status = status;
  return err;
}
function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[ch]));
}
// The dashboard markup only differs per request in the endpoint URL, so the
// ~15KB template is built once and cached at module scope.
let UI_TEMPLATE = null;
function getUITemplate() {
  if (UI_TEMPLATE) return UI_TEMPLATE;
  UI_TEMPLATE = buildUITemplate().split('__DOH_ENDPOINT__');
  return UI_TEMPLATE;
}
function buildUITemplate() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure DNS over HTTPS (DoH) Pro</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡️</text></svg>">
    <style>
        /* Pre-compiled Tailwind utilities: replaces the ~300KB CDN JIT script.
           Only the classes used by this template are included. */
        .fixed{position:fixed}.absolute{position:absolute}.relative{position:relative}
        .right-0{right:0}.right-6{right:1.5rem}.top-6{top:1.5rem}.z-50{z-index:50}
        .block{display:block}.hidden{display:none}
        .flex{display:flex}.flex-col{flex-direction:column}.flex-wrap{flex-wrap:wrap}
        .items-center{align-items:center}.justify-between{justify-content:space-between}.justify-center{justify-content:center}
        .max-w-4xl{max-width:56rem}.min-h-\\[300px\\]{min-height:300px}.w-44{width:11rem}.w-full{width:100%}
        .mx-auto{margin-left:auto;margin-right:auto}
        .mb-1{margin-bottom:.25rem}.mb-4{margin-bottom:1rem}.mb-6{margin-bottom:1.5rem}.mb-8{margin-bottom:2rem}
        .mb-10{margin-bottom:2.5rem}.mb-16{margin-bottom:4rem}.mb-20{margin-bottom:5rem}
        .mt-3{margin-top:.75rem}.mt-8{margin-top:2rem}.mt-32{margin-top:8rem}.pb-20{padding-bottom:5rem}
        .p-2{padding:.5rem}.p-3{padding:.75rem}.p-4{padding:1rem}.p-5{padding:1.25rem}
        .p-8{padding:2rem}.p-10{padding:2.5rem}
        .px-6{padding-left:1.5rem;padding-right:1.5rem}.px-12{padding-left:3rem;padding-right:3rem}
        .py-3{padding-top:.75rem;padding-bottom:.75rem}.py-5{padding-top:1.25rem;padding-bottom:1.25rem}
        .py-16{padding-top:4rem;padding-bottom:4rem}
        .gap-3{gap:.75rem}.gap-4{gap:1rem}.gap-8{gap:2rem}.gap-10{gap:2.5rem}
        .space-y-6>:not([hidden])~:not([hidden]){margin-top:1.5rem}
        .list-none{list-style-type:none}
        .rounded-2xl{border-radius:1rem}.rounded-xl{border-radius:.75rem}
        .rounded-\\[3rem\\]{border-radius:3rem}.rounded-\\[3\\.5rem\\]{border-radius:3.5rem}
        .border{border-width:1px}.border-t{border-top-width:1px}
        .border-slate-800{border-color:#1e293b}.border-slate-900{border-color:#0f172a}
        .border-sky-900\\/40{border-color:rgba(12,74,110,.4)}.border-cyan-500\\/20{border-color:rgba(6,182,212,.2)}
        .bg-black\\/40{background-color:rgba(0,0,0,.4)}.bg-cyan-600{background-color:#0891b2}
        .from-cyan-400{--tw-gradient-from:#22d3ee;--tw-gradient-stops:var(--tw-gradient-from),var(--tw-gradient-to,rgba(186,230,253,0))}
        .via-sky-300{--tw-gradient-stops:var(--tw-gradient-from),#bae6fd,var(--tw-gradient-to,rgba(52,211,153,0))}
        .to-emerald-400{--tw-gradient-to:#34d399}
        .bg-gradient-to-r{background-image:linear-gradient(to right,var(--tw-gradient-stops))}
        .bg-clip-text{-webkit-background-clip:text;background-clip:text}.text-transparent{color:transparent}
        .text-slate-400{color:#94a3b8}.text-slate-500{color:#64748b}
        .text-cyan-100{color:#cffafe}.text-cyan-300{color:#67e8f9}.text-cyan-500{color:#06b6d4}.text-cyan-600{color:#0891b2}
        .text-emerald-100{color:#d1fae5}.text-teal-100{color:#ccfbf1}.text-sky-400{color:#38bdf8}.text-black{color:#000}
        .text-xs{font-size:.75rem;line-height:1rem}.text-sm{font-size:.875rem;line-height:1.25rem}
        .text-base{font-size:1rem;line-height:1.5rem}.text-2xl{font-size:1.5rem;line-height:2rem}
        .text-5xl{font-size:3rem;line-height:1}
        .text-\\[9px\\]{font-size:9px}.text-\\[10px\\]{font-size:10px}.text-\\[11px\\]{font-size:11px}
        .text-\\[13px\\]{font-size:13px}
        .font-bold{font-weight:700}.font-black{font-weight:900}
        .font-mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
        .uppercase{text-transform:uppercase}.italic{font-style:italic}
        .tracking-widest{letter-spacing:.1em}.tracking-\\[0\\.3em\\]{letter-spacing:.3em}
        .leading-relaxed{line-height:1.625}.leading-loose{line-height:2}
        .text-left{text-align:left}.text-right{text-align:right}.text-center{text-align:center}
        .opacity-60{opacity:.6}
        .shadow-xl{box-shadow:0 20px 25px -5px rgba(0,0,0,.1),0 8px 10px -6px rgba(0,0,0,.1)}
        .shadow-2xl{box-shadow:0 25px 50px -12px rgba(0,0,0,.25)}
        .shadow-inner{box-shadow:inset 0 2px 4px 0 rgba(0,0,0,.06)}
        .transition-all{transition-property:all;transition-timing-function:cubic-bezier(.4,0,.2,1);transition-duration:.15s}
        .outline-none{outline:2px solid transparent;outline-offset:2px}
        .hover\\:scale-105:hover{transform:scale(1.05)}
        .active\\:scale-95:active{transform:scale(.95)}
        .hover\\:bg-cyan-400:hover{background-color:#22d3ee}.hover\\:bg-sky-600:hover{background-color:#0284c7}
        .hover\\:bg-emerald-600:hover{background-color:#059669}.hover\\:bg-teal-600:hover{background-color:#0d9488}
        .hover\\:text-cyan-400:hover{color:#22d3ee}
        .focus\\:border-cyan-500\\/50:focus{border-color:rgba(6,182,212,.5)}
        @media(min-width:768px){
            .md\\:flex-row{flex-direction:row}
            .md\\:p-12{padding:3rem}.md\\:p-14{padding:3.5rem}
            .md\\:py-24{padding-top:6rem;padding-bottom:6rem}
            .md\\:text-xs{font-size:.75rem;line-height:1rem}
            .md\\:text-lg{font-size:1.125rem;line-height:1.75rem}
            .md\\:text-7xl{font-size:4.5rem;line-height:1}
            .md\\:text-\\[14px\\]{font-size:14px}
        }
    </style>
    <style>
        body { background: #020617; color: #cbd5e1; font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; overflow-x: hidden; }
        .cyber-glass { background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(15px); border: 1px solid rgba(0, 243, 255, 0.08); }
        .lang-fa { direction: rtl; }
        .nav-active { background: #0ea5e9; color: white !important; border-color: #38bdf8 !important; box-shadow: 0 0 15px rgba(14, 165, 233, 0.3); }
        .panel { display: none; } .panel-active { display: block; animation: fadeInUp 0.3s ease-out; }
        @keyframes fadeInUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        code { color: #22d3ee; font-family: monospace; background: #000; padding: 3px 7px; border-radius: 6px; }
        .btn-tab { transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1); border: 1px solid #1e293b; }
    </style>
</head>
<body class="p-4 md:p-12">
    <!-- LANGUAGE SWITCHER -->
    <div class="fixed top-6 right-6 z-50">
        <button onclick="document.getElementById('langMenu').classList.toggle('hidden')" class="cyber-glass px-6 py-3 rounded-2xl flex items-center gap-4 text-xs font-bold border-cyan-500/20 hover:scale-105 transition-all shadow-2xl">
            🌐 <span id="currentLang">LANGUAGE</span>
        </button>
        <div id="langMenu" class="hidden absolute right-0 mt-3 cyber-glass p-2 rounded-2xl w-44 shadow-2xl border-slate-800">
            <button onclick="changeLang('en')" class="w-full text-left p-3 hover:bg-sky-600 rounded-xl text-xs mb-1">ENGLISH</button>
            <button onclick="changeLang('fa')" class="w-full text-right p-3 hover:bg-emerald-600 rounded-xl text-xs mb-1">فارسی</button>
            <button onclick="changeLang('zh')" class="w-full text-left p-3 hover:bg-teal-600 rounded-xl text-xs">简体中文</button>
        </div>
    </div>
    <div class="max-w-4xl mx-auto">
        <header class="text-center py-16 md:py-24">
            <h1 class="text-5xl md:text-7xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-300 to-emerald-400" id="mainTitle">Secure DNS over HTTPS</h1>
            <p id="subTag" class="mt-8 text-slate-500 font-bold uppercase tracking-[0.3em] text-[10px] md:text-xs">Edge Resolve Network • Intelligent HaGeZi Failover</p>
        </header>
        <section class="cyber-glass rounded-[3rem] p-8 md:p-14 mb-10 text-center">
            <div class="mb-6">
                <span class="text-[11px] font-black text-cyan-500 tracking-widest uppercase mb-4 block" id="labelUrl">Endpoint URL</span>
                <input id="linkInp" value="__DOH_ENDPOINT__" readonly class="w-full bg-black/40 border border-slate-800 p-5 rounded-2xl text-cyan-300 font-mono text-center text-sm outline-none focus:border-cyan-500/50 shadow-inner">
            </div>
            <button onclick="copyURL()" class="bg-cyan-600 hover:bg-cyan-400 text-black font-black px-12 py-5 rounded-2xl transition-all shadow-xl active:scale-95">
                <span id="txtCopy">COPY ENDPOINT</span>
            </button>
            <span id="copyStatus" role="status" aria-live="polite" class="block mt-3 text-xs text-cyan-300"></span>
        </section>
        <!-- TUTORIAL SECTION -->
        <div class="mb-16">
            <nav id="tutorialNav" class="flex flex-wrap gap-3 justify-center mb-8">
                <button onclick="tab('chrome', this)" id="btnC" class="btn-tab px-6 py-3 rounded-2xl text-[11px] font-black uppercase text-slate-400 nav-active">Chrome / Brave / Edge</button>
                <button onclick="tab('firefox', this)" id="btnF" class="btn-tab px-6 py-3 rounded-2xl text-[11px] font-black uppercase text-slate-400">Firefox</button>
                <button onclick="tab('mobile', this)" id="btnM" class="btn-tab px-6 py-3 rounded-2xl text-[11px] font-black uppercase text-slate-400">Android / iOS</button>
            </nav>
            <section id="docPanels" class="min-h-[300px]">
                <!-- Chrome/Edge Panel -->
                <div id="chrome" class="panel panel-active cyber-glass p-10 md:p-14 rounded-[3rem]">
                    <h3 class="text-2xl font-black mb-8 text-cyan-100" id="cH">Chromium Browser Settings</h3>
                    <ul class="list-none space-y-6 text-slate-400 text-sm leading-relaxed" id="cL">
                        <li>1. Open Browser <b>Settings</b> and find <b>Privacy &amp; Security</b>.</li>
                        <li>2. Scroll to <b>"Use Secure DNS"</b>.</li>
                        <li>3. Select <b>"With Custom"</b>.</li>
                        <li>4. Paste your DoH endpoint URL provided above.</li>
                    </ul>
                </div>
                <!-- Firefox Panel -->
                <div id="firefox" class="panel cyber-glass p-10 md:p-14 rounded-[3rem]">
                    <h3 class="text-2xl font-black mb-8 text-emerald-100" id="fH">Firefox Network Options</h3>
                    <ul class="list-none space-y-6 text-slate-400 text-sm leading-relaxed" id="fL">
                        <li>1. In Firefox <code>Settings</code>, search for "DNS over HTTPS".</li>
                        <li>2. Select <b>Custom</b> from the providers dropdown.</li>
                        <li>3. Paste this DoH endpoint URL and save.</li>
                    </ul>
                </div>
                <!-- Mobile/iOS Panel -->
                <div id="mobile" class="panel cyber-glass p-10 md:p-14 rounded-[3rem]">
                    <h3 class="text-2xl font-black mb-8 text-teal-100" id="mH">Mobile Setup Strategy</h3>
                    <p class="text-slate-500 text-sm mb-6 italic" id="mD">Smartphones often prioritize DoT hostnames in system settings. To use this Worker DoH endpoint:</p>
                    <ul class="list-none space-y-6 text-slate-400 text-sm" id="mL">
                        <li><b>In Browsers:</b> Setting it directly in Chrome or Firefox for Mobile is the easiest path.</li>
                        <li><b>For Apps:</b> On Android use <b>Intra</b> or <b>RethinkDNS</b>. On iOS install a compatible encrypted-DNS configuration profile.</li>
                    </ul>
                </div>
            </section>
        </div>
        <!-- SPECIAL EXPLANATION (Critical Point) -->
        <div class="cyber-glass p-8 md:p-12 rounded-[3.5rem] mb-20 border-sky-900/40 relative">
            <h4 class="text-sky-400 font-black text-base md:text-lg mb-6 flex items-center gap-3">
                ⭐ <span id="whyH">Why Browser-Level ONLY? (The Technical Reality)</span>
            </h4>
            <div class="space-y-6 text-[13px] md:text-[14px] text-slate-400 leading-loose" id="whyT">
                <p>Operating systems like Windows/Android often expect <b>DoT (Port 853)</b> or native resolver formats and may not accept a full <code>https://</code> DoH URL. Workers on Cloudflare run on <b>HTTPS (Port 443)</b>.</p><p><b>Result:</b> Modern browsers include their own DoH engine which works well on Port 443. DoH encrypts DNS queries between your browser and this Worker, but it does not hide destination IPs or guarantee bypass on every network.</p>
            </div>
        </div>
        <footer class="mt-32 pb-20 border-t border-slate-900 flex flex-col md:flex-row justify-between items-center opacity-60 gap-8">
            <div>
                <span class="text-[10px] font-black tracking-widest text-cyan-600 block mb-1">Secure DNS over HTTPS v${VERSION}</span>
                <p class="text-[9px] uppercase">Built with Edge-Computing Infrastructure</p>
            </div>
            <div class="flex gap-10 font-bold text-[10px] uppercase">
                <a href="https://github.com/anT0ny54/DOH-Cloudflare-Worker" class="hover:text-cyan-400" target="_blank" rel="noreferrer">GitHub</a>
            </div>
        </footer>
    </div>
    <script>
        const I18N = {
            // The English texts are the static markup above; they are captured
            // from the DOM at load time instead of being duplicated here.
            en: { copied: 'LINK CAPTURED!', copyFail: 'Copy failed: the endpoint is selected, press Ctrl+C / Cmd+C.', curL: 'ENGLISH' },
            fa: {
                main: 'سرویس امن DNS بر روی HTTPS', sub: 'پاسخگویی هوشمند با سه سرور HaGeZi و failover مرحله‌ای',
                urlL: 'آدرس مستقیم سرور شما (DoH)', cpT: 'کپی آدرس هوشمند', copied: 'لینک کپی شد!', copyFail: 'کپی انجام نشد؛ آدرس انتخاب شده است، Ctrl+C را بزنید.', tabC: 'خانواده کروم', tabF: 'فایرفاکس', tabM: 'اندروید و آیفون',
                cH: 'تنظیمات در کروم، اج و بریو', cL: '<li>۱. در تنظیمات مرورگر کلمه DNS را جستجو کنید.</li><li>۲. وارد بخش Security شوید و Use Secure DNS را پیدا کنید.</li><li>۳. آن را روی حالت <b>With Custom</b> قرار دهید.</li><li>۴. آدرس کپی شده از بالای این صفحه را در کادر قرار دهید.</li>',
                fH: 'تنظیمات در مرورگر فایرفاکس', fL: '<li>۱. در فایرفاکس وارد Settings شوید و DNS over HTTPS را جستجو کنید.</li><li>۲. آن را روی حالت Custom بگذارید.</li><li>۳. لینک اختصاصی خود را وارد و ذخیره کنید.</li>',
                mH: 'استراتژی راه‌اندازی در موبایل', mD: 'گوشی‌ها معمولاً در تنظیمات سیستمی به دنبال hostname برای DoT هستند؛ برای استفاده از سرویس DoH ما:',
                mL: '<li><b>داخل مرورگر:</b> بهترین راه تنظیم مستقیم در بخش Secure DNS خودِ کروم یا فایرفاکسِ گوشی است.</li><li><b>برای تمام برنامه‌ها:</b> از اپلیکیشن‌های <b>RethinkDNS</b> یا <b>Intra</b> در اندروید؛ در iOS از پروفایل DNS رمزگذاری‌شده استفاده کنید و لینک DoH را در آن‌ها ست کنید.</li>',
                whyH: 'چرا نمی‌توان در خیلی از تنظیمات سیستمی ست کرد؟',
                whyT: '<p>بسیاری از تنظیمات سیستمی ویندوز یا Private DNS اندروید، معمولاً <b>DoT (پورت ۸۵۳)</b> یا فرمت hostname می‌خواهند و اجازه نمی‌دهند آدرس کامل <code>https://</code> وارد کنید. این Worker روی <b>HTTPS (پورت ۴۴۳)</b> اجرا می‌شود.</p><p><b>راه حل:</b> مرورگرهای مدرن مثل کروم، اج و فایرفاکس موتور داخلی DoH دارند و با این Endpoint سازگارند. DoH درخواست‌های DNS بین مرورگر و این Worker را رمزنگاری می‌کند، اما IP مقصد را مخفی نمی‌کند و تضمین عبور در همه شبکه‌ها نیست.</p>',
                curL: 'فارسی (FA)'
            },
            zh: {
                main: 'Secure DoH 安全加密中心', sub: '基于边缘节点的智能 HaGeZi 故障转移',
                urlL: 'DoH 配置终端', cpT: '复制配置地址', copied: '已复制!', copyFail: '复制失败：地址已选中，请按 Ctrl+C / Cmd+C。', tabC: 'Chromium 引擎', tabF: 'Firefox 火狐', tabM: '安卓与 iOS',
                cH: 'Chromium 浏览器设置', cL: '<li>1. 进入浏览器“设置”，搜索“安全 DNS”。</li><li>2. 将服务提供商设置为“自定义 (Custom)”。</li><li>3. 粘贴本页面的 DoH 链接，然后重启浏览器生效。</li>',
                fH: '火狐浏览器配置指南', fL: '<li>1. 在火狐“设置”中搜索 DNS over HTTPS。</li><li>2. 选择自定义提供商。</li><li>3. 输入 DoH 服务器地址并确认保存。</li>',
                mH: '移动端解析说明', mD: '移动操作系统通常默认系统级 DoT 格式；若要使用此 DoH 服务器:',
                mL: '<li><b>浏览器设置:</b> 直接在安卓或苹果手机的浏览器（Chrome/Firefox）内按上述桌面步骤配置即可。</li><li><b>全系统生效:</b> 安卓可安装 <b>RethinkDNS</b> 或 <b>Intra</b> App；iOS 请安装兼容的加密 DNS 配置描述文件，并在软件中设置本页面地址。</li>',
                whyH: '为什么通常建议在浏览器配置? (技术架构说明)',
                whyT: '<p>Windows 或安卓系统的 Private DNS 设置项通常需要 <b>DoT / 853 端口</b> 或主机名格式，而不一定接受完整 HTTPS URL。本项目基于 <b>Port 443</b> 的 Cloudflare Worker 环境构建。</p><p><b>建议:</b> 浏览器自带独立 DoH 解析器，可直接使用此 Endpoint。DoH 会加密浏览器与此 Worker 之间的 DNS 查询，但不会隐藏目标 IP，也不能保证在所有网络中绕过限制。</p>',
                curL: '简体中文'
            }
        };
        // I18N key -> element id. Every value is a trusted constant from this file.
        const FIELDS = { main: 'mainTitle', sub: 'subTag', urlL: 'labelUrl', cpT: 'txtCopy', tabC: 'btnC', tabF: 'btnF', tabM: 'btnM',
            cH: 'cH', cL: 'cL', fH: 'fH', fL: 'fL', mH: 'mH', mD: 'mD', mL: 'mL', whyH: 'whyH', whyT: 'whyT' };
        for (const [key, id] of Object.entries(FIELDS)) I18N.en[key] = document.getElementById(id).innerHTML;
        function getStoredLanguage() {
            let stored = 'en';
            try { stored = localStorage.getItem('doc_v6') || 'en'; } catch (_) {}
            return I18N[stored] ? stored : 'en';
        }
        function changeLang(c) {
            if (!I18N[c]) c = 'en';
            try { localStorage.setItem('doc_v6', c); } catch (_) {}
            const l = I18N[c];
            document.body.classList.toggle('lang-fa', c === 'fa');
            document.documentElement.lang = c;
            document.getElementById('currentLang').innerText = l.curL;
            for (const [key, id] of Object.entries(FIELDS)) document.getElementById(id).innerHTML = l[key];
            document.getElementById('copyStatus').textContent = '';
            document.getElementById('langMenu').classList.add('hidden');
        }
        function tab(id, el) {
            document.querySelectorAll('.panel-active').forEach(p => { p.classList.remove('panel-active'); });
            document.querySelectorAll('.btn-tab').forEach(b => b.classList.remove('nav-active'));
            document.getElementById(id).classList.add('panel-active');
            el.classList.add('nav-active');
        }
        async function copyURL() {
            const el = document.getElementById('linkInp');
            const status = document.getElementById('copyStatus');
            const l = I18N[getStoredLanguage()];
            try {
                await navigator.clipboard.writeText(el.value);
                status.textContent = l.copied;
            } catch (_) {
                el.focus();
                el.select();
                status.textContent = l.copyFail;
            }
        }
        const initialLang = getStoredLanguage();
        if (initialLang === 'en') document.getElementById('currentLang').innerText = I18N.en.curL;
        else changeLang(initialLang);
    </script>
</body>
</html>`;
}
function renderUI(host) {
  const endpoint = escapeHtml(`https://${host}${CONFIG.DNS_PATH}`);
  const html = getUITemplate().join(endpoint);
  return new Response(html, {
    status: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'public, max-age=300',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    }
  });
}