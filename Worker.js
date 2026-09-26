/**
 * VERSION: 0.1.2
 * GITHUB: https://github.com/anT0ny54/DOH-Cloudflare-Worker
 * Runtime: Cloudflare Workers Module Syntax
 */

const VERSION = '0.1.2';

const CONFIG = {
  DNS_PATH: '/dns-query',

  // Two-level DNS cache. L1 is an isolate-local hot cache; L2 is the
  // Cloudflare Cache API for requests handled by the same data center.
  // The cache key is derived from the complete DNS wire query with the ID
  // normalized, so GET and POST can share cached answers safely.
  EDGE_CACHE_ENABLED: true,
  EDGE_CACHE_PATH: '/__doh-cache/v1',
  LOCAL_CACHE_MAX_TTL_SECONDS: 300,
  EDGE_CACHE_MAX_TTL_SECONDS: 3600,
  EDGE_CACHE_MIN_TTL_SECONDS: 1,
  MAX_CACHE_ENTRIES: 512,
  MAX_INFLIGHT_ENTRIES: 256,

  // Preferred: Cloudflare's native Rate Limiting binding (100/60s per IP).
  // Fallback: lightweight per-isolate fixed-window limiter when the binding is
  // not configured.
  RATE_LIMIT_WINDOW_MS: 60_000,
  RATE_LIMIT_MAX_REQUESTS: 100,
  MAX_THROTTLE_ENTRIES: 2048,

  // DoH packets should be tiny. Reject oversize input before buffering it when
  // Content-Length is available, and stream-limit unknown-length POST bodies.
  MAX_DNS_MESSAGE_BYTES: 4096,
  MAX_DNS_RESPONSE_BYTES: 65535,
  MAX_GET_DNS_CHARS: 5462,

  // Intelligent hedging: start with one resolver, then add a backup only when
  // the current attempt is slow or fails. The third resolver is last-resort
  // recovery, not part of the normal hot path.
  UPSTREAM_TIMEOUT_MS: 1200,
  HEDGE_MIN_MS: 80,
  HEDGE_MAX_MS: 220,
  SECONDARY_HEDGE_MIN_MS: 120,
  SECONDARY_HEDGE_MAX_MS: 260,

  SCORE_START: 100,
  SCORE_MIN: 0,
  SCORE_MAX: 100,
  SCORE_SUCCESS_DELTA: 1,
  SCORE_FAILURE_DELTA: 12,
  SCORE_TIMEOUT_DELTA: 8
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
  lastLatencyMs: null,
  ewmaLatencyMs: null,
  lastError: null
}));

const APP_STATE = {
  cache: new Map(),
  throttle: new Map(),
  inflight: new Map(),
  primaryCursor: 0
};

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const clientIP = getClientIP(req);

    if (url.pathname === CONFIG.DNS_PATH) {
      if (!(await allowDNSRequest(clientIP, env))) {
        return textResponse('Rate limit exceeded', 429, {
          'cache-control': 'no-store',
          'retry-after': '60'
        });
      }

      return handleDNS(req, url, ctx);
    }

    if (url.pathname === '/health') {
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
  const methodError = validateMethod(req.method);
  if (methodError) return methodError;

  let payload;

  try {
    payload = await readDNSPayload(req, url);
  } catch (err) {
    return textResponse(err.message || 'Invalid DNS query', err.status || 400, {
      'cache-control': 'no-store'
    });
  }

  if (!payload || payload.byteLength === 0) {
    return textResponse('Empty DNS query', 400, { 'cache-control': 'no-store' });
  }

  if (payload.byteLength > CONFIG.MAX_DNS_MESSAGE_BYTES) {
    return textResponse('DNS message too large', 413, { 'cache-control': 'no-store' });
  }

  const parsed = parseDNSQuestion(payload);
  if (!parsed.ok) {
    return textResponse(parsed.error, 400, { 'cache-control': 'no-store' });
  }

  const cacheKey = await makeCacheKey(payload);

  // L1: cheapest possible path.
  const localHit = getCache(cacheKey);
  if (localHit) {
    const ageSeconds = Math.max(0, Math.floor((Date.now() - localHit.storedAt) / 1000));
    const responseBody = patchDNSResponseForAge(localHit.body, parsed.id, ageSeconds);
    return dnsResponse(responseBody, {
      'x-cache': 'L1-HIT',
      'x-edge-cache': 'SKIP',
      'x-upstreams': '0'
    });
  }

  // Coalesce concurrent misses for the same DNS packet inside an isolate.
  // This prevents a burst of identical cold queries from multiplying upstream
  // traffic before the first response has reached either cache.
  const existing = APP_STATE.inflight.get(cacheKey);
  if (existing) {
    const shared = await existing;
    const ageSeconds = Math.max(0, Math.floor((Date.now() - shared.storedAt) / 1000));
    setCache(cacheKey, shared.body, Math.min(shared.ttlSeconds, CONFIG.LOCAL_CACHE_MAX_TTL_SECONDS), shared.storedAt);
    const responseBody = patchDNSResponseForAge(shared.body, parsed.id, ageSeconds);
    return dnsResponse(responseBody, {
      'x-cache': 'COALESCED',
      'x-edge-cache': 'SKIP',
      'x-upstreams': '0',
      'x-winner': sanitizeHeaderValue(shared.url),
      'x-winner-lat': `${shared.latencyMs}ms`
    });
  }

  // L2: Cache API. This runs after the rate limiter, so enabling this cache
  // does not bypass the per-IP /dns-query protection.
  if (CONFIG.EDGE_CACHE_ENABLED) {
    const edgeHit = await getEdgeCache(cacheKey, parsed.id, url.origin);
    if (edgeHit) {
      setCache(cacheKey, edgeHit.body, Math.min(edgeHit.ttlSeconds, CONFIG.LOCAL_CACHE_MAX_TTL_SECONDS), edgeHit.storedAt);
      return dnsResponse(edgeHit.responseBody, {
        'x-cache': 'L2-HIT',
        'x-edge-cache': 'HIT',
        'x-upstreams': '0'
      });
    }
  }

  // A second in-flight check closes the race between the L2 lookup and creating
  // a new upstream job.
  const raced = APP_STATE.inflight.get(cacheKey);
  if (raced) {
    const shared = await raced;
    const ageSeconds = Math.max(0, Math.floor((Date.now() - shared.storedAt) / 1000));
    setCache(cacheKey, shared.body, Math.min(shared.ttlSeconds, CONFIG.LOCAL_CACHE_MAX_TTL_SECONDS), shared.storedAt);
    const responseBody = patchDNSResponseForAge(shared.body, parsed.id, ageSeconds);
    return dnsResponse(responseBody, {
      'x-cache': 'COALESCED',
      'x-edge-cache': 'SKIP',
      'x-upstreams': '0',
      'x-winner': sanitizeHeaderValue(shared.url),
      'x-winner-lat': `${shared.latencyMs}ms`
    });
  }

  const resolvers = selectRacers(RESOLVER_NODES);
  const job = (async () => {
    const result = await resolveWithHedging(resolvers, payload, parsed.id);
    const storedAt = Date.now();
    let ttlSeconds = 0;
    let normalizedBody = result.body;

    if (isCacheableDNSResponse(result.body)) {
      ttlSeconds = getDNSCacheTTL(result.body);
      if (ttlSeconds > 0) {
        normalizedBody = normalizeDNSResponseID(result.body);
        const localTTL = Math.min(ttlSeconds, CONFIG.LOCAL_CACHE_MAX_TTL_SECONDS);
        setCache(cacheKey, normalizedBody, localTTL, storedAt);
        if (CONFIG.EDGE_CACHE_ENABLED) {
          ctx.waitUntil(putEdgeCache(
            cacheKey,
            normalizedBody,
            Math.min(ttlSeconds, CONFIG.EDGE_CACHE_MAX_TTL_SECONDS),
            storedAt,
            url.origin
          ));
        }
      }
    }

    return {
      ...result,
      body: normalizedBody,
      ttlSeconds,
      storedAt
    };
  })();

  APP_STATE.inflight.set(cacheKey, job);
  trimMap(APP_STATE.inflight, CONFIG.MAX_INFLIGHT_ENTRIES);

  try {
    const result = await job;
    const responseBody = patchDNSResponseForAge(result.body, parsed.id, 0);
    const headers = {
      'x-cache': 'MISS',
      'x-edge-cache': CONFIG.EDGE_CACHE_ENABLED ? 'MISS' : 'DISABLED',
      'x-upstreams': String(result.attempts),
      'x-winner': sanitizeHeaderValue(result.url),
      'x-winner-lat': `${result.latencyMs}ms`
    };

    if (result.degraded) headers['x-dns-degraded'] = '1';

    return dnsResponse(responseBody, headers);
  } catch (err) {
    return textResponse('Global resolving failed', 502, {
      'cache-control': 'no-store',
      'x-upstreams': String(err.attempts || resolvers.length)
    });
  } finally {
    if (APP_STATE.inflight.get(cacheKey) === job) APP_STATE.inflight.delete(cacheKey);
  }
}

function validateMethod(method) {
  if (method !== 'GET' && method !== 'POST') {
    return textResponse('Method not allowed', 405, {
      allow: 'GET, POST',
      'cache-control': 'no-store'
    });
  }

  return null;
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

  const contentType = req.headers.get('content-type') || '';
  if (!contentType.toLowerCase().includes('application/dns-message')) {
    throw httpError('POST requires content-type: application/dns-message', 415);
  }

  const contentLength = req.headers.get('content-length');
  if (contentLength !== null) {
    const n = Number(contentLength);
    if (Number.isFinite(n) && n > CONFIG.MAX_DNS_MESSAGE_BYTES) {
      throw httpError('DNS message too large', 413);
    }
  }

  // Avoid buffering attacker-sized chunked uploads. Typical DoH requests are
  // a few hundred bytes, so this path stays allocation-light.
  const reader = req.body?.getReader();
  if (!reader) return new Uint8Array(await req.arrayBuffer());

  const chunks = [];
  let total = 0;

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;

      total += value.byteLength;
      if (total > CONFIG.MAX_DNS_MESSAGE_BYTES) {
        await reader.cancel('dns-message-too-large');
        throw httpError('DNS message too large', 413);
      }
      chunks.push(value);
    }
  } finally {
    try { await reader.releaseLock(); } catch (_) {}
  }

  if (chunks.length === 1) return new Uint8Array(chunks[0]);

  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

function decodeBase64Url(input) {
  if (!input || !/^[A-Za-z0-9_-]+$/.test(input)) {
    throw httpError('Invalid base64url DNS query', 400);
  }

  let normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  normalized += '='.repeat((4 - (normalized.length % 4)) % 4);

  try {
    const decoded = atob(normalized);
    const bytes = new Uint8Array(decoded.length);
    for (let i = 0; i < decoded.length; i++) bytes[i] = decoded.charCodeAt(i);

    if (bytes.byteLength > CONFIG.MAX_DNS_MESSAGE_BYTES) {
      throw httpError('DNS message too large', 413);
    }
    return bytes;
  } catch (err) {
    if (err && err.status) throw err;
    throw httpError('Invalid base64url DNS query', 400);
  }
}

// Strictly validate the incoming DNS query while avoiding qname/string allocations.
// The request path only needs the original DNS transaction ID after validation.
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
  const arcount = (bytes[10] << 8) | bytes[11];

  if ((flags & 0x8000) !== 0) {
    return { ok: false, error: 'DNS query expected, got response' };
  }

  const opcode = (flags >>> 11) & 0x0f;
  if (opcode !== 0) {
    return { ok: false, error: 'Only standard DNS queries are supported' };
  }

  // Bit 6 of the DNS flags word remains reserved; modern DNS uses bits 5/4
  // for DNSSEC AD/CD semantics, so only the actual reserved Z bit is rejected.
  if ((flags & 0x0040) !== 0) {
    return { ok: false, error: 'Reserved DNS flag bit is set' };
  }

  if (qdcount !== 1 || ancount !== 0 || nscount !== 0) {
    return { ok: false, error: 'Invalid DNS query section counts' };
  }

  let offset = 12;
  let wireNameLength = 1; // Includes the terminating zero octet.
  let terminated = false;

  while (offset < bytes.length) {
    const len = bytes[offset++];

    if (len === 0) {
      terminated = true;
      break;
    }

    if ((len & 0xc0) !== 0) {
      return { ok: false, error: 'Invalid DNS label encoding' };
    }

    if (len > 63 || offset + len > bytes.length) {
      return { ok: false, error: 'Invalid DNS question name' };
    }

    wireNameLength += 1 + len;
    if (wireNameLength > 255) {
      return { ok: false, error: 'DNS question name too long' };
    }

    offset += len;
  }

  if (!terminated || offset + 4 > bytes.length) {
    return { ok: false, error: 'Incomplete DNS question' };
  }

  // QTYPE + QCLASS.
  offset += 4;

  // Additional records are allowed for EDNS(0) and other standards-compliant
  // DNS extensions. Validate their wire structure instead of rejecting all
  // packets with ARCOUNT > 0.
  for (let i = 0; i < arcount; i++) {
    const rr = readResourceRecord(bytes, offset);
    if (!rr) {
      return { ok: false, error: 'Invalid DNS additional section' };
    }
    offset = rr.end;
  }

  if (offset !== bytes.length) {
    return { ok: false, error: 'Trailing data after DNS message' };
  }

  return {
    ok: true,
    id
  };
}

function normalizeDNSResponseID(responseBuffer) {
  const bytes = new Uint8Array(responseBuffer);
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  copy[0] = 0;
  copy[1] = 0;
  return copy.buffer;
}

function isCacheableDNSResponse(responseBuffer) {
  const bytes = new Uint8Array(responseBuffer);

  if (bytes.length < 12) return false;

  const flags = (bytes[2] << 8) | bytes[3];
  const isResponse = (flags & 0x8000) !== 0;
  const rcode = flags & 0x000f;

  if (!isResponse) return false;

  // Cache NOERROR and NXDOMAIN only. Avoid caching SERVFAIL, REFUSED, etc.
  return rcode === 0 || rcode === 3;
}

function selectRacers(resolvers) {
  const ranked = [...resolvers].sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    const al = a.ewmaLatencyMs ?? Number.MAX_SAFE_INTEGER;
    const bl = b.ewmaLatencyMs ?? Number.MAX_SAFE_INTEGER;
    if (al !== bl) return al - bl;
    return a.order - b.order;
  });

  // Rotate only among similarly healthy endpoints so a healthy resolver does
  // not become a permanent hot spot, while failed endpoints naturally fall
  // behind and remain available as recovery targets.
  const bestScore = ranked[0]?.score ?? 0;
  const pool = ranked.filter((node) => node.score >= bestScore - 8);

  if (pool.length <= 1) return ranked;

  const chosen = pool[APP_STATE.primaryCursor++ % pool.length];
  return [chosen, ...ranked.filter((node) => node !== chosen)];
}

async function resolveWithHedging(nodes, packet, expectedID) {
  if (!nodes.length) throw new Error('No upstreams configured');

  const controllers = new Map();
  const active = new Map();
  const attempts = [];
  let nextIndex = 0;
  let fallback = null;

  const startAttempt = (node) => {
    const controller = new AbortController();
    controllers.set(node, controller);

    const promise = relay(node, packet, expectedID, controller.signal)
      .then((value) => ({ ok: true, node, value }))
      .catch((error) => ({ ok: false, node, error }));

    active.set(node, promise);
    attempts.push(node);
  };

  startAttempt(nodes[nextIndex++]);
  let hedgeDelay = getHedgeDelay(nodes[0]);

  try {
    while (active.size) {
      const result = await raceUntilActiveSettles(active, hedgeDelay);

      if (result.type === 'timer') {
        if (nextIndex < nodes.length) {
          startAttempt(nodes[nextIndex++]);
          hedgeDelay = getSecondaryHedgeDelay();
          continue;
        }

        // No more upstreams to start. Wait for whatever is already in flight.
        hedgeDelay = CONFIG.UPSTREAM_TIMEOUT_MS;
        continue;
      }

      active.delete(result.node);

      if (result.ok) {
        const value = result.value;

        if (value.usable) {
          abortAttempts(controllers, result.node);
          return {
            ...value,
            attempts: attempts.length
          };
        }

        // A syntactically valid SERVFAIL/REFUSED/etc. is preferable to a 502
        // when every resolver produces a DNS response, but keep trying others.
        fallback = value;

        // Do not launch the third resolver while a backup is already in flight.
        // Let that backup finish first; the existing hedge timer still provides
        // a last-resort third attempt when both active requests remain slow.
        if (nextIndex < nodes.length && active.size === 0) {
          startAttempt(nodes[nextIndex++]);
          hedgeDelay = nextIndex === 2
            ? getSecondaryHedgeDelay()
            : CONFIG.UPSTREAM_TIMEOUT_MS;
        }
        continue;
      }

      if (nextIndex < nodes.length) {
        // If another backup is already in flight, give it a short chance to
        // succeed before opening a third connection. A failed primary does not
        // by itself justify three concurrent upstream requests.
        if (active.size === 0) {
          startAttempt(nodes[nextIndex++]);
          hedgeDelay = nextIndex === 2
            ? getSecondaryHedgeDelay()
            : CONFIG.UPSTREAM_TIMEOUT_MS;
        } else {
          hedgeDelay = getSecondaryHedgeDelay();
        }
      }
    }

    if (fallback) {
      return {
        ...fallback,
        attempts: attempts.length
      };
    }

    const err = new Error('All DNS upstreams failed');
    err.attempts = attempts.length;
    throw err;
  } finally {
    abortAttempts(controllers);
  }
}

async function raceUntilActiveSettles(active, timeoutMs) {
  let timeoutHandle;
  const timer = new Promise((resolve) => {
    timeoutHandle = setTimeout(() => resolve({ type: 'timer' }), timeoutMs);
  });

  const settled = [...active.values()].map((promise) =>
    promise.then((result) => ({ type: 'result', ...result }))
  );

  try {
    return await Promise.race([timer, ...settled]);
  } finally {
    // Whichever of "settled" or "timer" wins, the loser's timer must not
    // linger: an uncleared hedge timer keeps firing on every subsequent
    // iteration and can outlive the request that created it.
    clearTimeout(timeoutHandle);
  }
}

function abortAttempts(controllers, winnerNode) {
  for (const [node, controller] of controllers) {
    if (!winnerNode || node !== winnerNode) {
      try { controller.abort('winner-selected'); } catch (_) {}
    }
  }
}

function getHedgeDelay(node) {
  const learned = node.ewmaLatencyMs ?? 120;
  return clamp(Math.round(learned * 1.5), CONFIG.HEDGE_MIN_MS, CONFIG.HEDGE_MAX_MS);
}

function getSecondaryHedgeDelay() {
  return clamp(150, CONFIG.SECONDARY_HEDGE_MIN_MS, CONFIG.SECONDARY_HEDGE_MAX_MS);
}

async function relay(node, packet, expectedID, signal) {
  const started = Date.now();
  const timeoutController = new AbortController();
  const timeout = setTimeout(() => timeoutController.abort('timeout'), CONFIG.UPSTREAM_TIMEOUT_MS);
  const combinedSignal = anySignal([signal, timeoutController.signal]);

  try {
    const res = await fetch(node.url, {
      method: 'POST',
      headers: {
        accept: 'application/dns-message',
        'content-type': 'application/dns-message'
      },
      body: packet,
      signal: combinedSignal
    });

    if (!res.ok) {
      throw new Error(`Upstream HTTP ${res.status}`);
    }

    const body = await readBoundedDNSResponse(res);
    const validation = validateDNSResponse(body, expectedID, packet);

    if (!validation.ok) {
      throw new Error(validation.error);
    }

    const latencyMs = Date.now() - started;
    const rcode = validation.rcode;
    const usable = rcode === 0 || rcode === 3;

    if (usable) {
      reward(node, latencyMs);
    } else {
      penalize(node, CONFIG.SCORE_FAILURE_DELTA, `DNS RCODE ${rcode}`);
    }

    return {
      url: node.url,
      body,
      latencyMs,
      rcode,
      usable,
      degraded: !usable
    };
  } catch (err) {
    const message = String(err && err.message ? err.message : err);
    const raceAbort = signal?.aborted && !timeoutController.signal.aborted;
    const timeoutAbort = timeoutController.signal.aborted
      || message.toLowerCase().includes('timeout');

    if (raceAbort) throw err;

    if (timeoutAbort) {
      node.timeout += 1;
      penalize(node, CONFIG.SCORE_TIMEOUT_DELTA, 'timeout');
    } else {
      penalize(node, CONFIG.SCORE_FAILURE_DELTA, message);
    }

    throw err;
  } finally {
    clearTimeout(timeout);
  }
}

function validateDNSResponse(responseBuffer, expectedID, requestPacket) {
  const bytes = new Uint8Array(responseBuffer);

  if (bytes.length < 12) return { ok: false, error: 'Upstream returned short DNS response' };

  const id = (bytes[0] << 8) | bytes[1];
  const flags = (bytes[2] << 8) | bytes[3];
  const rcode = flags & 0x000f;
  const opcode = (flags >>> 11) & 0x0f;
  const qdcount = (bytes[4] << 8) | bytes[5];
  const ancount = (bytes[6] << 8) | bytes[7];
  const nscount = (bytes[8] << 8) | bytes[9];
  const arcount = (bytes[10] << 8) | bytes[11];

  if (id !== expectedID) return { ok: false, error: 'Upstream response ID mismatch' };
  if ((flags & 0x8000) === 0) return { ok: false, error: 'Upstream returned a DNS query, not response' };
  if (opcode !== 0) return { ok: false, error: 'Upstream returned unsupported DNS opcode' };
  if ((flags & 0x0040) !== 0) return { ok: false, error: 'Upstream response has reserved DNS flag bit set' };
  if (qdcount !== 1) return { ok: false, error: 'Upstream returned invalid question count' };
  if (!requestPacket) return { ok: false, error: 'Original DNS query is required for response validation' };

  const request = new Uint8Array(requestPacket);
  if (request.length < 12) return { ok: false, error: 'Original DNS query is invalid' };

  const requestQuestionEnd = getDNSQuestionEnd(request);
  const responseQuestionEnd = getDNSQuestionEnd(bytes);
  if (requestQuestionEnd < 0 || responseQuestionEnd < 0) {
    return { ok: false, error: 'Upstream returned malformed DNS question' };
  }

  const requestQuestion = request.subarray(12, requestQuestionEnd);
  const responseQuestion = bytes.subarray(12, responseQuestionEnd);
  if (requestQuestion.length !== responseQuestion.length) {
    return { ok: false, error: 'Upstream response question mismatch' };
  }

  for (let i = 0; i < requestQuestion.length; i++) {
    if (!dnsQuestionByteEquals(requestQuestion[i], responseQuestion[i])) {
      return { ok: false, error: 'Upstream response question mismatch' };
    }
  }

  let offset = responseQuestionEnd;
  const counts = [ancount, nscount, arcount];
  for (const count of counts) {
    for (let i = 0; i < count; i++) {
      const rr = readResourceRecord(bytes, offset);
      if (!rr) return { ok: false, error: 'Upstream returned malformed DNS resource record' };
      offset = rr.end;
    }
  }

  if (offset !== bytes.length) {
    return { ok: false, error: 'Upstream returned trailing DNS data' };
  }

  return { ok: true, rcode };
}

// DNS names are case-insensitive (RFC 1035 3.1 / RFC 4343). A compliant
// resolver is free to echo the question back with different letter case
// than the outgoing query (some implementations normalize case, and
// case-randomization ["0x20 encoding"] clients rely on this exact byte
// range for anti-spoofing entropy), so an exact byte-for-byte compare would
// wrongly treat those legitimate answers as a mismatch and fail the whole
// upstream. Label-length octets are always <= 63 (0x3F) and QTYPE/QCLASS
// octets used by this Worker never fall in the ASCII letter ranges either,
// so folding case only for actual A-Z/a-z bytes cannot misclassify
// structural framing bytes as name content.
function dnsQuestionByteEquals(a, b) {
  if (a === b) return true;
  const aIsLetter = (a >= 0x41 && a <= 0x5a) || (a >= 0x61 && a <= 0x7a);
  const bIsLetter = (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a);
  return aIsLetter && bIsLetter && (a | 0x20) === (b | 0x20);
}

function getDNSQuestionEnd(bytes) {
  if (bytes.length < 12) return -1;

  const qdcount = (bytes[4] << 8) | bytes[5];
  if (qdcount !== 1) return -1;

  let offset = 12;
  const nameEnd = skipDNSName(bytes, offset);
  if (nameEnd < 0 || nameEnd + 4 > bytes.length) return -1;
  return nameEnd + 4;
}

async function readBoundedDNSResponse(res) {
  const contentLength = res.headers.get('content-length');
  if (contentLength !== null) {
    const n = Number(contentLength);
    if (Number.isFinite(n) && n > CONFIG.MAX_DNS_RESPONSE_BYTES) {
      throw new Error('Upstream DNS response too large');
    }
  }

  const reader = res.body?.getReader();
  if (!reader) {
    const body = new Uint8Array(await res.arrayBuffer());
    if (body.byteLength > CONFIG.MAX_DNS_RESPONSE_BYTES) {
      throw new Error('Upstream DNS response too large');
    }
    return body.buffer;
  }

  const chunks = [];
  let total = 0;

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;

      total += value.byteLength;
      if (total > CONFIG.MAX_DNS_RESPONSE_BYTES) {
        await reader.cancel('dns-response-too-large');
        throw new Error('Upstream DNS response too large');
      }
      chunks.push(value);
    }
  } finally {
    try { await reader.releaseLock(); } catch (_) {}
  }

  if (chunks.length === 1) return new Uint8Array(chunks[0]).buffer;

  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out.buffer;
}

function anySignal(signals) {
  const controller = new AbortController();

  function abortFrom(signal) {
    if (!controller.signal.aborted) {
      controller.abort(signal.reason || 'aborted');
    }
  }

  for (const signal of signals) {
    if (!signal) continue;
    if (signal.aborted) {
      abortFrom(signal);
      break;
    }
    signal.addEventListener('abort', () => abortFrom(signal), { once: true });
  }

  return controller.signal;
}

function reward(node, latencyMs) {
  node.ok += 1;
  node.lastLatencyMs = latencyMs;
  node.ewmaLatencyMs = node.ewmaLatencyMs == null
    ? latencyMs
    : Math.round(node.ewmaLatencyMs * 0.8 + latencyMs * 0.2);
  node.lastError = null;
  node.score = clamp(node.score + CONFIG.SCORE_SUCCESS_DELTA, CONFIG.SCORE_MIN, CONFIG.SCORE_MAX);
}

function penalize(node, amount, error) {
  node.fail += 1;
  node.lastError = String(error || 'unknown').slice(0, 80);
  node.score = clamp(node.score - amount, CONFIG.SCORE_MIN, CONFIG.SCORE_MAX);
}

async function makeCacheKey(packet) {
  // One compact hash gives GET and POST the same cache namespace and avoids
  // repeatedly parsing the DNS name/options just to build a string key.
  const bytes = packet instanceof Uint8Array ? packet : new Uint8Array(packet);
  const normalized = bytes.slice();
  normalized[0] = 0;
  normalized[1] = 0;

  const digest = await crypto.subtle.digest('SHA-256', normalized);
  const view = new Uint8Array(digest, 0, 16); // 128-bit cache key
  let out = '';
  for (let i = 0; i < view.length; i++) out += view[i].toString(16).padStart(2, '0');
  return out;
}

function getCache(key) {
  const item = APP_STATE.cache.get(key);
  if (!item) return null;

  if (Date.now() >= item.expiresAt) {
    APP_STATE.cache.delete(key);
    return null;
  }

  // LRU refresh.
  APP_STATE.cache.delete(key);
  APP_STATE.cache.set(key, item);
  return item;
}

function setCache(key, body, ttlSeconds, storedAt = Date.now()) {
  const ttl = Math.max(1, Math.floor(ttlSeconds));
  APP_STATE.cache.set(key, {
    body,
    storedAt,
    expiresAt: storedAt + ttl * 1000
  });

  trimMap(APP_STATE.cache, CONFIG.MAX_CACHE_ENTRIES);
}

function getDNSCacheTTL(responseBuffer) {
  const bytes = new Uint8Array(responseBuffer);
  if (bytes.length < 12) return 0;

  const flags = (bytes[2] << 8) | bytes[3];
  if ((flags & 0x8000) === 0) return 0;
  if ((flags & 0x0200) !== 0) return 0; // TC: do not cache truncated answers

  const rcode = flags & 0x000f;
  if (rcode !== 0 && rcode !== 3) return 0;

  const qdcount = (bytes[4] << 8) | bytes[5];
  const ancount = (bytes[6] << 8) | bytes[7];
  const nscount = (bytes[8] << 8) | bytes[9];
  const arcount = (bytes[10] << 8) | bytes[11];

  let offset = 12;
  for (let i = 0; i < qdcount; i++) {
    offset = skipDNSName(bytes, offset);
    if (offset < 0 || offset + 4 > bytes.length) return 0;
    offset += 4;
  }

  let answerMin = Number.MAX_SAFE_INTEGER;
  let authorityMin = Number.MAX_SAFE_INTEGER;
  let soaNegativeMin = Number.MAX_SAFE_INTEGER;

  const sections = [
    ['answer', ancount],
    ['authority', nscount],
    ['additional', arcount]
  ];

  for (const [section, count] of sections) {
    for (let i = 0; i < count; i++) {
      const rr = readResourceRecord(bytes, offset);
      if (!rr) return 0;
      offset = rr.end;

      // OPT and other meta records are not useful DNS answer TTLs here.
      if (rr.type === 41) continue;

      if (section === 'answer') {
        answerMin = Math.min(answerMin, rr.ttl);
      } else if (section === 'authority') {
        authorityMin = Math.min(authorityMin, rr.ttl);
        if (rr.type === 6 && rr.rdLength >= 20) {
          const minimumOffset = findSOAMinimumOffset(bytes, rr.rdataOffset, rr.rdEnd);
          if (minimumOffset >= 0) {
            soaNegativeMin = Math.min(soaNegativeMin, readUint32(bytes, minimumOffset));
          }
        }
      }
    }
  }

  let ttl;
  if (rcode === 3 || (rcode === 0 && ancount === 0)) {
    ttl = Math.min(authorityMin, soaNegativeMin);
  } else {
    ttl = answerMin;
  }

  if (!Number.isFinite(ttl) || ttl <= 0) return 0;

  return clamp(
    Math.floor(ttl),
    CONFIG.EDGE_CACHE_MIN_TTL_SECONDS,
    CONFIG.EDGE_CACHE_MAX_TTL_SECONDS
  );
}

function skipDNSName(bytes, offset) {
  if (offset < 0 || offset >= bytes.length) return -1;

  let pos = offset;
  let jumps = 0;
  let end = -1;
  const visited = new Set();

  while (pos < bytes.length) {
    const labelOffset = pos;
    const len = bytes[pos++];

    if (len === 0) {
      if (end < 0) end = pos;
      return end;
    }

    if ((len & 0xc0) === 0xc0) {
      if (pos >= bytes.length) return -1;

      const pointer = ((len & 0x3f) << 8) | bytes[pos];
      pos += 1;

      // Compression pointers must reference a prior byte in this message.
      if (pointer < 12 || pointer >= labelOffset) return -1;
      if (visited.has(pointer)) return -1;
      visited.add(pointer);

      if (end < 0) end = pos;
      if (++jumps > 255) return -1;
      pos = pointer;
      continue;
    }

    if ((len & 0xc0) !== 0 || len > 63 || pos + len > bytes.length) return -1;
    pos += len;
  }

  return -1;
}

function readResourceRecord(bytes, offset) {
  const nameEnd = skipDNSName(bytes, offset);
  if (nameEnd < 0 || nameEnd + 10 > bytes.length) return null;

  const type = (bytes[nameEnd] << 8) | bytes[nameEnd + 1];
  const ttl = readUint32(bytes, nameEnd + 4);
  const rdLength = (bytes[nameEnd + 8] << 8) | bytes[nameEnd + 9];
  const rdataOffset = nameEnd + 10;
  const rdEnd = rdataOffset + rdLength;

  if (rdEnd > bytes.length) return null;
  return {
    type,
    ttl,
    rdLength,
    rdataOffset,
    rdEnd,
    end: rdEnd
  };
}

function findSOAMinimumOffset(bytes, rdataOffset, rdEnd) {
  let pos = skipDNSName(bytes, rdataOffset);
  if (pos < 0 || pos >= rdEnd) return -1;
  pos = skipDNSName(bytes, pos);
  if (pos < 0 || pos + 20 > rdEnd) return -1;
  return rdEnd - 4;
}

function readUint32(bytes, offset) {
  return (((bytes[offset] * 0x100 + bytes[offset + 1]) * 0x100 + bytes[offset + 2]) * 0x100 + bytes[offset + 3]) >>> 0;
}

function patchDNSResponseForAge(responseBuffer, queryID, ageSeconds) {
  const bytes = new Uint8Array(responseBuffer);
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  copy[0] = (queryID >> 8) & 0xff;
  copy[1] = queryID & 0xff;

  if (copy.length < 12 || ageSeconds <= 0) return copy.buffer;

  const qdcount = (copy[4] << 8) | copy[5];
  const ancount = (copy[6] << 8) | copy[7];
  const nscount = (copy[8] << 8) | copy[9];
  const arcount = (copy[10] << 8) | copy[11];

  let offset = 12;
  for (let i = 0; i < qdcount; i++) {
    offset = skipDNSName(copy, offset);
    if (offset < 0 || offset + 4 > copy.length) return copy.buffer;
    offset += 4;
  }

  const counts = [ancount, nscount, arcount];
  for (const count of counts) {
    for (let i = 0; i < count; i++) {
      const rr = readResourceRecord(copy, offset);
      if (!rr) return copy.buffer;
      // OPT (TYPE 41) uses its 32-bit field for extended RCODE/version/flags,
      // not a DNS TTL. Leave it untouched.
      if (rr.type !== 41) {
        const remaining = Math.max(0, rr.ttl - ageSeconds);
        copy[rr.rdataOffset - 6] = (remaining >>> 24) & 0xff;
        copy[rr.rdataOffset - 5] = (remaining >>> 16) & 0xff;
        copy[rr.rdataOffset - 4] = (remaining >>> 8) & 0xff;
        copy[rr.rdataOffset - 3] = remaining & 0xff;
      }
      offset = rr.end;
    }
  }

  return copy.buffer;
}

function makeEdgeCacheRequest(origin, key) {
  return new Request(`${origin}${CONFIG.EDGE_CACHE_PATH}/${key}`, { method: 'GET' });
}

async function getEdgeCache(key, queryID, origin) {
  try {
    const cache = caches.default;
    const cacheKey = makeEdgeCacheRequest(origin, key);
    const hit = await cache.match(cacheKey);
    if (!hit) return null;

    const body = await hit.arrayBuffer();
    const storedHeader = hit.headers.get('x-doh-stored-at');
    const ttlHeader = hit.headers.get('x-doh-ttl');
    const storedAt = Number(storedHeader);
    const ttlSeconds = Number(ttlHeader);

    if (!Number.isFinite(storedAt) || !Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
      return null;
    }

    const ageSeconds = Math.max(0, Math.floor((Date.now() - storedAt) / 1000));
    if (ageSeconds >= ttlSeconds) return null;

    return {
      body,
      storedAt,
      ttlSeconds,
      responseBody: patchDNSResponseForAge(body, queryID, ageSeconds)
    };
  } catch (_) {
    // Cache availability should never break DNS resolution.
    return null;
  }
}

async function putEdgeCache(key, body, ttlSeconds, storedAt, origin) {
  try {
    const cache = caches.default;
    const cacheKey = makeEdgeCacheRequest(origin, key);
    const response = new Response(body, {
      status: 200,
      headers: {
        'content-type': 'application/dns-message',
        'cache-control': `public, s-maxage=${Math.max(1, Math.floor(ttlSeconds))}`,
        'x-doh-stored-at': String(storedAt),
        'x-doh-ttl': String(Math.max(1, Math.floor(ttlSeconds)))
      }
    });
    await cache.put(cacheKey, response);
  } catch (_) {
    // L1 cache and upstream failover remain fully functional if L2 is unavailable.
  }
}

async function allowDNSRequest(ip, env) {
  // Native Workers Rate Limiting binding: low-overhead and shared across isolates
  // within the same Cloudflare location. This is the preferred enforcement path.
  if (env?.DNS_RATE_LIMITER?.limit) {
    try {
      const result = await env.DNS_RATE_LIMITER.limit({ key: ip || 'unknown' });
      return result?.success !== false;
    } catch (_) {
      // Fall back to the local limiter if the binding is absent/misconfigured.
    }
  }

  return localRateLimit(ip || 'unknown');
}

function localRateLimit(ip) {
  const now = Date.now();
  const current = APP_STATE.throttle.get(ip);
  let stats = current || { count: 0, resetAt: now + CONFIG.RATE_LIMIT_WINDOW_MS };

  if (now >= stats.resetAt) {
    stats = { count: 0, resetAt: now + CONFIG.RATE_LIMIT_WINDOW_MS };
  }

  stats.count += 1;
  APP_STATE.throttle.set(ip, stats);

  trimMap(APP_STATE.throttle, CONFIG.MAX_THROTTLE_ENTRIES);
  return stats.count <= CONFIG.RATE_LIMIT_MAX_REQUESTS;
}

function trimMap(map, maxEntries) {
  while (map.size > maxEntries) {
    const oldestKey = map.keys().next().value;
    map.delete(oldestKey);
  }
}

function getClientIP(req) {
  // CF-Connecting-IP is the Cloudflare-provided client address.
  // Do not trust a public client's X-Forwarded-For value.
  return req.headers.get('CF-Connecting-IP') || 'unknown';
}

function getHealthSnapshot() {
  return {
    version: VERSION,
    upstreams: RESOLVER_NODES.map((node) => ({
      url: node.url,
      score: node.score,
      ok: node.ok,
      fail: node.fail,
      timeout: node.timeout,
      ewmaLatencyMs: node.ewmaLatencyMs,
      lastLatencyMs: node.lastLatencyMs,
      lastError: node.lastError
    })),
    cacheEntries: APP_STATE.cache.size,
    inflightEntries: APP_STATE.inflight.size,
    throttleEntries: APP_STATE.throttle.size,
    rateLimit: {
      maxRequests: CONFIG.RATE_LIMIT_MAX_REQUESTS,
      windowSeconds: CONFIG.RATE_LIMIT_WINDOW_MS / 1000,
      preferredBinding: 'DNS_RATE_LIMITER'
    },
    maxSimultaneousUpstreams: 3,
    cache: {
      l1: 'in-memory LRU',
      l2: CONFIG.EDGE_CACHE_ENABLED ? 'Cloudflare Cache API (data-center-local)' : 'disabled',
      localMaxTTLSeconds: CONFIG.LOCAL_CACHE_MAX_TTL_SECONDS,
      edgeMaxTTLSeconds: CONFIG.EDGE_CACHE_MAX_TTL_SECONDS
    }
  };
}

function dnsResponse(body, extraHeaders = {}) {
  return new Response(body, {
    status: 200,
    headers: {
      'content-type': 'application/dns-message',
      'cache-control': 'no-store',
      'vary': 'Accept-Encoding',
      ...extraHeaders
    }
  });
}

function textResponse(text, status = 200, headers = {}) {
  return new Response(text, {
    status,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      ...headers
    }
  });
}

function jsonResponse(data, status = 200, headers = {}) {
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

function sanitizeHeaderValue(value) {
  return String(value).replace(/[\r\n]/g, '').slice(0, 200);
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

function renderUI(host) {
  const safeHost = escapeHtml(host);
  const endpoint = `https://${safeHost}${CONFIG.DNS_PATH}`;

  return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <meta name="theme-color" content="#020617">
    <title>Secure DNS over HTTPS (DoH) Pro</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡️</text></svg>">
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;700;900&family=Vazirmatn:wght@400;700;900&display=swap');
        :root { color-scheme: dark; }
        html { scroll-behavior: smooth; }
        body {
            background: #020617;
            background-image:
                radial-gradient(circle at 15% 0%, rgba(14, 165, 233, 0.10), transparent 45%),
                radial-gradient(circle at 85% 20%, rgba(16, 185, 129, 0.08), transparent 40%),
                linear-gradient(rgba(148, 163, 184, 0.05) 1px, transparent 1px),
                linear-gradient(90deg, rgba(148, 163, 184, 0.05) 1px, transparent 1px);
            background-size: auto, auto, 42px 42px, 42px 42px;
            color: #cbd5e1;
            font-family: 'Inter', 'Vazirmatn', sans-serif;
            overflow-x: hidden;
            padding-top: env(safe-area-inset-top, 0px);
            padding-bottom: env(safe-area-inset-bottom, 0px);
        }
        .cyber-glass { background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(15px); border: 1px solid rgba(0, 243, 255, 0.08); }
        .lang-fa { direction: rtl; font-family: 'Vazirmatn', sans-serif; }
        .nav-active { background: #0ea5e9; color: white !important; border-color: #38bdf8 !important; box-shadow: 0 0 15px rgba(14, 165, 233, 0.3); }
        .panel { display: none; } .panel-active { display: block; animation: fadeInUp 0.3s ease-out; }
        @keyframes fadeInUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        code { color: #22d3ee; font-family: monospace; background: #000; padding: 3px 7px; border-radius: 6px; word-break: break-all; }
        .btn-tab { transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1); border: 1px solid #1e293b; }
        .btn-tab:active { transform: scale(0.95); }
        .no-scrollbar { scrollbar-width: none; -ms-overflow-style: none; }
        .no-scrollbar::-webkit-scrollbar { display: none; }
        /* Mobile-first hero type: never larger than what a small phone can wrap cleanly. */
        .hero-title { font-size: clamp(2.5rem, 9vw, 4.5rem); line-height: 1.05; }
        /* The endpoint is a long string; shrink it before it ever forces horizontal scroll. */
        #linkInp { font-size: clamp(0.7rem, 3vw, 0.95rem); }
        @media (max-width: 480px) {
            #tutorialNav { flex-wrap: nowrap; overflow-x: auto; justify-content: flex-start; scroll-snap-type: x mandatory; padding: 0 4px; }
            #tutorialNav .btn-tab { flex: 0 0 auto; scroll-snap-align: start; white-space: nowrap; }
        }
    </style>
</head>
<body class="p-4 md:p-12">

    <!-- LANGUAGE SWITCHER -->
    <div class="fixed z-50" style="top: calc(1.5rem + env(safe-area-inset-top, 0px)); right: 1.5rem;">
        <button onclick="toggleLangMenu(event)" aria-haspopup="true" aria-expanded="false" id="langBtn" class="cyber-glass px-5 py-3 md:px-6 rounded-2xl flex items-center gap-3 md:gap-4 text-xs font-bold border-cyan-500/20 hover:scale-105 active:scale-95 transition-all shadow-2xl">
            🌐 <span id="currentLang">LANGUAGE</span>
        </button>
        <div id="langMenu" class="hidden absolute right-0 mt-3 cyber-glass p-2 rounded-2xl w-44 shadow-2xl border-slate-800">
            <button onclick="changeLang('en')" class="w-full text-left p-3 hover:bg-sky-600 active:scale-95 rounded-xl text-xs mb-1 transition-all">ENGLISH</button>
            <button onclick="changeLang('fa')" class="w-full text-right p-3 hover:bg-emerald-600 active:scale-95 rounded-xl text-xs mb-1 transition-all">فارسی</button>
            <button onclick="changeLang('zh')" class="w-full text-left p-3 hover:bg-teal-600 active:scale-95 rounded-xl text-xs transition-all">简体中文</button>
        </div>
    </div>

    <div class="max-w-4xl mx-auto">
        <header class="text-center py-16 md:py-24">
            <h1 class="hero-title font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-300 to-emerald-400" id="mainTitle">Secure DNS over HTTPS</h1>
            <p id="subTag" class="mt-8 text-slate-500 font-bold uppercase tracking-[0.2em] md:tracking-[0.3em] text-[10px] md:text-xs px-4">Edge Resolve Network • Intelligent HaGeZi Failover</p>
        </header>

        <section class="cyber-glass rounded-[2rem] md:rounded-[3rem] p-6 md:p-14 mb-10 text-center">
            <div class="mb-6">
                <span class="text-[11px] font-black text-cyan-500 tracking-widest uppercase mb-4 block" id="labelUrl">Endpoint URL</span>
                <input id="linkInp" value="${endpoint}" readonly onclick="this.select()" class="w-full bg-black/40 border border-slate-800 p-4 md:p-5 rounded-2xl text-cyan-300 font-mono text-center outline-none focus:border-cyan-500/50 shadow-inner">
            </div>
            <button onclick="copyURL()" class="w-full md:w-auto bg-cyan-600 hover:bg-cyan-400 text-black font-black px-12 py-5 rounded-2xl transition-all shadow-xl active:scale-95">
                <span id="txtCopy">COPY ENDPOINT</span>
            </button>
        </section>

        <!-- TUTORIAL SECTION -->
        <div class="mb-16">
            <nav id="tutorialNav" class="no-scrollbar flex flex-wrap gap-3 justify-center mb-8">
                <button onclick="tab('chrome', this)" id="btnC" class="btn-tab px-6 py-3 rounded-2xl text-[11px] font-black uppercase text-slate-400 nav-active">Chrome / Brave / Edge</button>
                <button onclick="tab('firefox', this)" id="btnF" class="btn-tab px-6 py-3 rounded-2xl text-[11px] font-black uppercase text-slate-400">Firefox</button>
                <button onclick="tab('mobile', this)" id="btnM" class="btn-tab px-6 py-3 rounded-2xl text-[11px] font-black uppercase text-slate-400">Android / iOS</button>
            </nav>

            <section id="docPanels" class="min-h-[300px]">
                <!-- Chrome/Edge Panel -->
                <div id="chrome" class="panel panel-active cyber-glass p-10 md:p-14 rounded-[3rem]">
                    <h3 class="text-2xl font-black mb-8 text-cyan-100" id="cH">Setup for Chromium Browsers</h3>
                    <div class="space-y-6 text-slate-400 text-sm leading-relaxed" id="cL">
                        <p>1. Open Browser <b>Settings</b> and type "DNS" in the search box.</p>
                        <p>2. Select <b>Security</b> > Scroll to <b>Use Secure DNS</b>.</p>
                        <p>3. Choose <b>"With Custom"</b> provider.</p>
                        <p>4. Paste your Neptune URL from the copy-box above.</p>
                        <p>5. Test by visiting a DNS-restricted website.</p>
                    </div>
                </div>

                <!-- Firefox Panel -->
                <div id="firefox" class="panel cyber-glass p-10 md:p-14 rounded-[3rem]">
                    <h3 class="text-2xl font-black mb-8 text-emerald-100" id="fH">Setup for Firefox</h3>
                    <div class="space-y-6 text-slate-400 text-sm leading-relaxed" id="fL">
                        <p>1. Open Firefox <code>Settings</code> and scroll down to <b>Network Settings</b>.</p>
                        <p>2. Click <b>Settings...</b> and check <b>"Enable DNS over HTTPS"</b> at the bottom.</p>
                        <p>3. Set provider to <b>Custom</b> and paste your unique URL.</p>
                        <p>4. Select <b>"Max Protection"</b> for stronger browser-level DNS privacy.</p>
                    </div>
                </div>

                <!-- Mobile/iOS Panel -->
                <div id="mobile" class="panel cyber-glass p-10 md:p-14 rounded-[3rem]">
                    <h3 class="text-2xl font-black mb-8 text-teal-100" id="mH">Android / iOS Logic</h3>
                    <p class="text-slate-500 text-sm mb-6 italic" id="mD">This resolver is a DoH (HTTPS-based) service, which modern phones handle differently than system-wide settings.</p>
                    <div class="space-y-6 text-slate-400 text-sm" id="mL">
                        <p><b>A) For Mobile Browsers:</b> Open Browser settings (Chrome/Firefox/Edge) on your phone and follow the desktop steps. <b>This is the best and fastest way.</b></p>
                        <p><b>B) For System-wide Apps:</b> We recommend using <b>RethinkDNS</b> or <b>Intra</b> apps. In these apps, set the DNS type to DoH and provide your unique Neptune link.</p>
                    </div>
                </div>
            </section>
        </div>

        <!-- SPECIAL EXPLANATION (Critical Point) -->
        <div class="cyber-glass p-8 md:p-12 rounded-[3.5rem] mb-20 border-sky-900/40 relative">
            <h4 class="text-sky-400 font-black text-base md:text-lg mb-6 flex items-center gap-3">
                ⭐ <span id="whyH">Why ONLY Browser-level DOH? (Crucial Tip)</span>
            </h4>
            <div class="space-y-6 text-[13px] md:text-[14px] text-slate-400 leading-loose" id="whyT">
                <p>Most operating systems (Windows settings, Android "Private DNS", or Apple Profiles) natively expect <b>DNS-over-TLS (DoT)</b> which runs on Port 853. Since this worker is built on <b>Cloudflare Edge (Serverless)</b>, it strictly provides <b>DNS-over-HTTPS (DoH)</b> running on Port 443.</p>
                <p><b>The Issue:</b> You <u>cannot</u> paste an <code>https://</code> link into many native DNS settings. It will usually result in an "Invalid Hostname" error. Systems there expect a simple domain, but this service requires the full path for HTTPS resolution.</p>
                <p><b>The Solution:</b> Browsers (Chrome, Edge, Firefox) have their own independent DoH clients. They are compatible with Port 443 workers and provide browser-level encrypted DNS. DoH encrypts DNS queries between your browser and this endpoint, but it does not hide destination IPs or guarantee bypass on every network.</p>
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
            en: {
                main: 'Secure DNS over HTTPS', sub: 'Edge Resolve Network • Intelligent HaGeZi Failover',
                urlL: 'Endpoint URL', cpT: 'COPY ENDPOINT', copied: 'LINK CAPTURED!', tabC: 'Chrome / Brave / Edge', tabF: 'Firefox', tabM: 'Android / iOS',
                cH: 'Chromium Browser Settings', cL: '<li>1. Open Browser <b>Settings</b> and find <b>Privacy & Security</b>.</li><li>2. Scroll to <b>"Use Secure DNS"</b>.</li><li>3. Select <b>"With Custom"</b>.</li><li>4. Paste your DoH endpoint URL provided above.</li>',
                fH: 'Firefox Network Options', fL: '<li>1. In Firefox <code>Settings</code>, search for "DNS over HTTPS".</li><li>2. Select <b>Custom</b> from the providers dropdown.</li><li>3. Paste the Neptune DoH link and save.</li>',
                mH: 'Mobile Setup Strategy', mD: 'Smartphones often prioritize DoT hostnames in system settings. To use this Worker DoH endpoint:',
                mL: '<li><b>In Browsers:</b> Setting it directly in Chrome or Firefox for Mobile is the easiest path.</li><li><b>For Apps:</b> Use <b>Intra</b> or <b>RethinkDNS</b> apps and set DoH server to this link.</li>',
                whyH: 'Why Browser-Level ONLY? (The Technical Reality)',
                whyT: '<p>Operating systems like Windows/Android often expect <b>DoT (Port 853)</b> or native resolver formats and may not accept a full <code>https://</code> DoH URL. Workers on Cloudflare run on <b>HTTPS (Port 443)</b>.</p><p><b>Result:</b> Modern browsers include their own DoH engine which works well on Port 443. DoH encrypts DNS queries between your browser and this Worker, but it does not hide destination IPs or guarantee bypass on every network.</p>',
                curL: 'ENGLISH'
            },
            fa: {
                main: 'سرویس امن DNS بر روی HTTPS', sub: 'پاسخگویی هوشمند با سه سرور HaGeZi و failover مرحله‌ای',
                urlL: 'آدرس مستقیم سرور شما (DoH)', cpT: 'کپی آدرس هوشمند', copied: 'لینک کپی شد!', tabC: 'خانواده کروم', tabF: 'فایرفاکس', tabM: 'اندروید و آیفون',
                cH: 'تنظیمات در کروم، اج و بریو', cL: '<li>۱. در تنظیمات مرورگر کلمه DNS را جستجو کنید.</li><li>۲. وارد بخش Security شوید و Use Secure DNS را پیدا کنید.</li><li>۳. آن را روی حالت <b>With Custom</b> قرار دهید.</li><li>۴. آدرس کپی شده از بالای این صفحه را در کادر قرار دهید.</li>',
                fH: 'تنظیمات در مرورگر فایرفاکس', fL: '<li>۱. در فایرفاکس وارد Settings شوید و DNS over HTTPS را جستجو کنید.</li><li>۲. آن را روی حالت Custom بگذارید.</li><li>۳. لینک اختصاصی خود را وارد و ذخیره کنید.</li>',
                mH: 'استراتژی راه‌اندازی در موبایل', mD: 'گوشی‌ها معمولاً در تنظیمات سیستمی به دنبال hostname برای DoT هستند؛ برای استفاده از سرویس DoH ما:',
                mL: '<li><b>داخل مرورگر:</b> بهترین راه تنظیم مستقیم در بخش Secure DNS خودِ کروم یا فایرفاکسِ گوشی است.</li><li><b>برای تمام برنامه‌ها:</b> از اپلیکیشن‌های <b>RethinkDNS</b> یا <b>Intra</b> استفاده کنید و لینک DoH را در آن‌ها ست کنید.</li>',
                whyH: 'چرا نمی‌توان در خیلی از تنظیمات سیستمی ست کرد؟',
                whyT: '<p>بسیاری از تنظیمات سیستمی ویندوز یا Private DNS اندروید، معمولاً <b>DoT (پورت ۸۵۳)</b> یا فرمت hostname می‌خواهند و اجازه نمی‌دهند آدرس کامل <code>https://</code> وارد کنید. این Worker روی <b>HTTPS (پورت ۴۴۳)</b> اجرا می‌شود.</p><p><b>راه حل:</b> مرورگرهای مدرن مثل کروم، اج و فایرفاکس موتور داخلی DoH دارند و با این Endpoint سازگارند. DoH درخواست‌های DNS بین مرورگر و این Worker را رمزنگاری می‌کند، اما IP مقصد را مخفی نمی‌کند و تضمین عبور در همه شبکه‌ها نیست.</p>',
                curL: 'فارسی (FA)'
            },
            zh: {
                main: 'Secure DoH 安全加密中心', sub: '基于边缘节点的智能 HaGeZi 故障转移',
                urlL: 'DoH 配置终端', cpT: '复制配置地址', copied: '已复制!', tabC: 'Chromium 引擎', tabF: 'Firefox 火狐', tabM: '安卓与 iOS',
                cH: 'Chromium 浏览器设置', cL: '<li>1. 进入浏览器“设置”，搜索“安全 DNS”。</li><li>2. 将服务提供商设置为“自定义 (Custom)”。</li><li>3. 粘贴本页面的 Neptune 链接，然后重启浏览器生效。</li>',
                fH: '火狐浏览器配置指南', fL: '<li>1. 在火狐“设置”中搜索 DNS over HTTPS。</li><li>2. 选择自定义提供商。</li><li>3. 输入 DoH 服务器地址并确认保存。</li>',
                mH: '移动端解析说明', mD: '移动操作系统通常默认系统级 DoT 格式；若要使用此 DoH 服务器:',
                mL: '<li><b>浏览器设置:</b> 直接在安卓或苹果手机的浏览器（Chrome/Firefox）内按上述桌面步骤配置即可。</li><li><b>全系统生效:</b> 建议安装 <b>RethinkDNS</b> 或 <b>Intra</b> App，并在软件中设置本页面地址。</li>',
                whyH: '为什么通常建议在浏览器配置? (技术架构说明)',
                whyT: '<p>Windows 或安卓系统的 Private DNS 设置项通常需要 <b>DoT / 853 端口</b> 或主机名格式，而不一定接受完整 HTTPS URL。本项目基于 <b>Port 443</b> 的 Cloudflare Worker 环境构建。</p><p><b>建议:</b> 浏览器自带独立 DoH 解析器，可直接使用此 Endpoint。DoH 会加密浏览器与此 Worker 之间的 DNS 查询，但不会隐藏目标 IP，也不能保证在所有网络中绕过限制。</p>',
                curL: '简体中文'
            }
        };

        function toggleLangMenu(evt) {
            evt.stopPropagation();
            const menu = document.getElementById('langMenu');
            const willOpen = menu.classList.contains('hidden');
            menu.classList.toggle('hidden');
            document.getElementById('langBtn').setAttribute('aria-expanded', String(willOpen));
        }

        document.addEventListener('click', (evt) => {
            const menu = document.getElementById('langMenu');
            const btn = document.getElementById('langBtn');
            if (!menu.classList.contains('hidden') && !menu.contains(evt.target) && !btn.contains(evt.target)) {
                menu.classList.add('hidden');
                btn.setAttribute('aria-expanded', 'false');
            }
        });

        function changeLang(c) {
            c = I18N[c] ? c : 'en';
            localStorage.setItem('doc_v6', c);
            const l = I18N[c];
            document.body.classList.toggle('lang-fa', c === 'fa');
            document.documentElement.lang = c;
            document.documentElement.dir = c === 'fa' ? 'rtl' : 'ltr';
            document.getElementById('currentLang').innerText = l.curL;
            document.getElementById('mainTitle').innerText = l.main;
            document.getElementById('subTag').innerText = l.sub;
            document.getElementById('labelUrl').innerText = l.urlL;
            document.getElementById('txtCopy').innerText = l.cpT;
            document.getElementById('btnC').innerText = l.tabC;
            document.getElementById('btnF').innerText = l.tabF;
            document.getElementById('btnM').innerText = l.tabM;
            document.getElementById('cH').innerText = l.cH;
            document.getElementById('cL').innerHTML = l.cL;
            document.getElementById('fH').innerText = l.fH;
            document.getElementById('fL').innerHTML = l.fL;
            document.getElementById('mH').innerText = l.mH;
            document.getElementById('mD').innerText = l.mD;
            document.getElementById('mL').innerHTML = l.mL;
            document.getElementById('whyH').innerText = l.whyH;
            document.getElementById('whyT').innerHTML = l.whyT;
            document.getElementById('langMenu').classList.add('hidden');
            document.getElementById('langBtn').setAttribute('aria-expanded', 'false');
        }

        function tab(id, el) {
            document.querySelectorAll('.panel-active').forEach(p => { p.classList.remove('panel-active'); p.classList.add('panel'); });
            document.querySelectorAll('.btn-tab').forEach(b => b.classList.remove('nav-active'));
            document.getElementById(id).classList.add('panel-active');
            document.getElementById(id).classList.remove('panel');
            el.classList.add('nav-active');
        }

        async function copyURL() {
            const el = document.getElementById('linkInp');
            const lang = localStorage.getItem('doc_v6') || 'en';
            const msg = I18N[lang]?.copied || 'LINK CAPTURED!';

            try {
                await navigator.clipboard.writeText(el.value);
            } catch (_) {
                el.select();
                document.execCommand('copy');
            }

            alert(msg);
        }

        window.onload = () => changeLang(localStorage.getItem('doc_v6') || 'en');
    </script>
</body>
</html>`, {
    status: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'public, max-age=300',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer'
    }
  });
}
