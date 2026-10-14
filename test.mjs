import test, { beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import worker, { __internals } from './Worker.js';
// Module-level state (resolver statistics, L1/L2 caches, throttle/penalty
// maps, in-flight jobs, resolver rotation cursor) is shared between tests in
// this file, so every test starts from a clean slate.
beforeEach(() => { __internals.resetAppState(); });
function makeQuery(name, id = 0x1234, flags = 0x0100) {
  const labels = name === '.' ? [] : name.split('.');
  const bytes = [
    (id >> 8) & 0xff,
    id & 0xff,
    (flags >> 8) & 0xff,
    flags & 0xff,
    0,
    1, 
    0,
    0, 
    0,
    0, 
    0,
    0 
  ];
  for (const label of labels) {
    bytes.push(label.length);
    for (let i = 0; i < label.length; i++) {
      bytes.push(label.charCodeAt(i));
    }
  }
  bytes.push(0); 
  bytes.push(0, 1); 
  bytes.push(0, 1); 
  return new Uint8Array(bytes);
}
let globalRuntimeLock = Promise.resolve();
async function withGlobalRuntimeMocks(fn, { fetch, caches } = {}) {
  const previous = globalRuntimeLock;
  let release;
  globalRuntimeLock = new Promise((resolve) => { release = resolve; });
  await previous;
  const originalFetch = globalThis.fetch;
  const originalCaches = globalThis.caches;
  if (fetch) globalThis.fetch = fetch;
  if (caches) globalThis.caches = caches;
  try {
    return await fn();
  } finally {
    globalThis.fetch = originalFetch;
    if (originalCaches === undefined) delete globalThis.caches;
    else globalThis.caches = originalCaches;
    release();
  }
}
function makeAResponse(query, ttl = 100, rcode = 0) {
  const bytes = Array.from(query);
  bytes[2] = 0x81;
  bytes[3] = 0x80 | (rcode & 0x0f);
  bytes[6] = 0;
  bytes[7] = rcode === 0 ? 1 : 0; 
  if (rcode !== 0) return new Uint8Array(bytes);
  bytes.push(0xc0, 0x0c); 
  bytes.push(0, 1);       
  bytes.push(0, 1);       
  bytes.push((ttl >>> 24) & 0xff);
  bytes.push((ttl >>> 16) & 0xff);
  bytes.push((ttl >>> 8) & 0xff);
  bytes.push(ttl & 0xff);
  bytes.push(0, 4);
  bytes.push(93, 184, 216, 34);
  return new Uint8Array(bytes);
}
test('module exposes default fetch handler', () => {
  assert.equal(typeof worker.fetch, 'function');
});
test('parseDNSQuestion accepts a standard A query', () => {
  const parsed = __internals.parseDNSQuestion(makeQuery('example.com'));
  assert.deepEqual(parsed, { ok: true, id: 0x1234 });
});
test('parseDNSQuestion rejects DNS responses', () => {
  const query = makeQuery('example.com');
  query[2] |= 0x80;
  const parsed = __internals.parseDNSQuestion(query);
  assert.equal(parsed.ok, false);
  assert.match(parsed.error, /got response/);
});
test('parseDNSQuestion rejects non-query opcodes', () => {
  const parsed = __internals.parseDNSQuestion(makeQuery('example.com', 0x1234, 0x0800));
  assert.equal(parsed.ok, false);
  assert.match(parsed.error, /opcode/i);
});
test('makeCacheKey normalizes DNS name case and transaction IDs', async () => {
  const lower = await __internals.makeCacheKey(makeQuery('example.com', 0x1111));
  const upper = await __internals.makeCacheKey(makeQuery('EXAMPLE.COM', 0x2222));
  assert.equal(lower, upper);
  assert.match(lower, /^[0-9a-f]{32}$/);
});
test('decodeBase64Url round-trips a DNS query', () => {
  const query = makeQuery('example.com');
  let binary = '';
  for (const byte of query) binary += String.fromCharCode(byte);
  const encoded = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  const decoded = __internals.decodeBase64Url(encoded);
  assert.deepEqual(Array.from(decoded), Array.from(query));
});
test('decodeBase64Url rejects invalid base64url', () => {
  assert.throws(() => __internals.decodeBase64Url('abc='), /Invalid base64url/);
});
test('validateDNSResponse checks ID, response bit, and question echo', () => {
  const query = makeQuery('example.com');
  const response = makeAResponse(query);
  const validation = __internals.validateDNSResponse(response, 0x1234, query);
  assert.equal(validation.ok, true);
  assert.equal(validation.rcode, 0);
  assert.equal(validation.truncated, false);
  assert.equal(__internals.validateDNSResponse(response, 0x9999).ok, false);
  // The response bit check survives when called without the original query.
  assert.equal(__internals.validateDNSResponse(response, 0x1234).ok, true);
});
test('getDNSCacheTTL reads minimum answer TTL', () => {
  const response = makeAResponse(makeQuery('example.com'), 100);
  assert.equal(__internals.getDNSCacheTTL(response), 100);
});
test('patchDNSResponseForAge rewrites ID and decrements TTL', () => {
  const query = makeQuery('example.com');
  const response = makeAResponse(query, 100);
  const patched = new Uint8Array(__internals.patchDNSResponseForAge(response, 0xabcd, 40));
  assert.equal(patched[0], 0xab);
  assert.equal(patched[1], 0xcd);
  const ttlOffset = 29 + 2 + 2 + 2;
  const remaining = (
    (patched[ttlOffset] << 24)
    | (patched[ttlOffset + 1] << 16)
    | (patched[ttlOffset + 2] << 8)
    | patched[ttlOffset + 3]
  ) >>> 0;
  assert.equal(remaining, 60);
});
test('fetch rejects POST with a near-match content type', async () => {
  const req = new Request('https://workers.example/dns-query', {
    method: 'POST',
    headers: { 'content-type': 'xapplication/dns-message' },
    body: new Uint8Array([0, 1])
  });
  const res = await worker.fetch(req, {}, {});
  assert.equal(res.status, 415);
});
test('fetch rejects GET requests without the dns parameter before cache access', async () => {
  const req = new Request('https://workers.example/dns-query');
  const res = await worker.fetch(req, {}, {});
  assert.equal(res.status, 400);
});
test('health endpoint returns current hardening configuration', async () => {
  const req = new Request('https://workers.example/health');
  const res = await worker.fetch(req, {}, {});
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.maxUpstreamDNSMessageBytes, 65535);
  assert.equal(body.rateLimit.invalidBindingFallback, 'per-isolate local limiter');
  assert.equal(body.maxSimultaneousUpstreams, 3);
});
test('coalesced upstream failures return controlled 502 responses', async () => {
  await withGlobalRuntimeMocks(async () => {
    const makeRequest = () => new Request('https://workers.example/dns-query', {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message' },
      body: makeQuery('example.com')
    });
    const first = worker.fetch(makeRequest(), {}, {});
    await new Promise((resolve) => setTimeout(resolve, 5));
    const second = worker.fetch(makeRequest(), {}, {});
    const [firstRes, secondRes] = await Promise.all([first, second]);
    assert.equal(firstRes.status, 502);
    assert.equal(secondRes.status, 502);
  }, {
    fetch: async () => { throw new Error('upstream down'); },
    caches: {
      default: {
        match: async () => null,
        put: async () => {}
      }
    }
  });
});
test('streamed oversized client POST is rejected at 413', async () => {
  const chunks = [new Uint8Array(3000), new Uint8Array(1500)];
  const stream = new ReadableStream({
    pull(controller) {
      if (chunks.length) controller.enqueue(chunks.shift());
      else controller.close();
    }
  });
  const req = new Request('https://workers.example/dns-query', {
    method: 'POST',
    headers: { 'content-type': 'application/dns-message' },
    body: stream,
    duplex: 'half'
  });
  const res = await worker.fetch(req, {}, {});
  assert.equal(res.status, 413);
});
test('oversized upstream response with declared length is rejected', async () => {
  await withGlobalRuntimeMocks(async () => {
    const req = new Request('https://workers.example/dns-query', {
      method: 'POST',
      headers: {
        'content-type': 'application/dns-message',
        'cf-connecting-ip': 'declared-size-test'
      },
      body: makeQuery('example.com')
    });
    const res = await worker.fetch(req, {}, {});
    assert.equal(res.status, 502);
    assert.equal(res.headers.get('x-upstreams'), '3');
  }, {
    fetch: async () => new Response(new Uint8Array([0]), {
      status: 200,
      headers: {
        'content-type': 'application/dns-message',
        'content-length': String(65536)
      }
    })
  });
});
test('oversized upstream response with unknown length is stream-rejected', async () => {
  await withGlobalRuntimeMocks(async () => {
    const req = new Request('https://workers.example/dns-query', {
      method: 'POST',
      headers: {
        'content-type': 'application/dns-message',
        'cf-connecting-ip': 'stream-size-test'
      },
      body: makeQuery('stream-limit.example')
    });
    const res = await worker.fetch(req, {}, {});
    assert.equal(res.status, 502);
    assert.equal(res.headers.get('x-upstreams'), '3');
  }, {
    fetch: async () => {
      const stream = new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array(200000));
          controller.enqueue(new Uint8Array(100000));
          controller.close();
        }
      });
      return new Response(stream, {
        status: 200,
        headers: { 'content-type': 'application/dns-message' }
      });
    }
  });
});
test('malformed native rate limiter falls back to local limiter', async () => {
  const env = {
    DNS_RATE_LIMITER: {
      limit: async () => ({ success: 'not-a-boolean' })
    }
  };
  const ip = 'rate-fallback-test';
  for (let i = 0; i < 100; i++) {
    const req = new Request('https://workers.example/dns-query', {
      headers: { 'cf-connecting-ip': ip }
    });
    const res = await worker.fetch(req, env, {});
    assert.equal(res.status, 400);
  }
  const req = new Request('https://workers.example/dns-query', {
    headers: { 'cf-connecting-ip': ip }
  });
  const res = await worker.fetch(req, env, {});
  assert.equal(res.status, 429);
});
test('coalesced degraded results propagate x-dns-degraded', async () => {
  let releaseUpstream;
  const upstreamGate = new Promise((resolve) => { releaseUpstream = resolve; });
  await withGlobalRuntimeMocks(async () => {
    const makeRequest = () => new Request('https://workers.example/dns-query', {
      method: 'POST',
      headers: {
        'content-type': 'application/dns-message',
        'cf-connecting-ip': 'degraded-test'
      },
      body: makeQuery('degraded.example')
    });
    const first = worker.fetch(makeRequest(), {}, {});
    await new Promise((resolve) => setImmediate(resolve));
    const second = worker.fetch(makeRequest(), {}, {});
    await new Promise((resolve) => setImmediate(resolve));
    releaseUpstream();
    const [firstRes, secondRes] = await Promise.all([first, second]);
    assert.equal(firstRes.status, 200);
    assert.equal(secondRes.status, 200);
    assert.equal(firstRes.headers.get('x-dns-degraded'), '1');
    assert.equal(secondRes.headers.get('x-dns-degraded'), '1');
  }, {
    fetch: async () => {
      await upstreamGate;
      return new Response(makeAResponse(makeQuery('degraded.example'), 60, 2), {
        status: 200,
        headers: { 'content-type': 'application/dns-message' }
      });
    },
    caches: {
      default: {
        match: async () => null,
        put: async () => {}
      }
    }
  });
});
test('health reports version and sweep interval', async () => {
  const res = await worker.fetch(new Request('https://workers.example/health'), {}, {});
  const body = await res.json();
  assert.equal(body.version, '0.3.2');
  assert.equal(body.stateSweepIntervalSeconds, 60);
});
test('DNS name wire length boundary is enforced', () => {
  const validName = [
    'a'.repeat(63),
    'b'.repeat(63),
    'c'.repeat(63),
    'd'.repeat(61)
  ].join('.');
  const invalidName = [
    'a'.repeat(63),
    'b'.repeat(63),
    'c'.repeat(63),
    'd'.repeat(62)
  ].join('.');
  assert.equal(__internals.parseDNSQuestion(makeQuery(validName)).ok, true);
  assert.equal(__internals.parseDNSQuestion(makeQuery(invalidName)).ok, false);
});
test('compression pointers in a query question name are rejected', () => {
  const query = makeQuery('example.com');
  const compressed = new Uint8Array([
    ...query.slice(0, 12),
    0xc0, 0x0c,
    0, 1,
    0, 1
  ]);
  assert.equal(__internals.parseDNSQuestion(compressed).ok, false);
  const trailingPointer = new Uint8Array([
    ...query.slice(0, 12),
    3, 119, 119, 119,
    0xc0, 0x0c,
    0, 1,
    0, 1
  ]);
  assert.equal(__internals.parseDNSQuestion(trailingPointer).ok, false);
});
test('a query with a compressed question name gets 400 and never reaches upstream', async () => {
  let upstreamCalls = 0;
  await withGlobalRuntimeMocks(async () => {
    const query = makeQuery('example.com');
    const compressed = new Uint8Array([...query.slice(0, 12), 0xc0, 0x0c, 0, 1, 0, 1]);
    const before = (await (await worker.fetch(new Request('https://workers.example/health'), {}, {})).json())
      .upstreams.map((u) => u.score);
    const res = await worker.fetch(new Request('https://workers.example/dns-query', {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message', 'cf-connecting-ip': 'pointer-test' },
      body: compressed
    }), {}, {});
    assert.equal(res.status, 400);
    assert.equal(upstreamCalls, 0);
    const after = (await (await worker.fetch(new Request('https://workers.example/health'), {}, {})).json())
      .upstreams.map((u) => u.score);
    assert.deepEqual(after, before);
  }, {
    fetch: async () => { upstreamCalls += 1; throw new Error('upstream must not be used'); },
    caches: cacheMock()
  });
});
function makeNxdomainWithSOA(query, ttl, minimum) {
  const bytes = Array.from(query);
  bytes[2] = 0x81;
  bytes[3] = 0x83; 
  bytes[9] = 1; 
  const u32 = (v) => [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff];
  const rdata = [
    2, 110, 115, 0, 
    2, 104, 109, 0, 
    ...u32(1), ...u32(3600), ...u32(600), ...u32(86400), ...u32(minimum)
  ];
  bytes.push(0xc0, 0x0c, 0, 6, 0, 1, ...u32(ttl), 0, rdata.length, ...rdata);
  return new Uint8Array(bytes);
}
function cacheMock() {
  return { default: { match: async () => null, put: async () => {} } };
}
async function postQuery(name, ip, ctx = {}) {
  return worker.fetch(new Request('https://workers.example/dns-query', {
    method: 'POST',
    headers: { 'content-type': 'application/dns-message', 'cf-connecting-ip': ip },
    body: makeQuery(name)
  }), {}, ctx);
}
test('getDNSCacheTTL does not cache NXDOMAIN without an SOA record', () => {
  const response = makeAResponse(makeQuery('nosoa.example'), 100, 3);
  assert.equal(__internals.getDNSCacheTTL(response), 0);
});
test('getDNSCacheTTL uses min(SOA TTL, SOA MINIMUM) for NXDOMAIN', () => {
  const query = makeQuery('soa.example');
  assert.equal(__internals.getDNSCacheTTL(makeNxdomainWithSOA(query, 300, 45)), 45);
  assert.equal(__internals.getDNSCacheTTL(makeNxdomainWithSOA(query, 20, 900)), 20);
});
test('getDNSCacheTTL never caches SERVFAIL', () => {
  assert.equal(__internals.getDNSCacheTTL(makeAResponse(makeQuery('sf.example'), 60, 2)), 0);
});
test('patchDNSResponseForAge restores the querying client QNAME case', () => {
  const cached = makeAResponse(makeQuery('example.com'), 100);
  const mixed = makeQuery('ExAmPlE.CoM', 0x4321);
  const patched = new Uint8Array(__internals.patchDNSResponseForAge(cached, 0x4321, 0, mixed));
  assert.deepEqual(Array.from(patched.slice(12, 29)), Array.from(mixed.slice(12, 29)));
  const other = makeQuery('different.org', 0x4321);
  const untouched = new Uint8Array(__internals.patchDNSResponseForAge(cached, 0x4321, 0, other));
  assert.deepEqual(Array.from(untouched.slice(12, 29)), Array.from(cached.slice(12, 29)));
});
test('cache hit echoes client case and tolerates a ctx without waitUntil', async () => {
  await withGlobalRuntimeMocks(async () => {
    const first = await postQuery('casehit.example', 'case-test');
    assert.equal(first.status, 200);
    assert.equal(first.headers.get('x-cache'), 'MISS');
    const mixedReq = new Request('https://workers.example/dns-query', {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message', 'cf-connecting-ip': 'case-test' },
      body: makeQuery('CaseHit.Example')
    });
    const second = await worker.fetch(mixedReq, {}, {});
    assert.equal(second.headers.get('x-cache'), 'L1-HIT');
    const body = new Uint8Array(await second.arrayBuffer());
    assert.deepEqual(Array.from(body.slice(12, 28)), Array.from(makeQuery('CaseHit.Example').slice(12, 28)));
  }, {
    fetch: async (_url, init) => new Response(makeAResponse(init.body, 100), {
      status: 200,
      headers: { 'content-type': 'application/dns-message' }
    }),
    caches: cacheMock()
  });
});
test('SERVFAIL is not force-cached in L1', async () => {
  let releaseUpstream;
  const gate = new Promise((resolve) => { releaseUpstream = resolve; });
  await withGlobalRuntimeMocks(async () => {
    const first = postQuery('servfail-nocache.example', 'sf-test');
    await new Promise((resolve) => setImmediate(resolve));
    releaseUpstream();
    const firstRes = await first;
    assert.equal(firstRes.status, 200);
    assert.equal(firstRes.headers.get('x-dns-degraded'), '1');
    const third = await postQuery('servfail-nocache.example', 'sf-test');
    assert.equal(third.headers.get('x-cache'), 'MISS');
  }, {
    fetch: async (_url, init) => {
      await gate;
      return new Response(makeAResponse(init.body, 60, 2), {
        status: 200,
        headers: { 'content-type': 'application/dns-message' }
      });
    },
    caches: cacheMock()
  });
});
test('requests joining a failed in-flight resolution get a 502, not an exception', async () => {
  let releaseUpstream;
  const gate = new Promise((resolve) => { releaseUpstream = resolve; });
  await withGlobalRuntimeMocks(async () => {
    const first = postQuery('joinfail.example', 'join-fail');
    // Wait until the leader has registered its inflight entry (its digest is
    // async, so a bare setImmediate is not enough on every Node version).
    const joinKey = await __internals.makeCacheKey(makeQuery('joinfail.example'));
    for (let i = 0; i < 100 && !__internals.hasInflight(joinKey); i++) {
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    assert.equal(__internals.hasInflight(joinKey), true);
    const second = postQuery('joinfail.example', 'join-fail');
    // Give the joiner time to finish its async parse/digest and attach to the
    // leader's inflight job before releasing the upstream gate (a single
    // setImmediate is not enough on every Node version).
    await new Promise((resolve) => setTimeout(resolve, 25));
    releaseUpstream();
    const results = await Promise.allSettled([first, second]);
    for (const r of results) {
      assert.equal(r.status, 'fulfilled');
      assert.equal(r.value.status, 502);
    }
    assert.equal(results[0].value.headers.get('x-upstreams'), '3');
    assert.equal(results[1].value.headers.get('x-upstreams'), '0');
  }, {
    fetch: async () => { await gate; throw new Error('upstream down'); },
    caches: cacheMock()
  });
});
test('L2 hit older than the L1 cap is still promoted to L1', async () => {
  const query = makeQuery('promote.example');
  const key = await __internals.makeCacheKey(query);
  const body = makeAResponse(query, 3600).buffer;
  const storedAt = Date.now() - 400_000; 
  await withGlobalRuntimeMocks(async () => {
    const first = await postQuery('promote.example', 'promote-test');
    assert.equal(first.headers.get('x-cache'), 'L2-HIT');
    const second = await postQuery('promote.example', 'promote-test');
    assert.equal(second.headers.get('x-cache'), 'L1-HIT');
  }, {
    fetch: async () => { throw new Error('upstream must not be used'); },
    caches: {
      default: {
        match: async (req) => (req.url.endsWith(key)
          ? new Response(body, {
            headers: { 'x-doh-stored-at': String(storedAt), 'x-doh-ttl': '3600' }
          })
          : null),
        put: async () => {}
      }
    }
  });
});
test('getDNSCacheTTL treats TTLs with the MSB set as zero (RFC 2181)', () => {
  const response = makeAResponse(makeQuery('hugettl.example'), 0x80000000);
  assert.equal(__internals.getDNSCacheTTL(response), 0);
});
test('getDNSCacheTTL clamps long TTLs to the L2 maximum', () => {
  const response = makeAResponse(makeQuery('longttl.example'), 0x7fffffff);
  assert.equal(__internals.getDNSCacheTTL(response), __internals.CONFIG.EDGE_CACHE_MAX_TTL_SECONDS);
});
test('hedge delays stay inside their configured bounds', () => {
  const { CONFIG, getHedgeDelay } = __internals;
  assert.equal(getHedgeDelay({ ewmaLatencyMs: 1 }), CONFIG.HEDGE_MIN_MS);
  assert.equal(getHedgeDelay({ ewmaLatencyMs: 10_000 }), CONFIG.HEDGE_MAX_MS);
  assert.equal(getHedgeDelay({ ewmaLatencyMs: null }), 180); 
});
test('selectRacers puts the healthiest resolver first and keeps all three', () => {
  const mk = (order, score, ewmaLatencyMs = null) => ({ url: `u${order}`, order, score, ewmaLatencyMs });
  const racers = __internals.selectRacers([mk(0, 40), mk(1, 100, 50), mk(2, 70)]);
  assert.equal(racers.length, 3);
  assert.equal(racers[0].order, 1); 
  assert.deepEqual(racers.map((n) => n.order).sort(), [0, 1, 2]);
});
test('localRateLimit allows 100 requests per window then blocks', () => {
  const ip = 'local-limit-unit-test';
  for (let i = 0; i < __internals.CONFIG.RATE_LIMIT_MAX_REQUESTS; i++) {
    assert.equal(__internals.localRateLimit(ip), true);
  }
  assert.equal(__internals.localRateLimit(ip), false);
});
test('localRateLimit survives a table-overflow flood without a fresh window', () => {
  const busy = 'lru-busy-client';
  for (let i = 0; i < __internals.CONFIG.RATE_LIMIT_MAX_REQUESTS; i++) {
    assert.equal(__internals.localRateLimit(busy), true);
  }
  assert.equal(__internals.localRateLimit(busy), false);
  const max = __internals.CONFIG.MAX_THROTTLE_ENTRIES;
  for (let i = 0; i < max + 10; i++) {
    __internals.localRateLimit(`lru-filler-${i}`);
  }
  // The flood evicted `busy` from the main table, but its window survives in
  // the penalty map: it must NOT get a fresh 100-request window.
  assert.equal(__internals.localRateLimit(busy), false);
});
test('L1 is re-checked after an L2 miss so a concurrently filled entry avoids an upstream call', async () => {
  let upstreamCalls = 0;
  let l2Calls = 0;
  let releaseL2;
  const l2Gate = new Promise((resolve) => { releaseL2 = resolve; });
  await withGlobalRuntimeMocks(async () => {
    const query = makeQuery('l1recheck.example');
    const slow = postQuery('l1recheck.example', 'l1-recheck');
    await new Promise((resolve) => setImmediate(resolve));
    const key = await __internals.makeCacheKey(query);
    __internals.setCache(key, makeAResponse(query, 100).buffer, 100);
    releaseL2();
    const res = await slow;
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-cache'), 'L1-HIT');
    assert.equal(upstreamCalls, 0);
  }, {
    fetch: async () => { upstreamCalls += 1; throw new Error('upstream must not be used'); },
    caches: {
      default: {
        match: async () => { l2Calls += 1; if (l2Calls === 1) await l2Gate; return null; },
        put: async () => {}
      }
    }
  });
});
test('hedging: first resolver fails, second answers, third is never contacted', async () => {
  const calls = [];
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('hedge-two.example', 'hedge-two');
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-upstreams'), '2');
    assert.equal(calls.length, 2);
  }, {
    fetch: async (url, init) => {
      calls.push(url);
      if (calls.length === 1) throw new Error('boom');
      return new Response(makeAResponse(init.body, 60), {
        status: 200,
        headers: { 'content-type': 'application/dns-message' }
      });
    },
    caches: cacheMock()
  });
});
test('hedging: all three resolvers failing returns 502 with x-upstreams 3', async () => {
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('hedge-three.example', 'hedge-three');
    assert.equal(res.status, 502);
    assert.equal(res.headers.get('x-upstreams'), '3');
  }, {
    fetch: async () => { throw new Error('down'); },
    caches: cacheMock()
  });
});
test('hedging: the slower attempt is aborted once another resolver answers and is not penalised', async () => {
  const signals = [];
  await withGlobalRuntimeMocks(async () => {
    const before = (await (await worker.fetch(new Request('https://workers.example/health'), {}, {})).json())
      .upstreams.reduce((sum, u) => sum + u.timeout + u.fail, 0);
    const res = await postQuery('hedge-abort.example', 'hedge-abort');
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-upstreams'), '2');
    assert.equal(signals[0].aborted, true);
    const after = (await (await worker.fetch(new Request('https://workers.example/health'), {}, {})).json())
      .upstreams.reduce((sum, u) => sum + u.timeout + u.fail, 0);
    assert.equal(after, before);
  }, {
    fetch: (url, init) => {
      signals.push(init.signal);
      if (signals.length === 1) {
        return new Promise((_resolve, reject) => {
          init.signal.addEventListener('abort', () => reject(new Error('aborted')));
        });
      }
      return Promise.resolve(new Response(makeAResponse(init.body, 60), {
        status: 200,
        headers: { 'content-type': 'application/dns-message' }
      }));
    },
    caches: cacheMock()
  });
});
test('concurrent cold-cache misses coalesce into a single upstream job', async () => {
  let calls = 0;
  let releaseUpstream;
  const gate = new Promise((resolve) => { releaseUpstream = resolve; });
  await withGlobalRuntimeMocks(async () => {
    const pending = Promise.all([
      postQuery('race.example', 'race-1'),
      postQuery('race.example', 'race-2'),
      postQuery('race.example', 'race-3')
    ]);
    // Hold the upstream open until all three requests arrived, so the two
    // joiners must attach to the leader's inflight job (an instant mock would
    // let them observe the filled L1 instead).
    for (let i = 0; i < 100 && calls === 0; i++) {
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    assert.equal(calls, 1);
    releaseUpstream();
    const results = await pending;
    for (const res of results) assert.equal(res.status, 200);
    const tags = results.map((r) => r.headers.get('x-cache'));
    assert.equal(tags.filter((tag) => tag === 'MISS').length, 1);
    assert.equal(tags.filter((tag) => tag === 'COALESCED').length, 2);
    // One coalesced job with a healthy first resolver = exactly one upstream
    // call, not three jobs x up-to-three attempts each.
    assert.equal(calls, 1);
  }, {
    fetch: async (_url, init) => {
      calls += 1;
      await gate;
      return new Response(makeAResponse(init.body, 60), {
        status: 200,
        headers: { 'content-type': 'application/dns-message' }
      });
    },
    caches: cacheMock()
  });
});
test('getDNSCacheTTL treats SOA MINIMUM with the MSB set as zero (RFC 2181)', () => {
  const query = makeQuery('soamsb.example');
  assert.equal(__internals.getDNSCacheTTL(makeNxdomainWithSOA(query, 300, 0x80000000)), 0);
});
function makeAWithAuthority(query, answerTtl, authorityTtl) {
  const bytes = Array.from(makeAResponse(query, answerTtl));
  bytes[9] = 1; // nscount = 1 (an NS record in the authority section)
  const u32 = (v) => [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff];
  bytes.push(0xc0, 0x0c, 0, 2, 0, 1, ...u32(authorityTtl), 0, 0);
  return new Uint8Array(bytes);
}
test('getDNSCacheTTL uses the minimum TTL across all sections for positive answers', () => {
  const response = makeAWithAuthority(makeQuery('multi.example'), 100, 30);
  assert.equal(__internals.getDNSCacheTTL(response), 30);
});
test('corrupt L2 entries are purged instead of being re-read forever', async () => {
  const query = makeQuery('corrupt.example');
  const key = await __internals.makeCacheKey(query);
  let matches = 0;
  let deletes = 0;
  await withGlobalRuntimeMocks(async () => {
    await postQuery('corrupt.example', 'corrupt-test');
    await postQuery('corrupt.example', 'corrupt-test');
    assert.equal(matches, 2);
    assert.equal(deletes, 1);
  }, {
    fetch: async () => { throw new Error('upstream must not be used'); },
    caches: {
      default: {
        match: async (req) => {
          if (!req.url.endsWith(key)) return null;
          matches += 1;
          if (matches > 1) return null;
          // Body is fine but the bookkeeping headers are missing: corrupt.
          return new Response(makeAResponse(query, 100).buffer);
        },
        delete: async () => { deletes += 1; },
        put: async () => {}
      }
    }
  });
});
test('dashboard forbids framing and is served with a restrictive CSP', async () => {
  const res = await worker.fetch(new Request('https://workers.example/'), {}, {});
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.match(await res.text(), /v0\.3\.2/);
});
test('validateDNSResponse rejects QNAME, QTYPE and QCLASS mismatches', () => {
  const query = makeQuery('mismatch.example');
  const wrongName = makeAResponse(makeQuery('other.example'));
  assert.match(__internals.validateDNSResponse(wrongName, 0x1234, query).error, /QNAME/);
  const wrongType = Array.from(makeAResponse(query));
  wrongType[query.length - 4] = 0;
  wrongType[query.length - 3] = 2; // QTYPE A (1) -> NS (2)
  assert.match(
    __internals.validateDNSResponse(new Uint8Array(wrongType), 0x1234, query).error,
    /QTYPE/
  );
  const wrongClass = Array.from(makeAResponse(query));
  wrongClass[query.length - 2] = 0;
  wrongClass[query.length - 1] = 3; // QCLASS IN (1) -> CH (3)
  assert.match(
    __internals.validateDNSResponse(new Uint8Array(wrongClass), 0x1234, query).error,
    /QCLASS/
  );
});
test('validateDNSResponse accepts case-reordered QNAME echoes (0x20 randomization)', () => {
  const query = makeQuery('MiXeD.example');
  const response = makeAResponse(makeQuery('mixed.EXAMPLE'));
  const validation = __internals.validateDNSResponse(response, 0x1234, query);
  assert.equal(validation.ok, true);
  assert.equal(validation.rcode, 0);
});
test('validateDNSResponse rejects success answers without a question but accepts error ones', () => {
  const query = makeQuery('noq.example');
  const full = makeAResponse(query);
  const stripQuestion = (src) => {
    const out = new Uint8Array(12 + (src.length - query.length));
    out.set(src.slice(0, 12), 0);
    out[4] = 0;
    out[5] = 0; // qdcount = 0
    out.set(src.slice(query.length), 12);
    return out;
  };
  assert.equal(__internals.validateDNSResponse(stripQuestion(full), 0x1234, query).ok, false);
  const servfail = makeAResponse(query, 60, 2);
  assert.equal(__internals.validateDNSResponse(stripQuestion(servfail), 0x1234, query).ok, true);
});
test('validateDNSResponse rejects successful answers with truncated record sections', () => {
  const query = makeQuery('truncated.example');
  const response = Array.from(makeAResponse(query, 100));
  response.pop(); // cut the final rdata byte so the record overruns the message
  const validation = __internals.validateDNSResponse(new Uint8Array(response), 0x1234, query);
  assert.equal(validation.ok, false);
  assert.match(validation.error, /resource record/i);
});
test('upstream responses echoing a different question are rejected and fail over', async () => {
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('honest.example', 'q-mismatch-test');
    assert.equal(res.status, 502);
    assert.equal(res.headers.get('x-upstreams'), '3');
  }, {
    fetch: async () => new Response(makeAResponse(makeQuery('evil.example')), {
      status: 200,
      headers: { 'content-type': 'application/dns-message' }
    }),
    caches: cacheMock()
  });
});
test('toExactArrayBuffer preserves a subarray view of a larger buffer', () => {
  const backing = new Uint8Array(64);
  const query = makeQuery('slice-view.example');
  backing.set(query, 17); // non-zero offset inside a larger backing buffer
  const buffer = __internals.toExactArrayBuffer(backing.subarray(17, 17 + query.length));
  assert.equal(buffer.byteLength, query.length);
  assert.deepEqual(Array.from(new Uint8Array(buffer)), Array.from(query));
  // A full-span view keeps its original buffer without copying.
  const whole = new Uint8Array(8);
  assert.equal(__internals.toExactArrayBuffer(whole), whole.buffer);
});
test('readCappedBody keeps exact boundaries when a stream yields a single subarray chunk', async () => {
  const backing = new Uint8Array(256);
  const query = makeQuery('chunk-slice.example');
  backing.set(query, 40);
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(backing.subarray(40, 40 + query.length));
      controller.close();
    }
  });
  const chunk = await __internals.readCappedBody({ body: stream }, 4096, 'too large');
  const exact = __internals.toExactArrayBuffer(chunk);
  assert.equal(exact.byteLength, query.length);
  assert.deepEqual(Array.from(new Uint8Array(exact)), Array.from(query));
});
test('upstream fetch pins the redirect policy to error', async () => {
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('redirect-policy.example', 'redirect-test');
    assert.equal(res.status, 502);
  }, {
    fetch: async (_url, init) => {
      assert.equal(init.redirect, 'error');
      throw new Error('unreachable upstream');
    },
    caches: cacheMock()
  });
});
test('L2 entries with a corrupt DNS body are purged and re-resolved upstream', async () => {
  const key = await __internals.makeCacheKey(makeQuery('l2-corrupt.example'));
  let purged = false;
  let upstreamCalls = 0;
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('l2-corrupt.example', 'l2-corrupt-test');
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-cache'), 'MISS');
    assert.equal(upstreamCalls, 1);
    assert.equal(purged, true);
  }, {
    fetch: async (_url, init) => {
      upstreamCalls += 1;
      return new Response(makeAResponse(init.body, 60), {
        status: 200,
        headers: { 'content-type': 'application/dns-message' }
      });
    },
    caches: {
      default: {
        match: async (req) => (req.url.endsWith(key)
          ? new Response(new Uint8Array([1, 2, 3, 4, 5, 6]), {
            headers: { 'x-doh-stored-at': String(Date.now()), 'x-doh-ttl': '300' }
          })
          : null),
        put: async () => {},
        delete: async () => { purged = true; }
      }
    }
  });
});
test('L2 entries echoing a different question are purged and re-resolved', async () => {
  const key = await __internals.makeCacheKey(makeQuery('l2-mismatch.example'));
  let purged = false;
  const foreign = makeAResponse(makeQuery('foreign.example'), 60).buffer;
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('l2-mismatch.example', 'l2-mismatch-test');
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-cache'), 'MISS');
    assert.equal(purged, true);
  }, {
    fetch: async (_url, init) => new Response(makeAResponse(init.body, 60), {
      status: 200,
      headers: { 'content-type': 'application/dns-message' }
    }),
    caches: {
      default: {
        match: async (req) => (req.url.endsWith(key)
          ? new Response(foreign, {
            headers: { 'x-doh-stored-at': String(Date.now()), 'x-doh-ttl': '300' }
          })
          : null),
        put: async () => {},
        delete: async () => { purged = true; }
      }
    }
  });
});
test('getDNSCacheTTL ignores SOA records with trailing or missing bytes', () => {
  const query = makeQuery('soa-trailing.example');
  const q = query.length;
  const valid = makeNxdomainWithSOA(query, 300, 45);
  assert.equal(__internals.getDNSCacheTTL(valid), 45);
  const padded = new Uint8Array(valid.length + 2);
  padded.set(valid, 0);
  padded[q + 11] = 30; // rdlength 28 -> 30, leaving 2 trailing garbage bytes
  assert.equal(__internals.getDNSCacheTTL(padded), 0);
  const short = Array.from(valid);
  short[q + 11] = 26; // rdlength cuts into the MINIMUM field itself
  assert.equal(__internals.getDNSCacheTTL(new Uint8Array(short)), 0);
});
function makeTruncatedResponse(query, rcode = 0) {
  const bytes = Array.from(query);
  bytes[2] = 0x81;
  bytes[3] = 0x80 | 0x02 | (rcode & 0x0f); // QR | TC | RCODE
  return new Uint8Array(bytes);
}
test('truncated upstream answers lose the race to complete ones', async () => {
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('truncate.example', 'truncate-test');
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-dns-degraded'), null);
    const body = new Uint8Array(await res.arrayBuffer());
    assert.equal(body[3] & 0x02, 0); // the winning answer has TC clear
  }, {
    fetch: async (url) => {
      if (url.includes('root.hagezi')) {
        await new Promise((resolve) => setTimeout(resolve, 30));
        return new Response(makeTruncatedResponse(makeQuery('truncate.example')), {
          status: 200,
          headers: { 'content-type': 'application/dns-message' }
        });
      }
      return new Response(makeAResponse(makeQuery('truncate.example'), 60), {
        status: 200,
        headers: { 'content-type': 'application/dns-message' }
      });
    },
    caches: cacheMock()
  });
});
test('all-truncated upstreams return a degraded answer without caching it', async () => {
  await withGlobalRuntimeMocks(async () => {
    const first = await postQuery('truncate-all.example', 'truncate-all-test');
    assert.equal(first.status, 200);
    assert.equal(first.headers.get('x-dns-degraded'), '1');
    const second = await postQuery('truncate-all.example', 'truncate-all-test');
    assert.equal(second.headers.get('x-cache'), 'MISS');
  }, {
    fetch: async (_url, init) => new Response(makeTruncatedResponse(init.body), {
      status: 200,
      headers: { 'content-type': 'application/dns-message' }
    }),
    caches: cacheMock()
  });
});

// ---- Regression tests: L2 refresh TTLs, query and response validation ----
function readAnswerTTL(bytes, queryLength) {
  // makeAResponse: [query][c0 0c][type][class][ttl x4][rdlen][rdata]
  const o = queryLength + 6;
  return ((bytes[o] << 24) | (bytes[o + 1] << 16) | (bytes[o + 2] << 8) | bytes[o + 3]) >>> 0;
}
function withOPT(query, { arcount = 1, truncateBy = 0, extra = [] } = {}) {
  const opt = [0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]; // root, OPT, 4096, rdlen 0
  const out = Array.from(query).concat(opt.slice(0, opt.length - truncateBy), extra);
  out[11] = arcount;
  return new Uint8Array(out);
}
test('an L2 hit serves age-adjusted TTLs and does not rewrite the edge entry', async () => {
  const query = makeQuery('l2-no-rewrite.example');
  const key = await __internals.makeCacheKey(query);
  const storedAt = Date.now() - 100_000; // 100 seconds ago
  let puts = 0;
  await withGlobalRuntimeMocks(async () => {
    const ctx = { waitUntil: (promise) => promise };
    const res = await postQuery('l2-no-rewrite.example', 'l2-no-rewrite', ctx);
    assert.equal(res.headers.get('x-cache'), 'L2-HIT');
    const served = readAnswerTTL(new Uint8Array(await res.arrayBuffer()), query.length);
    assert.ok(served <= 3500 && served >= 3498, `served TTL ${served}`);
    assert.equal(puts, 0);
  }, {
    fetch: async () => { throw new Error('upstream must not be used'); },
    caches: {
      default: {
        match: async (req) => (req.url.endsWith(key)
          ? new Response(makeAResponse(query, 3600).buffer, {
            headers: { 'x-doh-stored-at': String(storedAt), 'x-doh-ttl': '3600' }
          })
          : null),
        put: async () => { puts += 1; }
      }
    }
  });
});
test('a throwing ctx.waitUntil does not break a cache miss', async () => {
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('bad-waituntil.example', 'bad-waituntil', {
      waitUntil() { throw new Error('cannot schedule'); }
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-cache'), 'MISS');
  }, {
    fetch: async (_url, init) => new Response(makeAResponse(init.body, 60), {
      status: 200,
      headers: { 'content-type': 'application/dns-message' }
    }),
    caches: cacheMock()
  });
});
test('patchDNSResponseForAge ages the SOA MINIMUM of negative answers', () => {
  const query = makeQuery('soa-age.example');
  const q = query.length;
  const response = makeNxdomainWithSOA(query, 300, 45);
  const aged = new Uint8Array(__internals.patchDNSResponseForAge(response, 0x1234, 10));
  const u32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
  assert.equal(u32(aged, q + 6), 290); // SOA TTL
  assert.equal(u32(aged, q + 36), 35); // SOA MINIMUM
  // Ageing past the lifetime clamps both at zero rather than wrapping.
  const expired = new Uint8Array(__internals.patchDNSResponseForAge(response, 0x1234, 1000));
  assert.equal(u32(expired, q + 6), 0);
  assert.equal(u32(expired, q + 36), 0);
  // The source buffer is never modified.
  assert.equal(u32(response, q + 36), 45);
});
test('patchDNSResponseForAge accepts ArrayBuffer and Uint8Array input without mutating it', () => {
  const query = makeQuery('copy.example');
  const view = makeAResponse(query, 100);
  const snapshot = Array.from(view);
  const fromView = new Uint8Array(__internals.patchDNSResponseForAge(view, 0x0a0b, 30));
  const fromBuffer = new Uint8Array(__internals.patchDNSResponseForAge(view.buffer, 0x0a0b, 30));
  assert.deepEqual(Array.from(fromView), Array.from(fromBuffer));
  assert.equal(readAnswerTTL(fromView, query.length), 70);
  assert.deepEqual(Array.from(view), snapshot);
});
test('parseDNSQuestion accepts a valid EDNS OPT query', () => {
  assert.equal(__internals.parseDNSQuestion(withOPT(makeQuery('edns.example'))).ok, true);
});
test('parseDNSQuestion rejects an ARCOUNT larger than the records present', () => {
  const parsed = __internals.parseDNSQuestion(withOPT(makeQuery('edns.example'), { arcount: 2 }));
  assert.equal(parsed.ok, false);
});
test('parseDNSQuestion rejects an ARCOUNT of 0 with additional bytes present', () => {
  const parsed = __internals.parseDNSQuestion(withOPT(makeQuery('edns.example'), { arcount: 0 }));
  assert.equal(parsed.ok, false);
  assert.match(parsed.error, /trailing/);
});
test('parseDNSQuestion rejects a truncated OPT record', () => {
  const parsed = __internals.parseDNSQuestion(withOPT(makeQuery('edns.example'), { truncateBy: 3 }));
  assert.equal(parsed.ok, false);
  assert.match(parsed.error, /additional/i);
});
test('parseDNSQuestion rejects trailing data, with or without EDNS', () => {
  const plain = Uint8Array.from([...makeQuery('trail.example'), 1, 2, 3]);
  assert.match(__internals.parseDNSQuestion(plain).error, /trailing/);
  const edns = withOPT(makeQuery('trail.example'), { extra: [9, 9] });
  assert.equal(__internals.parseDNSQuestion(edns).ok, false);
});
test('parseDNSQuestion rejects multiple OPT records', () => {
  const q = withOPT(makeQuery('two-opt.example'));
  const doubled = Uint8Array.from([...q, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
  doubled[11] = 2;
  assert.equal(__internals.parseDNSQuestion(doubled).ok, false);
});
test('malformed queries are rejected with 400 before any upstream request', async () => {
  let fetched = 0;
  await withGlobalRuntimeMocks(async () => {
    const res = await worker.fetch(new Request('https://workers.example/dns-query', {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message', 'cf-connecting-ip': 'bad-q' },
      body: Uint8Array.from([...makeQuery('bad.example'), 7, 7])
    }), {}, {});
    assert.equal(res.status, 400);
    assert.equal(fetched, 0);
  }, { fetch: async () => { fetched += 1; throw new Error('no'); }, caches: cacheMock() });
});
test('validateDNSResponse rejects more than one question', () => {
  const query = makeQuery('multi.example');
  const response = Array.from(makeAResponse(query));
  response[5] = 2;
  assert.match(__internals.validateDNSResponse(Uint8Array.from(response), 0x1234, query).error, /questions/);
});
test('validateDNSResponse rejects trailing bytes', () => {
  const query = makeQuery('trail.example');
  const response = Uint8Array.from([...makeAResponse(query), 0, 0]);
  const result = __internals.validateDNSResponse(response, 0x1234, query);
  assert.equal(result.ok, false);
  assert.match(result.error, /trailing/);
  assert.equal(__internals.validateDNSMessage(response).ok, false);
});
test('validateDNSResponse rejects invalid compression pointer targets', () => {
  const query = makeQuery('ptr.example');
  for (const target of [0x0000, 0x0005, query.length + 20, query.length]) {
    const response = Array.from(makeAResponse(query));
    response[query.length] = 0xc0 | (target >> 8);
    response[query.length + 1] = target & 0xff;
    assert.equal(__internals.validateDNSResponse(Uint8Array.from(response), 0x1234, query).ok, false,
      `pointer to ${target} must be rejected`);
  }
  // A self-referencing / forward pointer is also invalid.
  const loop = Array.from(makeAResponse(query));
  loop[query.length] = 0xc0;
  loop[query.length + 1] = query.length;
  assert.equal(__internals.validateDNSResponse(Uint8Array.from(loop), 0x1234, query).ok, false);
});
test('validateDNSResponse still accepts a pointer to the question name', () => {
  const query = makeQuery('ptr-ok.example');
  assert.equal(__internals.validateDNSResponse(makeAResponse(query), 0x1234, query).ok, true);
});
test('malformed error responses are rejected, well-formed ones stay accepted', () => {
  const query = makeQuery('err.example');
  const good = makeAResponse(query, 0, 2); // SERVFAIL with question
  assert.equal(__internals.validateDNSResponse(good, 0x1234, query).ok, true);
  // SERVFAIL that omits the question entirely is still allowed.
  const noQuestion = Uint8Array.from([0x12, 0x34, 0x81, 0x82, 0, 0, 0, 0, 0, 0, 0, 0]);
  assert.equal(__internals.validateDNSResponse(noQuestion, 0x1234, query).ok, true);
  // Declared record that is not present.
  const missing = Array.from(good);
  missing[7] = 1;
  assert.match(__internals.validateDNSResponse(Uint8Array.from(missing), 0x1234, query).error, /Truncated/);
  // Undeclared trailing bytes after an error response.
  const trailing = Uint8Array.from([...good, 1, 2, 3]);
  assert.match(__internals.validateDNSResponse(trailing, 0x1234, query).error, /trailing/);
});
