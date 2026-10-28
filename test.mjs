import test, { beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import worker, { __internals } from './worker-harness.mjs';
const { version: PACKAGE_VERSION } = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));
// Module-level state (resolver statistics, L1/L2 caches, throttle/penalty
// maps, in-flight jobs, resolver rotation cursor) is shared between tests in
// this file, so every test starts from a clean slate.
beforeEach(() => { __internals.resetAppState(); });
// Big-endian 32-bit value as four bytes (record TTLs, SOA fields).
function u32(v) { return [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]; }
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
  // The Worker queries upstreams with RFC 8484 GET; mocks receive the decoded
  // DNS query as init.body so they can build matching answers.
  if (fetch) globalThis.fetch = (url, init = {}) => fetch(url, { ...init, originalBody: init.body, body: queryFromURL(url) });
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
function queryFromURL(url) {
  const dns = new URL(url).searchParams.get('dns');
  return dns ? __internals.decodeBase64Url(dns) : undefined;
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
function makeRecordResponse(query, type, rdata, ttl = 60) {
  const bytes = Array.from(query);
  bytes[2] = 0x81;
  bytes[3] = 0x80;
  bytes[6] = 0;
  bytes[7] = 1;
  bytes[8] = bytes[9] = bytes[10] = bytes[11] = 0;
  bytes.push(
    0xc0, 0x0c,
    (type >> 8) & 0xff, type & 0xff,
    0, 1,
    ...u32(ttl),
    (rdata.length >> 8) & 0xff, rdata.length & 0xff,
    ...rdata
  );
  return Uint8Array.from(bytes);
}
test('module exposes default fetch handler', () => {
  assert.equal(typeof worker.fetch, 'function');
});
test('parseDNSQuestion accepts a standard A query', () => {
  const parsed = __internals.parseDNSQuestion(makeQuery('example.com'));
  assert.deepEqual(parsed, { ok: true, id: 0x1234, questionEnd: 25 });
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
test('validateDNSResponse rejects malformed common RDATA layouts', () => {
  const query = makeQuery('rdata.example');
  const malformed = [
    makeRecordResponse(query, 1, [93, 184, 216]), // A must contain exactly 4 bytes.
    makeRecordResponse(query, 28, new Array(15).fill(0)), // AAAA must contain exactly 16 bytes.
    makeRecordResponse(query, 5, [0xff]), // CNAME RDATA must be one complete domain name.
    makeRecordResponse(query, 15, [0, 10]), // MX preference without an exchange name.
    makeRecordResponse(query, 16, [2, 65]), // TXT character string overruns RDATA.
    makeRecordResponse(query, 33, [0, 0, 0, 0, 0, 0, 0xc0, 0x0c]), // SRV target must not be compressed.
    makeRecordResponse(query, 46, [...new Array(18).fill(0), 0xc0, 0x0c, 1]), // RRSIG signer must not be compressed.
    makeRecordResponse(query, 257, [0, 4, 3, 105]) // CAA tag length overruns RDATA.
  ];
  for (const response of malformed) {
    const result = __internals.validateDNSResponse(response, 0x1234, query);
    assert.equal(result.ok, false, `malformed type-specific RDATA accepted: ${Array.from(response).join(',')}`);
    assert.match(result.error, /RDATA/);
  }
});
test('validateDNSResponse accepts valid compressed legacy name RDATA', () => {
  const query = makeQuery('cname-target.example');
  const cname = makeRecordResponse(query, 5, [0xc0, 0x0c]);
  assert.equal(__internals.validateDNSResponse(cname, 0x1234, query).ok, true);
  const mx = makeRecordResponse(query, 15, [0, 10, 0xc0, 0x0c]);
  assert.equal(__internals.validateDNSResponse(mx, 0x1234, query).ok, true);
  const sig = makeRecordResponse(query, 24, [...new Array(18).fill(0), 0xc0, 0x0c, 1]);
  assert.equal(__internals.validateDNSResponse(sig, 0x1234, query).ok, true);
  const px = makeRecordResponse(query, 26, [0, 10, 0xc0, 0x0c, 0xc0, 0x0c]);
  assert.equal(__internals.validateDNSResponse(px, 0x1234, query).ok, true);
  const nxt = makeRecordResponse(query, 30, [0xc0, 0x0c, 1]);
  assert.equal(__internals.validateDNSResponse(nxt, 0x1234, query).ok, true);
});
test('validateDNSResponse rejects compressed targets in DNAME, KX, LP and IPSECKEY', () => {
  const query = makeQuery('compression-rules.example');
  const malformed = [
    makeRecordResponse(query, 23, [0xc0, 0x0c]), // NSAP-PTR is not compression-enabled.
    makeRecordResponse(query, 36, [0, 10, 0xc0, 0x0c]), // KX exchange name cannot be compressed.
    makeRecordResponse(query, 39, [0xc0, 0x0c]), // DNAME target names cannot be compressed.
    makeRecordResponse(query, 45, [10, 3, 2, 0xc0, 0x0c, 1]), // IPSECKEY gateway cannot be compressed.
    makeRecordResponse(query, 58, [0xc0, 0x0c, 0xc0, 0x0c]), // TALINK names cannot be compressed.
    makeRecordResponse(query, 107, [0, 10, 0xc0, 0x0c]) // LP FQDN cannot be compressed.
  ];
  for (const response of malformed) {
    const result = __internals.validateDNSResponse(response, 0x1234, query);
    assert.equal(result.ok, false, `compressed target accepted: ${Array.from(response).join(',')}`);
    assert.match(result.error, /RDATA/);
  }
  const validIPSECKEY = makeRecordResponse(query, 45, [10, 3, 2, 0, 1, 2, 3]);
  assert.equal(__internals.validateDNSResponse(validIPSECKEY, 0x1234, query).ok, true);
});
test('validateDNSResponse validates CAA tags, SPF strings and defined SVCB parameters', () => {
  const query = makeQuery('typed-parameters.example');
  const malformed = [
    makeRecordResponse(query, 257, [0, 1, 1, 0]), // CAA tags must be ASCII alphanumeric.
    makeRecordResponse(query, 65, [0, 1, 0, 0, 3, 0, 1, 80]), // port must be exactly two octets.
    makeRecordResponse(query, 65, [0, 1, 0, 0, 0, 0, 2, 0, 3]), // mandatory key 3 is absent.
    makeRecordResponse(query, 65, [0, 1, 0, 0, 2, 0, 1, 65]) // no-default-alpn is an empty flag.
  ];
  for (const response of malformed) {
    const result = __internals.validateDNSResponse(response, 0x1234, query);
    assert.equal(result.ok, false, `malformed typed parameter accepted: ${Array.from(response).join(',')}`);
    assert.match(result.error, /RDATA/);
  }
  const validCAA = makeRecordResponse(query, 257, [0, 3, 105, 115, 115, 101, 120]); // tag=iss, value=ex
  assert.equal(__internals.validateDNSResponse(validCAA, 0x1234, query).ok, true);
  const validSPF = makeRecordResponse(query, 99, [2, 118, 49]); // one TXT-style string: "v1"
  assert.equal(__internals.validateDNSResponse(validSPF, 0x1234, query).ok, true);
  const validSVCB = makeRecordResponse(query, 64, [0, 1, 0, 0, 3, 0, 2, 1, 187]); // target ., port=443
  assert.equal(__internals.validateDNSResponse(validSVCB, 0x1234, query).ok, true);
});
test('malformed upstream A RDATA triggers failover and is never cached', async () => {
  let calls = 0;
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('bad-a-rdata.example', 'bad-a-rdata');
    assert.equal(res.status, 502);
    assert.equal(res.headers.get('x-upstreams'), '3');
    assert.equal(__internals.getHealthSnapshot().cacheEntries, 0);
    assert.equal(calls, 3);
  }, {
    fetch: async (_url, init) => {
      calls += 1;
      return new Response(makeRecordResponse(init.body, 1, [93, 184, 216]), {
        status: 200,
        headers: { 'content-type': 'application/dns-message' }
      });
    },
    caches: cacheMock()
  });
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
  assert.equal(body.version, PACKAGE_VERSION);
  assert.equal(body.stateSweepIntervalSeconds, 60);
});
test('coalesced upstream failures return controlled 502 responses', async () => {
  let calls = 0;
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  await withGlobalRuntimeMocks(async () => {
    const first = postQuery('coalesced-fail.example', 'coalesce-fail-1');
    await waitForInflight('coalesced-fail.example');
    const second = postQuery('coalesced-fail.example', 'coalesce-fail-2');
    await waitForJoiners('coalesced-fail.example', 1);
    release();
    const [firstRes, secondRes] = await Promise.all([first, second]);
    assert.equal(firstRes.status, 502);
    assert.equal(secondRes.status, 502);
    assert.equal(firstRes.headers.get('x-upstreams'), '3');
    assert.equal(secondRes.headers.get('x-upstreams'), '0');
    assert.equal(calls, 3);
  }, {
    fetch: async () => { calls += 1; await gate; throw new Error('upstream down'); },
    caches: cacheMock()
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
  for (let i = 0; i < __internals.CONFIG.RATE_LIMIT_MAX_REQUESTS; i++) {
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
  let calls = 0;
  let releaseUpstream;
  const upstreamGate = new Promise((resolve) => { releaseUpstream = resolve; });
  await withGlobalRuntimeMocks(async () => {
    const first = postQuery('degraded.example', 'degraded-1');
    await waitForInflight('degraded.example');
    const second = postQuery('degraded.example', 'degraded-2');
    await waitForJoiners('degraded.example', 1);
    releaseUpstream();
    const [firstRes, secondRes] = await Promise.all([first, second]);
    assert.equal(firstRes.status, 200);
    assert.equal(secondRes.status, 200);
    assert.equal(secondRes.headers.get('x-cache'), 'COALESCED');
    assert.equal(firstRes.headers.get('x-dns-degraded'), '1');
    assert.equal(secondRes.headers.get('x-dns-degraded'), '1');
    assert.equal(calls, 3);
  }, {
    fetch: async (_url, init) => {
      calls += 1;
      await upstreamGate;
      return new Response(makeAResponse(init.body, 60, 2), {
        status: 200,
        headers: { 'content-type': 'application/dns-message' }
      });
    },
    caches: cacheMock()
  });
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
  const rdata = [
    2, 110, 115, 0,
    2, 104, 109, 0,
    ...u32(1), ...u32(3600), ...u32(600), ...u32(86400), ...u32(minimum)
  ];
  bytes.push(0xc0, 0x0c, 0, 6, 0, 1, ...u32(ttl), 0, rdata.length, ...rdata);
  return new Uint8Array(bytes);
}
async function waitUntilTrue(check) {
  for (let i = 0; i < 500 && !check(); i++) {
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  assert.equal(check(), true);
}
async function waitForInflight(name) {
  await waitUntilTrue(() => __internals.hasInflight(makeQuery(name)));
}
// Deterministic: waits until `count` requests have attached to the leader.
async function waitForJoiners(name, count) {
  await waitUntilTrue(() => __internals.joinerCount(makeQuery(name)) >= count);
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
  await withGlobalRuntimeMocks(async () => {
    const first = await postQuery('servfail-nocache.example', 'sf-test');
    assert.equal(first.status, 200);
    assert.equal(first.headers.get('x-dns-degraded'), '1');
    const second = await postQuery('servfail-nocache.example', 'sf-test');
    assert.equal(second.headers.get('x-cache'), 'MISS');
  }, {
    fetch: async (_url, init) => {
      return new Response(makeAResponse(init.body, 60, 2), {
        status: 200,
        headers: { 'content-type': 'application/dns-message' }
      });
    },
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
test('localRateLimit allows RATE_LIMIT_MAX_REQUESTS per window then blocks', () => {
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
  // the penalty map: it must NOT get a fresh request window.
  assert.equal(__internals.localRateLimit(busy), false);
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
test('hedging: the slower attempt is aborted and not counted as a failure or timeout', async () => {
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
  // Valid NS RDATA: a compressed name pointing to the question's QNAME.
  bytes.push(0xc0, 0x0c, 0, 2, 0, 1, ...u32(authorityTtl), 0, 2, 0xc0, 0x0c);
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
  assert.ok((await res.text()).includes(`v${PACKAGE_VERSION}`));
});
test('dashboard CSS keeps escaped utility selectors', async () => {
  const html = await (await worker.fetch(new Request('https://workers.example/'), {}, {})).text();
  // Unescaped forms such as ".md:p-12{" or ".min-h-[300px]{" are invalid CSS
  // and silently dropped by browsers.
  for (const selector of ['.md\\:p-12{', '.min-h-\\[300px\\]{', '.bg-black\\/40{', '.hover\\:bg-cyan-400:hover{',
    '.rounded-\\[3\\.5rem\\]{', '.tracking-\\[0\\.3em\\]{']) {
    assert.ok(html.includes(selector), `missing ${selector}`);
  }
  assert.doesNotMatch(html, /\.(?:md|hover|active|focus):[a-z]/);
  assert.doesNotMatch(html, /\.[a-z0-9-]+-\[[^\]]+\]\{/);
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
test('questionless extended-RCODE errors are checked after parsing OPT', () => {
  // Base RCODE 0 with an OPT extended RCODE of 1 is BADVERS (effective RCODE 16).
  const response = Uint8Array.from([
    0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 1,
    0, 0, 41, 0x10, 0, 1, 0, 0, 0, 0, 0
  ]);
  const result = __internals.validateDNSResponse(response, 0x1234, makeQuery('extended-rcode.example'));
  assert.equal(result.ok, true);
  assert.equal(result.rcode, 16);
  assert.equal(result.metadata.ttl, 0);
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
test('upstream queries use RFC 8484 GET with the client query as base64url', async () => {
  const seen = [];
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('get-upstream.example', 'get-upstream');
    assert.equal(res.status, 200);
    assert.equal(seen[0].method, 'GET');
    assert.equal(seen[0].hasBody, false);
    assert.deepEqual(Array.from(queryFromURL(seen[0].url)), Array.from(makeQuery('get-upstream.example')));
  }, {
    fetch: async (url, init) => {
      seen.push({ url, method: init.method, hasBody: init.originalBody != null });
      return new Response(makeAResponse(init.body, 60), { headers: { 'content-type': 'application/dns-message' } });
    },
    caches: cacheMock()
  });
});
test('upstream redirects are never followed and count as a resolver failure', async () => {
  const seen = [];
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('redirect-policy.example', 'redirect-test');
    assert.equal(res.status, 502);
    assert.equal(res.headers.get('x-upstreams'), '3');
    // Workers only implements 'follow' and 'manual'; 'error' throws at runtime.
    assert.deepEqual([...new Set(seen)], ['manual']);
    assert.ok(__internals.getHealthSnapshot().upstreams.every((u) => /HTTP 307/.test(u.lastError)));
  }, {
    fetch: async (_url, init) => {
      seen.push(init.redirect);
      return new Response(null, { status: 307, headers: { location: 'https://elsewhere.example/dns-query' } });
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
test('validateDNSResponse rejects malformed SOA RDATA even on positive answers', () => {
  const query = makeQuery('bad-soa-positive.example');
  const response = Array.from(makeAResponse(query, 60));
  response[9] = 1; // One authority record.
  // SOA must contain two domain names and five 32-bit fields; a root byte
  // alone is not valid SOA RDATA even though the enclosing RR is complete.
  response.push(0xc0, 0x0c, 0, 6, 0, 1, ...u32(300), 0, 1, 0);
  const result = __internals.validateDNSResponse(Uint8Array.from(response), 0x1234, query);
  assert.equal(result.ok, false);
  assert.match(result.error, /SOA/);
});
function makeTruncatedResponse(query, rcode = 0) {
  const bytes = Array.from(query);
  bytes[2] = 0x83; // QR + TC (TC is in the high flag byte) + RD
  bytes[3] = 0x80 | (rcode & 0x0f);
  return new Uint8Array(bytes);
}
test('truncated upstream answers lose the race to complete ones', async () => {
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('truncate.example', 'truncate-test');
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-dns-degraded'), null);
    const body = new Uint8Array(await res.arrayBuffer());
    assert.equal(body[2] & 0x02, 0); // the winning answer has TC clear
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

// ---- Regression tests: cache TTLs, query and response validation ----
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
test('patchDNSResponseForAge ages SOA TTL without modifying signed MINIMUM', () => {
  const query = makeQuery('soa-age.example');
  const q = query.length;
  const response = makeNxdomainWithSOA(query, 300, 45);
  const aged = new Uint8Array(__internals.patchDNSResponseForAge(response, 0x1234, 10));
  const readU32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
  assert.equal(readU32(aged, q + 6), 35); // SOA TTL
  assert.equal(readU32(aged, q + 36), 45); // SOA MINIMUM
  // Ageing past the lifetime clamps both at zero rather than wrapping.
  const expired = new Uint8Array(__internals.patchDNSResponseForAge(response, 0x1234, 1000));
  assert.equal(readU32(expired, q + 6), 0);
  assert.equal(readU32(expired, q + 36), 45);
  // The source buffer is never modified.
  assert.equal(readU32(response, q + 36), 45);
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
test('validateDNSResponse requires EDNS options to tile OPT RDATA exactly', () => {
  const query = makeQuery('response-edns-framing.example');
  const valid = Array.from(makeAResponse(query, 60));
  const withOpt = (rdata) => {
    const response = valid.slice();
    response[11] = 1; // One additional OPT record.
    response.push(
      0, 0, 41, 0x10, 0, // Root owner, OPT type, UDP payload size 4096.
      0, 0, 0, 0, // Extended RCODE, version, flags.
      (rdata.length >> 8) & 0xff, rdata.length & 0xff,
      ...rdata
    );
    return Uint8Array.from(response);
  };
  assert.equal(__internals.validateDNSResponse(withOpt([0, 12, 0, 2, 0, 0]), 0x1234, query).ok, true);
  for (const bad of [
    [0, 12, 0], // Partial option header.
    [0, 12, 0, 2, 0], // Option data is one byte short.
    [0, 12, 0, 223, 1, 2, 3, 4], // Declared option data overruns RDATA.
    [0, 10, 0, 1, 7, 0, 12] // Valid option followed by a partial header.
  ]) {
    const result = __internals.validateDNSResponse(withOpt(bad), 0x1234, query);
    assert.equal(result.ok, false, `RDATA ${bad} must be rejected`);
    assert.match(result.error, /EDNS options/);
  }
});
test('malformed upstream EDNS options trigger failover and are never cached', async () => {
  let calls = 0;
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('bad-upstream-edns.example', 'bad-upstream-edns');
    assert.equal(res.status, 502);
    assert.equal(res.headers.get('x-upstreams'), '3');
    assert.equal(__internals.getHealthSnapshot().cacheEntries, 0);
    assert.equal(calls, 3);
  }, {
    fetch: async (_url, init) => {
      calls += 1;
      const response = Array.from(makeAResponse(init.body, 60));
      response[11] = 1; // One additional OPT record.
      response.push(0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 8, 0, 12, 0, 223, 1, 2, 3, 4);
      return new Response(Uint8Array.from(response), {
        status: 200,
        headers: { 'content-type': 'application/dns-message' }
      });
    },
    caches: cacheMock()
  });
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
test('validateDNSResponse rejects compression targets that overlap their pointer source', () => {
  // The label byte at offset 19 is 63. If followed as a name pointer target,
  // its label body crosses the answer pointer and ends on the RR type's zero
  // byte. A target name must be entirely encoded before the pointer.
  const longLabel = makeQuery(`${'a'.repeat(6)}?${'a'.repeat(56)}`);
  const overlappingLabel = makeAResponse(longLabel);
  overlappingLabel[longLabel.length + 1] = 19;
  assert.equal(__internals.validateDNSResponse(overlappingLabel, 0x1234, longLabel).ok, false);

  // This second case places a pointer in the last byte of an earlier RR's
  // RDATA. Its second byte would be the first byte of the current owner-name
  // pointer, which is not a complete prior encoding.
  const query = makeQuery('pointer-overlap.example');
  const response = Array.from(query);
  response[2] = 0x81;
  response[3] = 0x80;
  response[7] = 2; // Two answer records.
  const rdata = new Uint8Array(4020);
  const firstRecordStart = query.length;
  const secondOwnerOffset = firstRecordStart + 12 + rdata.length;
  const target = secondOwnerOffset - 1;
  rdata[rdata.length - 1] = 0xc0 | ((target >> 8) & 0x3f);
  response.push(
    0xc0, 0x0c, 0, 16, 0, 1, ...u32(60),
    (rdata.length >> 8) & 0xff, rdata.length & 0xff,
    ...rdata,
    0xc0 | ((target >> 8) & 0x3f), target & 0xff,
    0, 1, 0, 1, ...u32(60), 0, 4, 93, 184, 216, 34
  );
  assert.equal(__internals.validateDNSResponse(Uint8Array.from(response), 0x1234, query).ok, false);
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

// ---- 0.4.0 regressions and previously uncovered paths ----
function makeCnameNodata(query) {
  const b = Array.from(query);
  b[2] = 0x81; b[3] = 0x80; b[7] = 1; b[9] = 1;
  b.push(0xc0, 0x0c, 0, 5, 0, 1, ...u32(3600), 0, 2, 0xc0, 0x0c);
  const rd = [2, 110, 115, 0, 2, 104, 109, 0, ...u32(1), ...u32(1), ...u32(1), ...u32(1), ...u32(60)];
  b.push(0xc0, 0x0c, 0, 6, 0, 1, ...u32(3600), 0, rd.length, ...rd);
  return Uint8Array.from(b);
}
test('CNAME to NODATA answers respect SOA MINIMUM', () => {
  assert.equal(__internals.getDNSCacheTTL(makeCnameNodata(makeQuery('cname-nodata.example'))), 60);
});
test('IPv6 rate-limit keys use the /64 prefix', () => {
  assert.equal(__internals.rateLimitKey('2001:db8:1:2:3:4:5:6'), '2001:db8:1:2::/64');
  assert.equal(__internals.rateLimitKey('2001:db8:1:2::9'), '2001:db8:1:2::/64');
  const max = __internals.CONFIG.RATE_LIMIT_MAX_REQUESTS;
  for (let i = 0; i < max; i++) assert.equal(__internals.localRateLimit(`2001:db8:9:9::${i.toString(16)}`), true);
  assert.equal(__internals.localRateLimit('2001:db8:9:9:ffff::1'), false);
});
test('EDNS padding does not split cache keys', async () => {
  const query = makeQuery('pad.example');
  assert.equal(await __internals.makeCacheKey(withPadding(query, 1)), await __internals.makeCacheKey(withPadding(query, 20)));
});
test('fallback priority: truncated NOERROR > truncated NXDOMAIN > SERVFAIL > other RCODEs', () => {
  const p = (rcode) => __internals.fallbackPriority({ rcode });
  assert.ok(p(0) > p(3));
  assert.ok(p(3) > p(2));
  assert.ok(p(2) > p(5));
  assert.equal(p(5), p(4));
});
test('resolver scores recover over time to the starting score', () => {
  const node = { score: 80, lastScoreUpdateAt: 1 };
  __internals.recoverScore(node, 1 + 5 * __internals.CONFIG.SCORE_RECOVERY_INTERVAL_MS);
  assert.equal(node.score, 85);
});
test('all-SERVFAIL domains do not penalise resolvers', async () => {
  await withGlobalRuntimeMocks(async () => {
    await postQuery('all-servfail.example', 'all-sf');
    const health = __internals.getHealthSnapshot();
    assert.deepEqual(health.upstreams.map((u) => u.score), [100, 100, 100]);
  }, {
    fetch: async (_url, init) => new Response(makeAResponse(init.body, 60, 2), { headers: { 'content-type': 'application/dns-message' } }),
    caches: cacheMock()
  });
});
test('L1 respects the byte budget', () => {
  const { CONFIG } = __internals;
  const old = CONFIG.MAX_CACHE_BYTES;
  CONFIG.MAX_CACHE_BYTES = 70;
  try {
    __internals.setCache('a', makeAResponse(makeQuery('a.example')).buffer, 10);
    __internals.setCache('b', makeAResponse(makeQuery('b.example')).buffer, 10);
    assert.equal(__internals.getHealthSnapshot().cacheEntries, 1);
  } finally { CONFIG.MAX_CACHE_BYTES = old; }
});
test('method, GET size and content-length guards return precise errors', async () => {
  assert.equal((await worker.fetch(new Request('https://workers.example/dns-query', { method: 'PUT' }), {}, {})).status, 405);
  assert.equal((await worker.fetch(new Request(`https://workers.example/dns-query?dns=${'A'.repeat(5463)}`), {}, {})).status, 413);
  const req = new Request('https://workers.example/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message', 'content-length': '4097' }, body: makeQuery('cl.example') });
  assert.equal((await worker.fetch(req, {}, {})).status, 413);
});
test('upstream timeouts are recorded', async () => {
  const old = __internals.CONFIG.UPSTREAM_TIMEOUT_MS;
  __internals.CONFIG.UPSTREAM_TIMEOUT_MS = 5;
  // Node unrefs AbortSignal.timeout timers; keep the test process alive.
  const keepAlive = setInterval(() => {}, 1000);
  try {
    await withGlobalRuntimeMocks(async () => {
      assert.equal((await postQuery('timeout.example', 'timeout')).status, 502);
      assert.ok(__internals.getHealthSnapshot().upstreams.some((u) => u.timeout > 0));
    }, { fetch: (_url, init) => new Promise((_resolve, reject) => init.signal.addEventListener('abort', () => reject(init.signal.reason))), caches: cacheMock() });
  } finally {
    clearInterval(keepAlive);
    __internals.CONFIG.UPSTREAM_TIMEOUT_MS = old;
  }
});
test('expired L2 and expired L1 entries are discarded', async () => {
  const query = makeQuery('expired.example');
  const key = __internals.localKeyOf(query);
  let deleted = 0;
  __internals.setCache(key, makeAResponse(query).buffer, 1, Date.now() - 2000);
  const originalNow = Date.now;
  Date.now = () => originalNow() + 1001;
  try {
    await withGlobalRuntimeMocks(async () => {
      assert.equal((await postQuery('expired.example', 'expired')).headers.get('x-cache'), 'MISS');
      assert.equal(deleted, 1);
    }, {
      fetch: async (_url, init) => new Response(makeAResponse(init.body), { headers: { 'content-type': 'application/dns-message' } }),
      caches: { default: { match: async () => new Response(makeAResponse(query).buffer, { headers: { 'x-doh-stored-at': String(originalNow() - 2000), 'x-doh-ttl': '1' } }), delete: async () => { deleted += 1; }, put: async () => {} } }
    });
  } finally { Date.now = originalNow; }
});
test('native limiter exceptions fall back locally', async () => {
  const env = { DNS_RATE_LIMITER: { limit: async () => { throw new Error('binding down'); } } };
  const res = await worker.fetch(new Request('https://workers.example/dns-query', { headers: { 'cf-connecting-ip': 'native-throw' } }), env, {});
  assert.equal(res.status, 400);
});
test('penalty entries are evicted when the penalty map overflows', () => {
  const { CONFIG } = __internals;
  for (let i = 0; i < CONFIG.MAX_THROTTLE_ENTRIES + CONFIG.MAX_PENALTY_ENTRIES + 5; i++) __internals.localRateLimit(`penalty-${i}`);
  assert.equal(__internals.getHealthSnapshot().penaltyEntries, CONFIG.MAX_PENALTY_ENTRIES);
});
test('unexpected request body errors do not leak internal messages', async () => {
  const stream = new ReadableStream({ pull() { throw new Error('secret stream detail'); } });
  const res = await worker.fetch(new Request('https://workers.example/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: stream, duplex: 'half' }), {}, {});
  assert.equal(res.status, 400);
  assert.equal(await res.text(), 'Invalid DNS query');
});
test('compression pointer targets count toward the 255-byte name limit', () => {
  const query = makeQuery(['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(61)].join('.'));
  const response = Array.from(makeAResponse(query));
  const answer = query.length;
  response.splice(answer, 2, 1, 120, ...new Array(120).fill(120), 0xc0, 0x0c);
  assert.equal(__internals.validateDNSResponse(Uint8Array.from(response), 0x1234, query).ok, false);
});

// ---- 0.5.0 regressions ----
const { CONFIG: CFG } = __internals;
function okResponse(init, ttl = 60) {
  return new Response(makeAResponse(init.body, ttl), { headers: { 'content-type': 'application/dns-message' } });
}
function neverAnswers(init) {
  return new Promise((_resolve, reject) => init.signal.addEventListener('abort', () => reject(new Error('aborted'))));
}
function withPadding(query, len) {
  const out = Array.from(withOPT(query));
  out[out.length - 1] = len + 4; // OPT rdlength
  out.push(0, 12, 0, len, ...new Array(len).fill(0));
  return Uint8Array.from(out);
}
function mkNode(order, score, ewmaLatencyMs) {
  return { url: `u${order}`, order, score, ewmaLatencyMs, lastScoreUpdateAt: Date.now() };
}
test('wrangler.toml rate limit matches the local fallback limiter', () => {
  const toml = readFileSync(new URL('./wrangler.toml', import.meta.url), 'utf8');
  assert.equal(Number(/^limit\s*=\s*(\d+)/m.exec(toml)[1]), CFG.RATE_LIMIT_MAX_REQUESTS);
  assert.equal(Number(/^period\s*=\s*(\d+)/m.exec(toml)[1]) * 1000, CFG.RATE_LIMIT_WINDOW_MS);
});
test('an attempt overtaken by a hedge is penalised and its latency learned', async () => {
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('overtaken.example', 'overtaken');
    assert.equal(res.headers.get('x-upstreams'), '2');
    const root = __internals.RESOLVER_NODES[0];
    assert.equal(root.slow, 1);
    assert.equal(root.score, CFG.SCORE_START - CFG.SCORE_SLOW_DELTA);
    assert.ok(root.ewmaLatencyMs >= CFG.HEDGE_MIN_MS, `ewma ${root.ewmaLatencyMs}`);
    assert.equal(root.fail + root.timeout, 0);
  }, {
    fetch: (url, init) => (url.includes('root.') ? neverAnswers(init) : Promise.resolve(okResponse(init))),
    caches: cacheMock()
  });
});
test('a resolver that keeps losing to hedges stops being chosen first', async () => {
  const first = new Map();
  await withGlobalRuntimeMocks(async () => {
    for (let i = 0; i < 12; i++) await postQuery(`learn-${i}.example`, `learn-${i}`);
  }, {
    fetch: (url, init) => {
      const key = Buffer.from(init.body).toString('hex');
      if (!first.has(key)) first.set(key, url);
      return url.includes('root.') ? neverAnswers(init) : Promise.resolve(okResponse(init));
    },
    caches: cacheMock()
  });
  const rootFirst = [...first.values()].filter((url) => url.includes('root.')).length;
  assert.ok(rootFirst <= 2, `slow resolver led ${rootFirst} of 12 resolutions`);
});
test('selectRacers prefers the lowest learned latency inside the pool', () => {
  const racers = __internals.selectRacers([mkNode(0, 100, 90), mkNode(1, 100, 20), mkNode(2, 100, 40)]);
  assert.deepEqual(racers.map((n) => n.order), [1, 2, 0]);
});
test('a resolver that just timed out leaves the first-choice pool', () => {
  const racers = __internals.selectRacers([
    mkNode(0, CFG.SCORE_START - CFG.SCORE_TIMEOUT_DELTA, 10), mkNode(1, 100, 50), mkNode(2, 100, 60)
  ]);
  assert.deepEqual(racers.map((n) => n.order), [1, 2, 0]);
});
test('every Nth resolution explores another pool member first', () => {
  const nodes = [mkNode(0, 100, 90), mkNode(1, 100, 20), mkNode(2, 100, 40)];
  const firsts = [];
  for (let i = 0; i < CFG.PRIMARY_EXPLORE_EVERY; i++) firsts.push(__internals.selectRacers(nodes)[0].order);
  assert.deepEqual(firsts.slice(0, -1), new Array(CFG.PRIMARY_EXPLORE_EVERY - 1).fill(1));
  assert.notEqual(firsts.at(-1), 1);
});
test('truncated answers from every resolver penalise nobody', async () => {
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('tc-everyone.example', 'tc-everyone');
    assert.equal(res.headers.get('x-dns-degraded'), '1');
    assert.deepEqual(__internals.getHealthSnapshot().upstreams.map((u) => u.score), [100, 100, 100]);
  }, {
    fetch: async (_url, init) => new Response(makeTruncatedResponse(init.body), { headers: { 'content-type': 'application/dns-message' } }),
    caches: cacheMock()
  });
});
test('a truncated answer is penalised when another resolver answers fully', async () => {
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('tc-one.example', 'tc-one');
    assert.equal(res.headers.get('x-dns-degraded'), null);
    const scores = __internals.getHealthSnapshot().upstreams.map((u) => u.score);
    assert.equal(scores[0], CFG.SCORE_START - CFG.SCORE_FAILURE_DELTA);
  }, {
    fetch: async (url, init) => (url.includes('root.')
      ? new Response(makeTruncatedResponse(init.body), { headers: { 'content-type': 'application/dns-message' } })
      : okResponse(init)),
    caches: cacheMock()
  });
});
test('/health reports scores after time-based recovery', () => {
  const node = __internals.RESOLVER_NODES[0];
  node.score = 90;
  node.lastScoreUpdateAt = Date.now() - 3 * CFG.SCORE_RECOVERY_INTERVAL_MS;
  assert.equal(__internals.getHealthSnapshot().upstreams[0].score, 93);
});
test('EDNS padding presence stays in the cache key, its length does not', () => {
  const query = makeQuery('pad-presence.example');
  const { localKeyOf, cacheKeyBytes } = __internals;
  assert.equal(localKeyOf(withPadding(query, 1)), localKeyOf(withPadding(query, 30)));
  assert.notEqual(localKeyOf(withOPT(query)), localKeyOf(withPadding(query, 1)));
  const key = cacheKeyBytes(withPadding(query, 30));
  assert.deepEqual(Array.from(key.slice(-6)), [0, 4, 0, 12, 0, 0]); // rdlength 4 + empty padding
});
test('cache key bytes zero the ID and lower-case only the question name', () => {
  const key = __internals.cacheKeyBytes(makeQuery('MiXeD.Example', 0xbeef));
  assert.deepEqual(Array.from(key), Array.from(makeQuery('mixed.example', 0)));
});
test('a stale in-flight entry is ignored and replaced', async () => {
  const query = makeQuery('stale.example');
  await withGlobalRuntimeMocks(async () => {
    __internals.injectInflight(query, {
      job: new Promise(() => {}), createdAt: Date.now() - CFG.INFLIGHT_JOIN_TIMEOUT_MS - 1, joiners: 0
    });
    const res = await postQuery('stale.example', 'stale');
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-cache'), 'MISS');
    assert.equal(__internals.hasInflight(query), false);
  }, { fetch: async (_url, init) => okResponse(init), caches: cacheMock() });
});
test('a joiner whose leader never settles resolves on its own after the join timeout', async () => {
  const old = CFG.INFLIGHT_JOIN_TIMEOUT_MS;
  CFG.INFLIGHT_JOIN_TIMEOUT_MS = 30;
  try {
    await withGlobalRuntimeMocks(async () => {
      __internals.injectInflight(makeQuery('lost-leader.example'), { job: new Promise(() => {}), createdAt: Date.now(), joiners: 0 });
      const res = await postQuery('lost-leader.example', 'lost-leader');
      assert.equal(res.status, 200);
      assert.equal(res.headers.get('x-cache'), 'MISS');
    }, { fetch: async (_url, init) => okResponse(init), caches: cacheMock() });
  } finally {
    CFG.INFLIGHT_JOIN_TIMEOUT_MS = old;
  }
});
test('the upstream job is detached with ctx.waitUntil and cleans up its in-flight entry', async () => {
  const scheduled = [];
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('detached.example', 'detached', { waitUntil: (p) => { scheduled.push(p); } });
    assert.equal(res.status, 200);
    assert.ok(scheduled.length >= 1);
    await Promise.all(scheduled);
    assert.equal(__internals.hasInflight(makeQuery('detached.example')), false);
  }, { fetch: async (_url, init) => okResponse(init), caches: cacheMock() });
});
test('a fresh answer echoes the leader case without altering the cached copy', async () => {
  await withGlobalRuntimeMocks(async () => {
    const first = await postQuery('MiXeD-Fresh.example', 'fresh-case');
    assert.equal(first.headers.get('x-cache'), 'MISS');
    const firstBody = new Uint8Array(await first.arrayBuffer());
    assert.deepEqual(Array.from(firstBody.slice(12, 32)), Array.from(makeQuery('MiXeD-Fresh.example').slice(12, 32)));
    const second = await postQuery('mixed-fresh.example', 'fresh-case');
    assert.equal(second.headers.get('x-cache'), 'L1-HIT');
    const secondBody = new Uint8Array(await second.arrayBuffer());
    assert.deepEqual(Array.from(secondBody.slice(12, 32)), Array.from(makeQuery('mixed-fresh.example').slice(12, 32)));
  }, { fetch: async () => okResponse({ body: makeQuery('mixed-fresh.example') }), caches: cacheMock() });
});
test('OPTIONS preflight is answered before the rate limiter, and DNS responses carry CORS', async () => {
  const denied = { DNS_RATE_LIMITER: { limit: async () => ({ success: false }) } };
  const pre = await worker.fetch(new Request('https://workers.example/dns-query', { method: 'OPTIONS' }), denied, {});
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get('access-control-allow-origin'), '*');
  assert.match(pre.headers.get('access-control-allow-methods'), /POST/);
  assert.match(pre.headers.get('access-control-allow-headers'), /content-type/);
  const limited = await worker.fetch(new Request('https://workers.example/dns-query'), denied, {});
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get('access-control-allow-origin'), '*');
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('cors.example', 'cors');
    assert.equal(res.headers.get('access-control-allow-origin'), '*');
    assert.match(res.headers.get('access-control-expose-headers'), /x-cache/);
  }, { fetch: async (_url, init) => okResponse(init), caches: cacheMock() });
});

// ---- 0.5.1 regressions ----
test('an NXDOMAIN without a question section is rejected, a SERVFAIL without one is not', () => {
  const query = makeQuery('noq-nx.example');
  // Header (QDCOUNT 0, NSCOUNT 1) plus one SOA record with a root owner name.
  const soa = [2, 110, 115, 0, 2, 104, 109, 0, ...u32(1), ...u32(3600), ...u32(600), ...u32(86400), ...u32(60)];
  const nxdomain = Uint8Array.from([
    0x12, 0x34, 0x81, 0x83, 0, 0, 0, 0, 0, 1, 0, 0,
    0, 0, 6, 0, 1, ...u32(300), 0, soa.length, ...soa
  ]);
  const result = __internals.validateDNSResponse(nxdomain, 0x1234, query);
  assert.equal(result.ok, false);
  assert.match(result.error, /missing question/);
  const servfail = Uint8Array.from([0x12, 0x34, 0x81, 0x82, 0, 0, 0, 0, 0, 0, 0, 0]);
  assert.equal(__internals.validateDNSResponse(servfail, 0x1234, query).ok, true);
});
test('an upstream NXDOMAIN without a question fails over instead of being cached', async () => {
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('noq-upstream.example', 'noq-upstream');
    assert.equal(res.status, 502);
    assert.equal(res.headers.get('x-upstreams'), '3');
    assert.equal(__internals.getHealthSnapshot().cacheEntries, 0);
  }, {
    fetch: async (_url, init) => {
      const soa = [2, 110, 115, 0, 2, 104, 109, 0, ...u32(1), ...u32(3600), ...u32(600), ...u32(86400), ...u32(60)];
      const id = init.body.subarray(0, 2);
      return new Response(Uint8Array.from([
        id[0], id[1], 0x81, 0x83, 0, 0, 0, 0, 0, 1, 0, 0,
        0, 0, 6, 0, 1, ...u32(300), 0, soa.length, ...soa
      ]), { headers: { 'content-type': 'application/dns-message' } });
    },
    caches: cacheMock()
  });
});
test('an L2 entry with bad bookkeeping headers is purged without reading its body', async () => {
  const query = makeQuery('l2-headers-only.example');
  const key = await __internals.makeCacheKey(query);
  let bodyReads = 0;
  let deletes = 0;
  await withGlobalRuntimeMocks(async () => {
    const res = await postQuery('l2-headers-only.example', 'l2-headers-only');
    assert.equal(res.headers.get('x-cache'), 'MISS');
    assert.equal(bodyReads, 0);
    assert.equal(deletes, 1);
  }, {
    fetch: async (_url, init) => okResponse(init),
    caches: {
      default: {
        match: async (req) => (req.url.endsWith(key)
          ? { headers: new Headers({ 'x-doh-ttl': '300' }), arrayBuffer: async () => { bodyReads += 1; return new ArrayBuffer(0); } }
          : null),
        delete: async () => { deletes += 1; },
        put: async () => {}
      }
    }
  });
});
test('a rejected upstream job with no joiners and no waitUntil raises no unhandled rejection', async () => {
  const unhandled = [];
  const onUnhandled = (reason) => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandled);
  try {
    await withGlobalRuntimeMocks(async () => {
      const res = await postQuery('no-unhandled.example', 'no-unhandled');
      assert.equal(res.status, 502);
      await new Promise((resolve) => setTimeout(resolve, 20));
      assert.deepEqual(unhandled, []);
    }, { fetch: async () => { throw new Error('down'); }, caches: cacheMock() });
  } finally {
    process.off('unhandledRejection', onUnhandled);
  }
});

// ---- 0.5.2 regressions ----
// A query whose single EDNS OPT record carries the given RDATA (root owner,
// type 41, UDP size 4096, zero extended flags, then RDLENGTH and RDATA).
function withOptRdata(query, rdata) {
  const out = [...query, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, rdata.length >> 8, rdata.length & 0xff, ...rdata];
  out[11] = 1;
  return Uint8Array.from(out);
}
test('parseDNSQuestion requires EDNS options to tile the OPT RDATA exactly', () => {
  const q = makeQuery('opt-framing.example');
  const parse = (rdata) => __internals.parseDNSQuestion(withOptRdata(q, rdata));
  assert.equal(parse([]).ok, true);
  assert.equal(parse([0, 12, 0, 2, 0, 0]).ok, true); // one option, exact fit
  assert.equal(parse([0, 10, 0, 1, 7, 0, 12, 0, 0]).ok, true); // two options
  for (const bad of [
    [0, 12, 0, 223, 1, 2, 3, 4], // option length overruns the RDATA
    [0, 12, 0], // incomplete option header
    [0, 12, 0, 2, 0], // option one byte short
    [0, 10, 0, 1, 7, 0, 12] // valid option followed by a partial header
  ]) {
    const parsed = parse(bad);
    assert.equal(parsed.ok, false, `RDATA ${bad} must be rejected`);
    assert.match(parsed.error, /EDNS options/);
  }
});
test('every query accepted by parseDNSQuestion has computable cache key bytes', () => {
  const q = makeQuery('key-invariant.example');
  for (const rdata of [[], [0, 12, 0, 0], [0, 12, 0, 2, 0, 0], [0, 10, 0, 2, 1, 2, 0, 12, 0, 0]]) {
    const query = withOptRdata(q, rdata);
    const parsed = __internals.parseDNSQuestion(query);
    assert.equal(parsed.ok, true);
    assert.doesNotThrow(() => __internals.cacheKeyBytes(query, parsed.questionEnd));
  }
});
test('a query with malformed EDNS options gets 400 (not an exception) and never reaches upstream', async () => {
  let upstreamCalls = 0;
  const bad = withOptRdata(makeQuery('bad-edns.example'), [0, 12, 0, 223, 1, 2, 3, 4]);
  await withGlobalRuntimeMocks(async () => {
    const post = await worker.fetch(new Request('https://workers.example/dns-query', {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message', 'cf-connecting-ip': 'bad-edns-post' },
      body: bad
    }), {}, {});
    assert.equal(post.status, 400);
    const get = await worker.fetch(new Request(
      `https://workers.example/dns-query?dns=${Buffer.from(bad).toString('base64url')}`,
      { headers: { 'cf-connecting-ip': 'bad-edns-get' } }
    ), {}, {});
    assert.equal(get.status, 400);
    assert.equal(upstreamCalls, 0);
  }, { fetch: async () => { upstreamCalls += 1; throw new Error('upstream must not be used'); }, caches: cacheMock() });
});
test('resolver scores stay inside [SCORE_MIN, SCORE_MAX]', async () => {
  await withGlobalRuntimeMocks(async () => {
    assert.equal((await postQuery('clamp-ok.example', 'clamp-ok')).status, 200);
    assert.ok(__internals.getHealthSnapshot().upstreams.every((u) => u.score === CFG.SCORE_MAX));
  }, { fetch: async (_url, init) => okResponse(init), caches: cacheMock() });
  await withGlobalRuntimeMocks(async () => {
    // Each failed resolution penalises every resolver once; 10 x 12 > 100.
    for (let i = 0; i < 10; i++) assert.equal((await postQuery(`clamp-fail-${i}.example`, 'clamp-fail')).status, 502);
    assert.ok(__internals.getHealthSnapshot().upstreams.every((u) => u.score === CFG.SCORE_MIN));
  }, { fetch: async () => { throw new Error('down'); }, caches: cacheMock() });
});
test('a joiner attaches to a leader inside the three-sequential-timeout window', async () => {
  let calls = 0;
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  await withGlobalRuntimeMocks(async () => {
    const leader = postQuery('join-window.example', 'join-window-1');
    await waitForInflight('join-window.example');
    // Age the leader's entry to 3 s: above 0.5.2's 2500 ms join timeout but
    // below 0.5.3's 4000 ms one and inside the 3600 ms worst case of three
    // sequential upstream timeouts. A correct implementation still attaches
    // the joiner to it; 0.5.2 would fork a duplicate upstream resolution.
    const entry = __internals.inflightEntry(makeQuery('join-window.example'));
    entry.createdAt -= 3000;
    const joiner = postQuery('join-window.example', 'join-window-2');
    await waitForJoiners('join-window.example', 1);
    release();
    const [leaderRes, joinerRes] = await Promise.all([leader, joiner]);
    assert.equal(leaderRes.status, 200);
    assert.equal(joinerRes.status, 200);
    assert.equal(joinerRes.headers.get('x-cache'), 'COALESCED');
    assert.equal(calls, 1);
  }, {
    fetch: async (_url, init) => {
      calls += 1;
      await gate;
      return okResponse(init);
    },
    caches: cacheMock()
  });
});
