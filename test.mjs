import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { __internals } from './Worker.js';

function makeQuery(name, id = 0x1234, flags = 0x0100) {
  const labels = name === '.' ? [] : name.split('.');
  const bytes = [
    (id >> 8) & 0xff,
    id & 0xff,
    (flags >> 8) & 0xff,
    flags & 0xff,
    0,
    1, // QDCOUNT
    0,
    0, // ANCOUNT
    0,
    0, // NSCOUNT
    0,
    0 // ARCOUNT
  ];

  for (const label of labels) {
    bytes.push(label.length);
    for (let i = 0; i < label.length; i++) {
      bytes.push(label.charCodeAt(i));
    }
  }
  bytes.push(0); // Root label.

  bytes.push(0, 1); // QTYPE A
  bytes.push(0, 1); // QCLASS IN
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
  bytes[7] = rcode === 0 ? 1 : 0; // ANCOUNT

  if (rcode !== 0) return new Uint8Array(bytes);

  bytes.push(0xc0, 0x0c); // Compressed question name
  bytes.push(0, 1);       // TYPE A
  bytes.push(0, 1);       // CLASS IN
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

test('validateDNSResponse checks ID and response bit', () => {
  const query = makeQuery('example.com');
  const response = makeAResponse(query);
  assert.deepEqual(__internals.validateDNSResponse(response, 0x1234), {
    ok: true,
    rcode: 0
  });
  assert.equal(__internals.validateDNSResponse(response, 0x9999).ok, false);
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

  // Answer starts after the 12-byte header and 17-byte example.com question.
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
        'content-length': String(262145)
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
  assert.equal(body.version, '0.2.2');
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

test('valid compressed question name is accepted structurally', () => {
  const query = makeQuery('example.com');
  const compressed = new Uint8Array([
    ...query.slice(0, 12),
    0xc0, 0x0c,
    0, 1,
    0, 1
  ]);
  const parsed = __internals.parseDNSQuestion(compressed);
  assert.equal(parsed.ok, true);
});

function makeNxdomainWithSOA(query, ttl, minimum) {
  const bytes = Array.from(query);
  bytes[2] = 0x81;
  bytes[3] = 0x83; // response, RD+RA, NXDOMAIN
  bytes[9] = 1; // NSCOUNT

  const u32 = (v) => [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff];
  const rdata = [
    2, 110, 115, 0, // MNAME ns.
    2, 104, 109, 0, // RNAME hm.
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
