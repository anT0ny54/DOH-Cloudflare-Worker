import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(fileURLToPath(new URL('../', import.meta.url)));
const workerPath = path.join(root, 'Worker.js');
const workerSource = await readFile(workerPath, 'utf8');

const originalFetch = globalThis.fetch;
const originalCaches = globalThis.caches;
let upstreamHandler = async () => new Response('unused', { status: 500 });
let upstreamLog = [];
let waitUntilJobs = [];
let moduleCounter = 0;

class MemoryCache {
  constructor() { this.map = new Map(); }
  async match(request) {
    const item = this.map.get(String(request.url ?? request));
    return item ? item.clone() : undefined;
  }
  async put(request, response) {
    this.map.set(String(request.url ?? request), response.clone());
  }
  clear() { this.map.clear(); }
}

const edgeCache = new MemoryCache();
globalThis.caches = { default: edgeCache };
globalThis.fetch = (...args) => {
  upstreamLog.push({ input: args[0], init: args[1] });
  return upstreamHandler(...args);
};

function u16(value) { return [(value >>> 8) & 0xff, value & 0xff]; }
function u32(value) { return [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]; }
function encodeName(name) {
  if (!name || name === '.') return [0];
  return [...name.split('.').flatMap(label => [label.length, ...Buffer.from(label, 'ascii')]), 0];
}
function makeQuery(id = 0x1234, name = 'example.com', qtype = 1, additional = [], flags = 0x0100) {
  return new Uint8Array([
    ...u16(id), ...u16(flags), ...u16(1), ...u16(0), ...u16(0), ...u16(additional.length),
    ...encodeName(name), ...u16(qtype), ...u16(1), ...additional.flat()
  ]);
}
function makeOPT({ udpPayloadSize = 1232, ttl = 0, rdata = [] } = {}) {
  return [0, ...u16(41), ...u16(udpPayloadSize), ...u32(ttl), ...u16(rdata.length), ...rdata];
}
function questionEnd(query) {
  let offset = 12;
  while (offset < query.length) {
    const len = query[offset++];
    if (len === 0) return offset + 4;
    offset += len;
  }
  return -1;
}
function makeAResponse(query, { id = null, ttl = 60, rcode = 0, tc = false, question = true } = {}) {
  const q = new Uint8Array(query);
  const qEnd = questionEnd(q);
  const qBytes = question && qEnd >= 0 ? Array.from(q.slice(12, qEnd)) : [];
  const answer = [0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, ...u32(ttl), 0x00, 0x04, 1, 2, 3, 4];
  const flags = 0x8000 | 0x0080 | (tc ? 0x0200 : 0) | (rcode & 0x0f);
  return new Uint8Array([
    ...u16(id ?? ((q[0] << 8) | q[1])), ...u16(flags), ...u16(question ? 1 : 1), ...u16(1), ...u16(0), ...u16(0),
    ...qBytes, ...answer
  ]);
}
function makeHeaderOnlyResponse(query) {
  const q = new Uint8Array(query);
  return new Uint8Array([
    q[0], q[1], 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ]);
}
function makeSERVFAILResponse(query) {
  const q = new Uint8Array(query);
  const qEnd = questionEnd(q);
  return new Uint8Array([
    q[0], q[1], 0x81, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ...q.slice(12, qEnd)
  ]);
}
function makeNXDOMAINResponse(query, ttl = 30) {
  const q = new Uint8Array(query);
  const qEnd = questionEnd(q);
  const soaRdata = [0, 0, 0, 0, ...u32(1), ...u32(1), ...u32(1), ...u32(1), ...u32(ttl)];
  const authority = [0, 0x00, 0x06, 0x00, 0x01, ...u32(ttl), ...u16(soaRdata.length), ...soaRdata];
  return new Uint8Array([
    q[0], q[1], 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    ...q.slice(12, qEnd), ...authority
  ]);
}
function b64url(bytes) { return Buffer.from(bytes).toString('base64url'); }
function makeRequest(url, init = {}) { return new Request(url, init); }
function makeContext() { return { waitUntil(promise) { waitUntilJobs.push(Promise.resolve(promise)); } }; }
function resetRuntime() {
  upstreamLog = [];
  waitUntilJobs = [];
  edgeCache.clear();
  upstreamHandler = async () => new Response('unused', { status: 500 });
}
async function drainWaitUntil() {
  const jobs = waitUntilJobs.splice(0);
  await Promise.all(jobs);
}
async function loadWorker() {
  return (await import(`file://${workerPath}?all=${++moduleCounter}`)).default;
}
async function responseBytes(response) { return new Uint8Array(await response.arrayBuffer()); }
function upstreamCount() { return upstreamLog.filter(entry => String(entry.input.url ?? entry.input).includes('.hagezi.org')).length; }
function sleep(ms, signal) {
  if (!ms) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    if (!signal) return;
    const onAbort = () => { clearTimeout(timer); reject(signal.reason || new Error('aborted')); };
    if (signal.aborted) return onAbort();
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

await test('complete Cloudflare DoH Worker feature validation', async (t) => {
  await t.test('routing, health, headers, and dashboard', async () => {
    resetRuntime();
    const worker = await loadWorker();
    const home = await worker.fetch(makeRequest('https://dns.example/'), {}, makeContext());
    assert.equal(home.status, 200);
    assert.match(home.headers.get('content-type'), /text\/html/);
    assert.equal(home.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(home.headers.get('referrer-policy'), 'no-referrer');
    const html = await home.text();
    for (const needle of [
      'viewport-fit=cover', 'theme-color', '.hero-title { font-size: clamp', '#linkInp { font-size: clamp',
      'onclick="this.select()"', 'class="no-scrollbar', 'scroll-snap-type: x mandatory',
      'aria-haspopup="true"', 'aria-expanded="false"', 'document.documentElement.lang',
      'document.documentElement.dir', 'menu.classList.contains', "c = I18N[c] ? c : 'en'"
    ]) assert.match(html, new RegExp(needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    const script = html.match(/<script>\s*([\s\S]*?)\s*<\/script>/)?.[1];
    assert.ok(script);
    new vm.Script(script);

    const index = await worker.fetch(makeRequest('https://dns.example/index.html'), {}, makeContext());
    assert.equal(index.status, 200);
    const health = await (await worker.fetch(makeRequest('https://dns.example/health'), {}, makeContext())).json();
    assert.equal(health.upstreams.length, 3);
    assert.equal(health.maxSimultaneousUpstreams, 3);
    assert.equal(health.rateLimit.maxRequests, 100);
    assert.equal(health.cache.l1, 'in-memory LRU');
    const missing = await worker.fetch(makeRequest('https://dns.example/missing'), {}, makeContext());
    assert.equal(missing.status, 404);
  });

  await t.test('HTTP and request-size validation', async () => {
    resetRuntime();
    const worker = await loadWorker();
    const put = await worker.fetch(makeRequest('https://dns.example/dns-query', { method: 'PUT' }), {}, makeContext());
    assert.equal(put.status, 405); assert.equal(put.headers.get('allow'), 'GET, POST');
    const missing = await worker.fetch(makeRequest('https://dns.example/dns-query'), {}, makeContext());
    assert.equal(missing.status, 400);
    const invalid64 = await worker.fetch(makeRequest('https://dns.example/dns-query?dns=abc='), {}, makeContext());
    assert.equal(invalid64.status, 400);
    const wrongType = await worker.fetch(makeRequest('https://dns.example/dns-query', {
      method: 'POST', headers: { 'content-type': 'text/plain' }, body: 'x'
    }), {}, makeContext());
    assert.equal(wrongType.status, 415);
    const bigCL = await worker.fetch(makeRequest('https://dns.example/dns-query', {
      method: 'POST', headers: { 'content-type': 'application/dns-message', 'content-length': '4097' }, body: 'x'
    }), {}, makeContext());
    assert.equal(bigCL.status, 413);
    const bigGET = await worker.fetch(makeRequest(`https://dns.example/dns-query?dns=${'A'.repeat(5463)}`), {}, makeContext());
    assert.equal(bigGET.status, 413);

    let cancelSeen = false;
    const stream = new ReadableStream({
      start(controller) { controller.enqueue(new Uint8Array(4096)); controller.enqueue(new Uint8Array(1)); controller.close(); },
      cancel() { cancelSeen = true; }
    });
    const bigStream = await worker.fetch(makeRequest('https://dns.example/dns-query', {
      method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: stream, duplex: 'half'
    }), {}, makeContext());
    assert.equal(bigStream.status, 413);
    assert.equal(typeof cancelSeen, 'boolean');
  });

  await t.test('valid DoH GET/POST, cache sharing, and transaction IDs', async () => {
    resetRuntime();
    const worker = await loadWorker();
    upstreamHandler = async (_input, init = {}) => {
      const query = new Uint8Array(init.body);
      return new Response(makeAResponse(query, { ttl: 60 }), { status: 200, headers: { 'content-type': 'application/dns-message' } });
    };
    const getQuery = makeQuery(0xbeef, 'example.com', 1);
    const get = await worker.fetch(makeRequest(`https://dns.example/dns-query?dns=${b64url(getQuery)}`), {}, makeContext());
    assert.equal(get.status, 200);
    assert.equal(get.headers.get('content-type'), 'application/dns-message');
    assert.equal(get.headers.get('cache-control'), 'no-store');
    assert.equal(get.headers.get('vary'), 'Accept-Encoding');
    assert.equal(get.headers.get('x-cache'), 'MISS');
    let body = await responseBytes(get);
    assert.equal((body[0] << 8) | body[1], 0xbeef);

    const postQuery = makeQuery(0x1234, 'example.com', 1);
    const post = await worker.fetch(makeRequest('https://dns.example/dns-query', {
      method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: postQuery
    }), {}, makeContext());
    assert.equal(post.status, 200);
    assert.equal(post.headers.get('x-cache'), 'L1-HIT');
    body = await responseBytes(post);
    assert.equal((body[0] << 8) | body[1], 0x1234);
    assert.equal(upstreamCount(), 1);
  });

  await t.test('L2 Cache API survives fresh Worker isolate and restores ID', async () => {
    resetRuntime();
    upstreamHandler = async (_input, init = {}) => {
      const query = new Uint8Array(init.body);
      return new Response(makeAResponse(query, { ttl: 60 }), { status: 200 });
    };
    const worker1 = await loadWorker();
    const first = await worker1.fetch(makeRequest('https://dns.example/dns-query', {
      method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0x1111, 'l2.example')
    }), {}, makeContext());
    assert.equal(first.status, 200);
    await drainWaitUntil();
    const worker2 = await loadWorker();
    const second = await worker2.fetch(makeRequest('https://dns.example/dns-query', {
      method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0x2222, 'l2.example')
    }), {}, makeContext());
    assert.equal(second.headers.get('x-cache'), 'L2-HIT');
    assert.equal(second.headers.get('x-edge-cache'), 'HIT');
    const body = await responseBytes(second);
    assert.equal((body[0] << 8) | body[1], 0x2222);
    assert.equal(upstreamCount(), 1);
  });

  await t.test('concurrent request coalescing', async () => {
    resetRuntime();
    const worker = await loadWorker();
    upstreamHandler = async (_input, init = {}) => {
      await sleep(80, init.signal);
      return new Response(makeAResponse(new Uint8Array(init.body), { ttl: 60 }), { status: 200 });
    };
    const [a, b] = await Promise.all([
      worker.fetch(makeRequest('https://dns.example/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0xaaaa, 'coal.example') }), {}, makeContext()),
      worker.fetch(makeRequest('https://dns.example/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0xbbbb, 'coal.example') }), {}, makeContext())
    ]);
    assert.notEqual(a.headers.get('x-cache'), b.headers.get('x-cache'));
    assert.equal(upstreamCount(), 1);
    const [ab, bb] = await Promise.all([responseBytes(a), responseBytes(b)]);
    assert.equal((ab[0] << 8) | ab[1], 0xaaaa);
    assert.equal((bb[0] << 8) | bb[1], 0xbbbb);
  });

  await t.test('primary failure failover and resolver scoring', async () => {
    resetRuntime();
    const worker = await loadWorker();
    upstreamHandler = async (input, init = {}) => {
      if (String(input.url ?? input).includes('root.hagezi.org')) return new Response('bad', { status: 503 });
      return new Response(makeAResponse(new Uint8Array(init.body), { ttl: 60 }), { status: 200 });
    };
    const response = await worker.fetch(makeRequest('https://dns.example/dns-query', {
      method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0x3001, 'failover.example')
    }), {}, makeContext());
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('x-upstreams'), '2');
    const health = await (await worker.fetch(makeRequest('https://dns.example/health'), {}, makeContext())).json();
    const root = health.upstreams.find(n => n.url.includes('root.hagezi.org'));
    assert.ok(root.fail >= 1); assert.ok(root.score < 100);
  });

  await t.test('hedging, winner selection, and timer cleanup behavior', async () => {
    resetRuntime();
    const worker = await loadWorker();
    upstreamHandler = async (input, init = {}) => {
      const url = String(input.url ?? input);
      await sleep(url.includes('root.hagezi.org') ? 450 : 5, init.signal);
      return new Response(makeAResponse(new Uint8Array(init.body), { ttl: 60 }), { status: 200 });
    };
    const response = await worker.fetch(makeRequest('https://dns.example/dns-query', {
      method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0x3002, 'hedge.example')
    }), {}, makeContext());
    assert.equal(response.status, 200); assert.equal(response.headers.get('x-upstreams'), '2');

    const code = workerSource.replace(/^export default \{/m, 'const __workerExport = {');
    let pending = new Set();
    let nextTimer = 1;
    const timers = new Map();
    const timerSet = (fn) => { const id = nextTimer++; timers.set(id, fn); pending.add(id); return id; };
    const timerClear = (id) => { timers.delete(id); pending.delete(id); };
    const context = vm.createContext({
      AbortController, Map, Promise, Uint8Array, ArrayBuffer, Number, Math, String, Date, console,
      Response, Request, Headers, crypto: globalThis.crypto, setTimeout: timerSet, clearTimeout: timerClear
    });
    vm.runInContext(code, context, { filename: workerPath });
    const race = vm.runInContext('raceUntilActiveSettles', context);
    const active = new Map([[{}, Promise.resolve({ ok: true })]]);
    const result = await race(active, 9999);
    assert.equal(result.type, 'result');
    assert.equal(pending.size, 0);
  });

  await t.test('all failures, DNS degraded fallback, wrong ID, malformed response, and response structure validation', async () => {
    resetRuntime();
    const worker = await loadWorker();
    let mode = 'http'; let calls = 0;
    upstreamHandler = async (_input, init = {}) => {
      calls++;
      const query = new Uint8Array(init.body);
      if (mode === 'http') return new Response('bad', { status: 503 });
      if (mode === 'servfail') return new Response(makeSERVFAILResponse(query), { status: 200 });
      if (mode === 'wrong-id') return new Response(makeAResponse(query, { id: 0x9999 }), { status: 200 });
      if (mode === 'short') return new Response(makeHeaderOnlyResponse(query), { status: 200 });
      if (mode === 'bad-qcount') {
        const body = makeAResponse(query, { ttl: 60 }); body[4] = 0; body[5] = 0; return new Response(body, { status: 200 });
      }
      if (mode === 'bad-question') {
        const body = makeAResponse(query, { ttl: 60 });
        body[12] = body[12] + 1; return new Response(body, { status: 200 });
      }
      if (mode === 'reserved-z') {
        const body = makeAResponse(query, { ttl: 60 });
        body[3] |= 0x40; return new Response(body, { status: 200 });
      }
      if (mode === 'trailing') return new Response(new Uint8Array([...makeAResponse(query, { ttl: 60 }), 0xde]), { status: 200 });
      return new Response(makeAResponse(query, { ttl: 60 }), { status: 200 });
    };
    const allFail = await worker.fetch(makeRequest('https://dns.example/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0x3101, 'allfail.example') }), {}, makeContext());
    assert.equal(allFail.status, 502); assert.equal(allFail.headers.get('x-upstreams'), '3'); assert.equal(calls, 3);

    mode = 'servfail'; calls = 0;
    const degraded = await worker.fetch(makeRequest('https://dns.example/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0x3102, 'servfail.example') }), {}, makeContext());
    assert.equal(degraded.status, 200); assert.equal(degraded.headers.get('x-dns-degraded'), '1'); assert.equal(degraded.headers.get('x-upstreams'), '3'); assert.equal(calls, 3);

    for (const invalidMode of ['wrong-id', 'short', 'bad-qcount', 'bad-question', 'reserved-z', 'trailing']) {
      mode = invalidMode; calls = 0;
      const response = await worker.fetch(makeRequest('https://dns.example/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0x3200 + calls + invalidMode.length, `${invalidMode}.example`) }), {}, makeContext());
      assert.equal(response.status, 502);
      assert.equal(response.headers.get('x-upstreams'), '3');
      assert.equal(calls, 3);
    }
  });

  await t.test('DNS names are case-insensitive: an upstream echoing a different-case question is still usable', async () => {
    resetRuntime();
    const worker = await loadWorker();
    let calls = 0;
    upstreamHandler = async (_input, init = {}) => {
      calls++;
      const query = new Uint8Array(init.body);
      const body = makeAResponse(query, { ttl: 60 });
      // A compliant resolver may normalize/echo the question in different
      // letter case than the outgoing query (RFC 1035 names are
      // case-insensitive). Flip the case of every ASCII letter in the
      // echoed question only -- label lengths, QTYPE, and QCLASS are left
      // untouched since flipping bit 0x20 on those would corrupt them.
      const qEnd = questionEnd(query);
      for (let i = 12; i < qEnd - 4; i++) {
        const b = body[i];
        if ((b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a)) body[i] = b ^ 0x20;
      }
      return new Response(body, { status: 200 });
    };
    const response = await worker.fetch(makeRequest('https://dns.example/dns-query', {
      method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0x3150, 'CaseFold.example')
    }), {}, makeContext());
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('x-cache'), 'MISS');
    assert.equal(calls, 1);
    const body = await responseBytes(response);
    assert.equal((body[0] << 8) | body[1], 0x3150);

    // A genuinely different question (not just different case) must still
    // be rejected as a mismatch.
    calls = 0;
    upstreamHandler = async (_input, init = {}) => {
      calls++;
      const query = new Uint8Array(init.body);
      const body = makeAResponse(query, { ttl: 60 });
      body[12] = body[12] + 1; // corrupt the first label's length byte
      return new Response(body, { status: 200 });
    };
    const mismatch = await worker.fetch(makeRequest('https://dns.example/dns-query', {
      method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0x3151, 'genuinely-different.example')
    }), {}, makeContext());
    assert.equal(mismatch.status, 502);
    assert.equal(calls, 3);
  });

  await t.test('upstream timeout path records timeouts and fails over all three resolvers', async () => {
    resetRuntime();
    const worker = await loadWorker();
    let calls = 0;
    upstreamHandler = async (_input, init = {}) => {
      calls++;
      await sleep(5000, init.signal);
      throw new Error('unexpected timeout test completion');
    };

    const response = await worker.fetch(makeRequest('https://dns.example/dns-query', {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message' },
      body: makeQuery(0x3250, 'timeout.example')
    }), {}, makeContext());

    assert.equal(response.status, 502);
    assert.equal(response.headers.get('x-upstreams'), '3');
    assert.equal(calls, 3);

    const health = await (await worker.fetch(makeRequest('https://dns.example/health'), {}, makeContext())).json();
    assert.equal(health.upstreams.reduce((sum, node) => sum + node.timeout, 0), 3);
    assert.equal(health.inflightEntries, 0);
  });

  await t.test('bounded upstream response body', async () => {
    resetRuntime();
    const worker = await loadWorker();
    let calls = 0;
    upstreamHandler = async (_input, init = {}) => {
      calls++;
      if (calls < 3) {
        return new Response(new Uint8Array(65536), { status: 200, headers: { 'content-length': '65536' } });
      }
      return new Response(makeAResponse(new Uint8Array(init.body), { ttl: 60 }), { status: 200 });
    };
    const response = await worker.fetch(makeRequest('https://dns.example/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0x3301, 'bound.example') }), {}, makeContext());
    assert.equal(response.status, 200); assert.equal(response.headers.get('x-upstreams'), '3'); assert.equal(calls, 3);
  });

  await t.test('L1 TTL aging, expiry, NXDOMAIN negative caching, and non-cacheable responses', async () => {
    resetRuntime();
    const worker = await loadWorker();
    let calls = 0; let mode = 'a';
    upstreamHandler = async (_input, init = {}) => {
      calls++;
      const query = new Uint8Array(init.body);
      if (mode === 'nx') return new Response(makeNXDOMAINResponse(query, 30), { status: 200 });
      if (mode === 'sf') return new Response(makeSERVFAILResponse(query), { status: 200 });
      if (mode === 'tc') return new Response(makeAResponse(query, { ttl: 60, tc: true }), { status: 200 });
      return new Response(makeAResponse(query, { ttl: 2 }), { status: 200 });
    };
    const realNow = Date.now; let now = 10_000_000; Date.now = () => now;
    try {
      const q1 = makeQuery(0x4101, 'ttl.example');
      await worker.fetch(makeRequest('https://dns.example/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: q1 }), {}, makeContext());
      now += 1000;
      const hit = await worker.fetch(makeRequest('https://dns.example/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0x4102, 'ttl.example') }), {}, makeContext());
      assert.equal(hit.headers.get('x-cache'), 'L1-HIT');
      const bytes = await responseBytes(hit);
      const qEnd = questionEnd(bytes); const ttlOffset = qEnd + 6;
      const ttl = (((bytes[ttlOffset] * 256 + bytes[ttlOffset + 1]) * 256 + bytes[ttlOffset + 2]) * 256 + bytes[ttlOffset + 3]) >>> 0;
      assert.equal(ttl, 1);
      now += 2000;
      const expired = await worker.fetch(makeRequest('https://dns.example/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0x4103, 'ttl.example') }), {}, makeContext());
      assert.equal(expired.headers.get('x-cache'), 'MISS'); assert.equal(calls, 2);

      mode = 'nx';
      const nx1 = await worker.fetch(makeRequest('https://dns.example/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0x4201, 'missing.example') }), {}, makeContext());
      const nx2 = await worker.fetch(makeRequest('https://dns.example/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0x4202, 'missing.example') }), {}, makeContext());
      assert.equal(nx1.status, 200); assert.equal(nx2.headers.get('x-cache'), 'L1-HIT');

      mode = 'sf';
      await worker.fetch(makeRequest('https://dns.example/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0x4301, 'sf.example') }), {}, makeContext());
      const sf2 = await worker.fetch(makeRequest('https://dns.example/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0x4302, 'sf.example') }), {}, makeContext());
      assert.equal(sf2.headers.get('x-cache'), 'MISS');

      mode = 'tc';
      await worker.fetch(makeRequest('https://dns.example/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0x4401, 'tc.example') }), {}, makeContext());
      const tc2 = await worker.fetch(makeRequest('https://dns.example/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0x4402, 'tc.example') }), {}, makeContext());
      assert.equal(tc2.headers.get('x-cache'), 'MISS');
    } finally { Date.now = realNow; }
  });

  await t.test('native/local rate limits, IP isolation, and reset window', async () => {
    resetRuntime();
    const worker = await loadWorker();
    const requests = { DNS_RATE_LIMITER: { calls: [], async limit(arg) { this.calls.push(arg); return { success: false }; } } };
    const denied = await worker.fetch(makeRequest('https://dns.example/dns-query', { headers: { 'CF-Connecting-IP': '203.0.113.10' } }), requests, makeContext());
    assert.equal(denied.status, 429); assert.deepEqual(requests.DNS_RATE_LIMITER.calls, [{ key: '203.0.113.10' }]);

    const local = await loadWorker();
    const realNow = Date.now; let now = 20_000_000; Date.now = () => now;
    try {
      for (let i = 0; i < 100; i++) {
        const r = await local.fetch(makeRequest('https://dns.example/dns-query', { method: 'PUT', headers: { 'CF-Connecting-IP': '198.51.100.1', 'X-Forwarded-For': `192.0.2.${i}` } }), {}, makeContext());
        assert.equal(r.status, 405);
      }
      assert.equal((await local.fetch(makeRequest('https://dns.example/dns-query', { method: 'PUT', headers: { 'CF-Connecting-IP': '198.51.100.1' } }), {}, makeContext())).status, 429);
      assert.equal((await local.fetch(makeRequest('https://dns.example/dns-query', { method: 'PUT', headers: { 'CF-Connecting-IP': '198.51.100.2' } }), {}, makeContext())).status, 405);
      now += 60_000;
      assert.equal((await local.fetch(makeRequest('https://dns.example/dns-query', { method: 'PUT', headers: { 'CF-Connecting-IP': '198.51.100.1' } }), {}, makeContext())).status, 405);
    } finally { Date.now = realNow; }
  });

  await t.test('cache failure resilience and bounded in-memory state', async () => {
    resetRuntime();
    const worker = await loadWorker();
    upstreamHandler = async (_input, init = {}) => new Response(makeAResponse(new Uint8Array(init.body), { ttl: 1 }), { status: 200 });
    globalThis.caches.default = {
      async match() { throw new Error('cache unavailable'); },
      async put() { throw new Error('cache unavailable'); }
    };
    const response = await worker.fetch(makeRequest('https://dns.example/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: makeQuery(0x5101, 'cache-fail.example') }), {}, makeContext());
    assert.equal(response.status, 200); await drainWaitUntil();
    globalThis.caches.default = edgeCache;

    const bounded = await loadWorker();
    const env = { DNS_RATE_LIMITER: { async limit() { return { success: true }; } } };
    upstreamHandler = async (_input, init = {}) => new Response(makeAResponse(new Uint8Array(init.body), { ttl: 1 }), { status: 200 });
    for (let i = 0; i < 520; i++) {
      const r = await bounded.fetch(makeRequest('https://dns.example/dns-query', {
        method: 'POST', headers: { 'content-type': 'application/dns-message', 'CF-Connecting-IP': `192.0.2.${(i % 200) + 1}` }, body: makeQuery(i, `x${i}.example`)
      }), env, makeContext());
      assert.equal(r.status, 200);
    }
    const health = await (await bounded.fetch(makeRequest('https://dns.example/health'), {}, makeContext())).json();
    assert.ok(health.cacheEntries <= 512); assert.ok(health.throttleEntries <= 2048); assert.equal(health.inflightEntries, 0);
  });

  await t.test('Cloudflare-compatible configuration and dead-code audit', async () => {
    const configPath = path.join(root, 'wrangler.toml');
    try {
      const config = await readFile(configPath, 'utf8');
      assert.match(config, /main\s*=\s*\"Worker\.js\"/);
      assert.match(config, /name\s*=\s*\"DNS_RATE_LIMITER\"/);
      assert.match(config, /limit\s*=\s*100/);
      assert.match(config, /period\s*=\s*60/);
    } catch (err) {
      assert.equal(err?.code, 'ENOENT', `unexpected wrangler.toml read failure: ${err}`);
      assert.match(workerSource, /RATE_LIMIT_MAX_REQUESTS:\s*100/);
    }
    assert.doesNotMatch(workerSource, /patchDNSResponseID\s*\(/);
    assert.doesNotMatch(workerSource, /questionKey\s*:/);
    assert.equal((workerSource.match(/https:\/\/[^'\"`]*hagezi\.org\/dns-query/g) || []).length, 3);
    assert.doesNotMatch(workerSource, /cloudflare.*fallback/i);
    assert.match(workerSource, /clearTimeout\(timeoutHandle\)/);
    assert.match(workerSource, /MAX_DNS_RESPONSE_BYTES/);
  });
});

process.on('exit', () => {
  globalThis.fetch = originalFetch;
  globalThis.caches = originalCaches;
});
