# 🛡️ DoH — Cloudflare Worker

A lightweight Cloudflare Worker that exposes a standard **DNS-over-HTTPS** endpoint, uses three HaGeZi resolvers with intelligent staged failover, and keeps a two-level DNS cache (Worker version 0.5.3, 113-test suite, green CI):

```txt
L1: per-isolate memory cache
L2: Cloudflare Cache API (data-center-local)
```

```txt
https://root.hagezi.org/dns-query
https://wurzn.hagezi.org/dns-query
https://juuri.hagezi.org/dns-query
```

No other DNS upstreams or resolver profiles are used by the Worker. (The "Free DNS Services" table further down lists separate hosted deployments; the Worker never contacts them.) According to HaGeZi's published server list, the three endpoints are hosted in different locations (Falkenstein DE, Nuremberg DE and Helsinki FI), which is what makes them useful as mutual backups.


### Cloudflare limits and how this build uses them

Cloudflare's current Workers Free limits are 100,000 requests/day, 10 ms CPU time/invocation, 128 MB memory, 50 subrequests/invocation, and 6 simultaneous outgoing connections per invocation. Free requests reset at midnight UTC, and Cloudflare also applies a burst limit to Free accounts (documented as 1,000 requests per minute at the time of writing). Cache API calls share the subrequest quota; check the current Cloudflare Workers Limits documentation for the exact per-request numbers, which Cloudflare has changed before. This Worker makes at most one Cache API `match` and one `put` per request (plus a best-effort background `delete` when it purges an expired or corrupt entry). An L2 hit does not write back to the cache. A stored entry whose bookkeeping headers are missing, invalid or expired is purged without its body being read.

This Worker deliberately stays far below those ceilings on ordinary DNS traffic:

| Path | Cache API | HaGeZi upstreams |
|---|---:|---:|
| L1 cache hit | 0 | 0 |
| L2 cache hit | 1 | 0 |
| Cold cache miss | 1 match + 1 async put (only if the answer is cacheable) | normally 1 |
| Slow/failing recovery | 1 match + 1 async put (only if the answer is cacheable) | at most 3 |

The resolver logic never launches all three upstreams immediately. In-flight duplicate work is bounded at 128 entries: the in-flight entry for a cache key is registered synchronously before the L2 lookup, so concurrent cold-cache misses for the same question coalesce onto a single upstream job instead of each spawning duplicate subrequests. The job is detached from the request that started it with `ctx.waitUntil`, so it still settles (releasing every waiting request and removing its in-flight entry) if that request is cancelled, for example because its client disconnected. A request that joins another request's job waits at most 4 s (longer than the 3.6 s worst case of three sequential upstream timeouts, so joiners never duplicate a degraded resolution); after that, or when the in-flight entry is already older than 4 s, it resolves on its own. Upstream response buffering is capped at 65,535 bytes to reduce worst-case memory pressure. It starts with one learned/rotated HaGeZi endpoint, hedges to a backup only when latency or failure justifies it, and uses the third endpoint only as last-resort recovery. Maximum concurrent upstream connections from this Worker are therefore 3, below Cloudflare's limit of 6.

#### Resolver selection and hedging

- Upstream queries are sent as RFC 8484 `GET` requests (`?dns=` base64url) with `redirect: 'manual'`, so a redirect is never followed to another host: a `3xx` counts as a resolver failure. (`redirect: 'error'` is not implemented by the Workers runtime and makes every fetch throw. A `GET` is used because aborting a `POST` with a request body makes the runtime log an uncaught abort error.)
- Each resolver starts with a score of 100 (range 0-100). A usable answer (`NOERROR`/`NXDOMAIN`) gives +1. A transport or validation failure (HTTP error, redirect, too-short, oversized or malformed message, query instead of response, transaction-ID mismatch) gives -12, and a timeout gives -8. A truncated (TC) answer or an error RCODE such as `SERVFAIL` or `REFUSED` gives -12 only when another resolver returns a usable answer for the same query. If every attempted resolver returns an error RCODE or a truncated answer, the domain is treated as the problem and no resolver is penalised. An attempt that is still running when a later-started backup wins is aborted, gives -2 and is counted in the `slow` counter (not as a failure or timeout); its elapsed time can only raise its learned latency. The Worker validates each upstream response structurally: length, QR bit, transaction ID, at most one question, and an echoed question that matches the query's QNAME (case-insensitively), QTYPE and QCLASS. A `NOERROR` or `NXDOMAIN` answer must carry the question, because it would be unverifiable and unsafe to cache under the query's key; it is otherwise treated as a resolver failure and the next resolver is tried. Only other error responses (`SERVFAIL`, `REFUSED`, ...) may omit it. Every declared answer/authority/additional record must be complete, compression pointers must point backwards at a well-formed name, and the message must end exactly where its declared sections end. Error responses must still have well-formed records and no trailing bytes. EDNS OPT is accepted only once, in the additional section, with a root owner name; its extended RCODE bits are included in the RCODE check. The 255-byte name limit covers labels reached through compression pointers. Remaining edge cases: a pointer is checked to land on a parseable name, not on a verified record boundary, and RDATA contents other than SOA are not interpreted.
- The first-choice pool holds the resolvers scoring strictly more than 8 points below the best one, so a single timeout (-8) removes a resolver from it. Inside the pool, the resolver with the lowest learned latency (EWMA) goes first; every 10th upstream resolution another pool member goes first so its latency estimate stays current. Resolvers outside the pool follow in score/latency order.
- A backup is started if the first attempt has not answered after `1.5 x` its learned latency (clamped to 80-220 ms, so the 120 ms assumed before any sample gives 180 ms) or as soon as it fails. The last-resort resolver is started after a further 150 ms, or immediately when the first two have both failed. The delay timer restarts whenever any attempt settles, so these delays are measured from the most recent event rather than from the start of the request.
- Each upstream attempt is aborted after 1200 ms. A truncated (TC) answer is treated as unusable so that a resolver returning a complete answer wins. If no resolver produces a usable answer but at least one returned a DNS message, the best fallback is relayed: truncated `NOERROR`, then truncated `NXDOMAIN`, then `SERVFAIL`, then other RCODEs. It is relayed to the client (`x-dns-degraded: 1`); if none returns a DNS message at all, the client gets `502`.
- Scores recover over time by +1 per minute up to 100, so one transient failure cannot keep a resolver out of the first-choice pool indefinitely. `/health` applies this recovery before reporting scores. A broken domain that makes every resolver return `SERVFAIL` (or another error RCODE, or a truncated answer) does not lower any score.
- Scores, counters, the L1 cache and the in-flight table live in each isolate's memory. They are not shared between isolates or data centers, and `/health` shows only the state of the isolate that answered it.

### Two-level DNS cache

The Worker intentionally does **not** enable the global Workers Cache feature in `wrangler.toml`. That feature can return a cached response without executing the Worker, which would put the cache in front of the `/dns-query` rate limiter. Instead, the Worker uses the Cache API after rate limiting, so every `/dns-query` request still reaches the rate-limit check.

The Cache API is data-center-local and does not replicate entries automatically between data centers. It is also generally not effective on `*.workers.dev` hostnames, so deploy on a custom domain/route to get L2 hits; on `workers.dev` the Worker still works and simply relies on L1 plus upstream resolution. That is still useful for hot DNS traffic because repeated queries at the same edge location can avoid an upstream lookup entirely.

Both DoH GET and POST requests use the same cache key: the DNS wire query with the transaction ID set to 0, the question name lower-cased, and every EDNS Padding option (RFC 7830) replaced by an empty one. Padding length never splits the cache, but whether the client asked for padding does, because padded responses are meant only for padding clients. Flags, the question type/class and every other EDNS option remain part of the key. L1 and the in-flight table use these key bytes directly (no hashing on the hot path); the L2 Cache API URL uses the first 128 bits of their SHA-256, computed only after an L1 miss. EDNS Cookies deliberately stay in the key: a response echoes the client's cookie, so sharing it with another client would be wrong. ASCII QNAME case is normalized (question names are always uncompressed here, because queries with a compressed question name are rejected before the cache key is computed), so `example.com`, `EXAMPLE.com`, and mixed-case variants can share a cache entry. Therefore the same DNS question can share a cache entry across GET and POST. Every response, including a fresh answer and a coalesced one, is built from a copy of the shared answer with the requesting client's transaction ID and exact question letter case, so DNS 0x20-style case randomization still validates and the cached copy is never modified.

Only DNS answers that are safe to reuse are cached: `NOERROR` and `NXDOMAIN` responses that are not truncated (TC) and are at most 65,535 bytes. Negative answers (`NXDOMAIN`/`NODATA`) are cached only when they carry an SOA record. Any response with an authority-section SOA, including a `NOERROR` CNAME chain that ends in NODATA, is capped by the SOA `MINIMUM` field, per RFC 2308. Record TTLs with the top bit set are treated as 0 (RFC 2181), so such answers are not cached; the SOA `MINIMUM` field gets the same treatment. The cache TTL is the minimum across all non-OPT records in the answer, authority and additional sections, so a short-lived record in any section cannot be over-cached. `SERVFAIL`, `REFUSED` and similar responses are relayed to the client (marked `x-dns-degraded: 1`) but never cached.

Responses cached internally use DNS TTL-derived expiration. The response transaction ID is rewritten for each client, and cached DNS record TTLs are reduced by cache age before being returned; for an authority-section SOA, the Worker serves `min(SOA TTL, SOA MINIMUM) - age` as the SOA record TTL. It never modifies SOA `MINIMUM` or other RDATA, because RRSIG signatures cover RDATA and changing it would break DNSSEC validation. An L2 hit is not written back: the entry simply expires at its original time and is then re-resolved (a hit is promoted to L1 with its remaining TTL). `Cache-Control: no-store` remains on the client-facing response so the Worker controls the DNS cache instead of creating an uncontrolled browser/HTTP cache layer.

### Rate limiting

`/dns-query` is limited to **100 requests per 60 seconds per client IP** through the native `DNS_RATE_LIMITER` binding in `wrangler.toml` (Cloudflare only accepts a period of 10 or 60 seconds). The check runs before the method, size and format checks, so rejected or malformed requests also count against the limit; `/health` and the dashboard are not rate limited. A lightweight per-isolate fallback limiter (fixed 60 s window, 100 requests per IP, at most 2048 tracked IPs, least-recently-used eviction, at most 256 penalty entries) is used when the binding is missing, throws, or returns an invalid response (the request is then limited locally rather than rejected or allowed unconditionally). The client IP is taken from `CF-Connecting-IP`; requests without it share one `unknown` bucket. Cloudflare documents the native Rate Limiting API as low-latency; its counters are scoped to the relevant Cloudflare location rather than being one globally exact counter.

### Request-size protection

DoH DNS messages are normally tiny, so this Worker rejects client messages larger than 4 KiB. It checks `Content-Length` before reading a POST when available and also stream-limits chunked/unknown-length bodies; a GET `dns` parameter longer than 5,462 characters (the base64url encoding of a 4 KiB message) is rejected before decoding. Upstream resolver responses are independently capped at **65,535 bytes** (the DNS wire-format maximum) and are stream-limited before buffering. These limits avoid spending memory/CPU on oversized abuse traffic while still allowing large legitimate DNSSEC/EDNS answers.

### Query validation

Before any cache or upstream work, the Worker checks that the client message is a plausible single-question DNS query: at least 12 bytes, QR bit clear, opcode 0, `QDCOUNT` = 1 with no answer or authority records, and a complete, well-formed question name (labels of at most 63 bytes, at most 255 bytes on the wire) followed by 4 bytes of type/class. Any `ARCOUNT` additional records are then walked and must be complete: a single valid EDNS OPT record (root owner name) is accepted, provided its options (code, length, data) tile the OPT RDATA exactly, while a wrong `ARCOUNT`, a truncated or duplicate OPT record, an option whose length overruns the RDATA (or a dangling partial option header), or undeclared trailing bytes are rejected with `400` before any cache or upstream work, so malformed requests no longer cost resolvers a score penalty. A **compression pointer in the question name is rejected with `400`**: a query's only question has nothing earlier to point to, so a pointer is never valid, and forwarding it would make all three resolvers answer `FORMERR` and lower every resolver score by 12 for a single malformed request. Compression pointers remain supported when the Worker parses *responses*.

## Deploy with Wrangler

The repository includes `wrangler.toml` with the service name `secure-doh-worker` and a `DNS_RATE_LIMITER` binding configured for **100 requests / 60 seconds**. With Wrangler (version 4.36.0 or later is required for the `[[ratelimits]]` binding syntax used here), deploy from the folder containing `Worker.js` and `wrangler.toml` so the binding is created/used. Keep the rate-limit namespace unique if this service must not share counters with another deployment. If the Worker is uploaded through a method that does not apply the Wrangler binding, the script falls back to an in-memory per-isolate limiter.

For strict network-wide abuse protection, a Cloudflare WAF Rate Limiting Rule can also be applied to `/dns-query`. Cloudflare notes that rate-limit counters are not globally shared across its entire network, so neither the native binding nor WAF should be treated as one globally exact counter.

```bash
npx wrangler deploy
```

## Endpoint

After deployment:

```txt
https://YOUR-DOMAIN.example/dns-query
```

| Path | Purpose |
|---|---|
| `/dns-query` | DoH endpoint (GET and POST), rate limited. Sends `Access-Control-Allow-Origin: *` so browser-based DoH clients can use it; `OPTIONS` preflight is answered with `204` before the rate limiter |
| `/health` | JSON status: version, resolver scores and `ok`/`fail`/`timeout`/`slow` counters, L1 entry/byte counters, in-flight/throttle counters, limits |
| `/`, `/index.html` | Setup dashboard (EN / FA / ZH). Its Tailwind utilities are pre-compiled and inlined in a `<style>` block (no external CDN dependency); a unit test checks that escaped selectors such as `.md\:p-12` survive the JavaScript template literal; the DoH endpoint itself does not depend on it. Served with a restrictive Content-Security-Policy that includes `frame-ancestors 'none'`, so the page cannot be embedded in a frame. The endpoint URL is built once at module load and cached, so repeat requests to `/` do not rebuild the template |
| anything else | `404` |

`/dns-query` status codes: `200` DNS message, `204` CORS preflight (`OPTIONS`), `400` malformed query (including a compressed question name, malformed EDNS options/additional records or trailing bytes), invalid base64url, or missing `dns` parameter, `405` method other than GET/POST/OPTIONS, `413` message larger than 4 KiB (or a GET `dns` parameter longer than 5,462 characters), `415` POST without `application/dns-message`, `429` rate limit exceeded (`Retry-After: 60`), `502` all upstreams failed (the `x-upstreams` header counts the attempts made by *this* request: a request that joined another request's failed in-flight resolution reports `0`). The rate-limit check runs first (except for `OPTIONS`), so a client over the limit receives `429` even when its request would otherwise have been a `405`, `400` or `413`.

## DoH methods

### GET

Standard RFC 8484-style GET requests use the `dns` base64url query parameter:

```txt
/dns-query?dns=BASE64URL_DNS_PACKET
```

### POST

Send the raw DNS wire-format packet with:

```txt
Content-Type: application/dns-message
```

## Cloudflare Worker notes

The L1 cache is a per-isolate LRU capped at 512 entries and 8 MiB of DNS message bodies, with lifetime capped at 300 s or the record's remaining TTL, whichever is shorter. It also stores the parsed TTL offsets, so an L1 hit copies and patches the response without walking its DNS names again. Entries found in L2 are promoted to L1 using their *remaining* TTL, so hot long-TTL names are served from memory even when the L2 entry is older than 300 s. Identical concurrent cache misses within one isolate share a single upstream resolution (at most 128 distinct keys tracked at once); if that resolution fails, every waiting request receives a `502`. If it does not settle within 4 s, waiting requests resolve on their own instead of hanging. L2 Cache API entries can honor authoritative TTLs up to 24 hours, reducing unnecessary upstream resolutions for long-lived DNS records. The per-isolate state (L1 cache, in-flight table, resolver scores, fallback limiter) is lost when the isolate is recycled. Correctness never depends on the Cache API: if L2 is unavailable, misses, or fails, requests fall through to the upstream resolvers. Expired isolate-local cache and throttle entries are swept periodically so `/health` does not retain stale bounded state indefinitely.

For a production deployment, attach the Worker to a custom domain and use:

```txt
https://dns.yourdomain.com/dns-query
```

`/health` is public and unauthenticated. It exposes resolver scores and cache counters but no client data; restrict it with a WAF rule if you prefer not to publish it.

## Testing

### Unit tests

Run the included Node.js unit tests from the project folder. Use Node.js 22 or newer (Node.js 20 can run the current suite but is end-of-life and is not tested in CI; Wrangler itself requires Node.js 22): the suite loads `Worker.js` through `worker-harness.mjs` and relies on stable web-standard globals (`Request`/`Response` with streamed bodies, `ReadableStream`, `AbortSignal.any`) together with the `node --test` runner. The project ships a minimal `package.json` with `"type": "module"`, so the module type is explicit — no module-syntax detection (or `--experimental` flags) is needed.

```bash
npm test        # or: node --test
```

The suite (113 tests) mocks `fetch` and the Cache API, so it needs no network or Cloudflare account. Test-only hooks live in `worker-harness.mjs`, which appends them to a temporary copy of `Worker.js` and deletes that copy once it is imported; the deployed Worker exports only its default fetch handler. Coalescing tests wait on the harness's joiner counter instead of fixed sleeps. CI also runs `node --check Worker.js` and `npm run check` (`wrangler deploy --dry-run` with Wrangler pinned to 4.151.0) to validate the bundle and `wrangler.toml` without deploying.

### Verifying a deployment

Send the RFC 8484 sample query (`www.example.com`, type A) with GET:

```bash
curl -s -D - -o /dev/null -H 'accept: application/dns-message' \
  'https://YOUR-DOMAIN.example/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB'
```

A healthy request returns:

```txt
HTTP 200
Content-Type: application/dns-message
```

Useful response headers include:

```txt
x-cache: L1-HIT / L2-HIT / COALESCED / MISS
x-edge-cache: HIT / MISS / SKIP / DISABLED   (DISABLED only if EDGE_CACHE_ENABLED is set to false in CONFIG)
x-upstreams: 0 / 1 / 2 / 3
x-winner: <HaGeZi-upstream-url>      (MISS, and COALESCED when the shared request went upstream)
x-winner-lat: <latency>               (MISS, and COALESCED when the shared request went upstream)
x-dns-degraded: 1   (only when no resolver gave a usable answer: SERVFAIL/REFUSED/etc., or a truncated NOERROR/NXDOMAIN fallback)
```

The `/health` endpoint reports the Worker version, the three resolver scores, and L1/L2 cache, in-flight and rate-limit state for the isolate that served it.

## Important limitation

This is **DNS encryption**, not a VPN. It protects DNS traffic between the client and this Worker, but it does not hide destination IP addresses or guarantee bypass of IP, SNI, TLS, QUIC, or other network-level filtering.

## 🖥️ **Live Demo For This Project :** [Secure DNS over HTTPS](https://dns.mydoh.workers.dev/).

## Credits

Based on [Secure DNS over HTTPS Cloudflare Worker](https://github.com/TheGreatAzizi/Secure-DNS-over-HTTPS-Cloudflare-Worker) by M.M.Azizi (MIT). The original copyright notice is retained in [`LICENSE`](LICENSE).

## 🔗 Related projects (not part of this repository)

The services below are maintained separately and are **not** part of this repository, its build pipeline, or its release cycle. They are listed here for convenience only.

### 🌐 Free DNS Services

High-performance DNS utilizing HaGeZi Blocklists (Multi Pro + TIF).

| Blocklist | DNS-over-HTTPS (DoH) |
| :--- | :--- |
| Multi Pro + TIF | `https://freedns.koyeb.app/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dns.mydoh.workers.dev/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dns-pi.vercel.app/api/doh/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dnssix.netlify.app/api/doh/dns-query` |
| Multi Pro + TIF | `https://dns-93aca.containers.snapdeploy.app/dns-query` |
| Multi Pro + TIF | `https://doh-93aca.containers.snapdeploy.app/dns-query` |

### ⚡ Bandwidth Hero Server

A lightweight image optimization proxy designed to slash bandwidth usage and accelerate web browsing.

Bandwidth Hero Server fetches remote images, compresses them on the fly, and delivers optimized versions to the client. This significantly reduces data consumption while improving page load performance.

🖥️ **Live Demo:** [Bandwidth Hero](https://bhserv.netlify.app/).

## Supporting the Project

If you find this project useful, donations are appreciated:

- **Bitcoin**: `1HntwKxyqGCfnSGvGLMUTRAqLnTvLarAQP`

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md).

## License

See [`LICENSE`](LICENSE).
