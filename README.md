# 🛡️ DoH — Cloudflare Worker

A lightweight Cloudflare Worker that exposes a standard **DNS-over-HTTPS** endpoint, uses three HaGeZi resolvers with intelligent staged failover, and keeps a two-level DNS cache:

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

Cloudflare's current Workers Free limits are 100,000 requests/day, 10 ms CPU time/invocation, 128 MB memory, 50 subrequests/invocation, and 6 simultaneous outgoing connections per invocation. Free requests reset at midnight UTC, and Cloudflare also applies a burst limit to Free accounts (documented as 1,000 requests per minute at the time of writing). Cache API calls share the subrequest quota; check the current Cloudflare Workers Limits documentation for the exact per-request numbers, which Cloudflare has changed before. This Worker makes at most one Cache API `match` and one `put` per request.

This Worker deliberately stays far below those ceilings on ordinary DNS traffic:

| Path | Cache API | HaGeZi upstreams |
|---|---:|---:|
| L1 cache hit | 0 | 0 |
| L2 cache hit | 1 | 0 |
| Cold cache miss | 1 match + 1 async put (only if the answer is cacheable) | normally 1 |
| Slow/failing recovery | 1 match + 1 async put (only if the answer is cacheable) | at most 3 |

The resolver logic never launches all three upstreams immediately. In-flight duplicate work is bounded at 128 entries: the in-flight entry for a cache key is registered synchronously before the L2 lookup, so concurrent cold-cache misses for the same question coalesce onto a single upstream job instead of each spawning duplicate subrequests. Upstream response buffering is capped at 65,535 bytes to reduce worst-case memory pressure. It starts with one learned/rotated HaGeZi endpoint, hedges to a backup only when latency or failure justifies it, and uses the third endpoint only as last-resort recovery. Maximum concurrent upstream connections from this Worker are therefore 3, below Cloudflare's limit of 6.

#### Resolver selection and hedging

- Each resolver starts with a score of 100 (range 0-100). A usable answer (`NOERROR`/`NXDOMAIN`) gives +1, a failure (HTTP error, response that is too short, oversized, not marked as a response or whose transaction ID does not match, or a `SERVFAIL`/`REFUSED`/other RCODE) gives -12, and a timeout gives -8. Aborting a slower attempt after another resolver won is not penalised. The Worker validates the response header only (length, QR bit, transaction ID); it does not compare the echoed question section with the query.
- The first resolver is chosen round-robin among resolvers whose score is within 8 points of the best one; the rest follow in score/latency order.
- A backup is started if the first attempt has not answered after `1.5 x` its learned latency (clamped to 80-220 ms, so the 120 ms assumed before any sample gives 180 ms) or as soon as it fails. The last-resort resolver is started after a further 150 ms, or immediately when the first two have both failed. The delay timer restarts whenever any attempt settles, so these delays are measured from the most recent event rather than from the start of the request.
- Each upstream attempt is aborted after 1200 ms. If no resolver produces a usable answer but at least one returned a DNS message with an error code such as `SERVFAIL`, the last such answer is relayed to the client (`x-dns-degraded: 1`); if none returns a DNS message at all, the client gets `502`.
- Scores only change when a resolver is actually queried; there is no time-based recovery. A resolver that falls more than 8 points behind the best one is no longer picked first and regains points only when it is used as a backup. A `SERVFAIL` for a genuinely broken domain makes the Worker try all three resolvers and lowers all three scores by 12; the same applies to any other non-`NOERROR`/`NXDOMAIN` answer, such as a `FORMERR` for a query that passed the Worker's structural checks but that the resolvers reject.
- Scores, counters, the L1 cache and the in-flight table live in each isolate's memory. They are not shared between isolates or data centers, and `/health` shows only the state of the isolate that answered it.

### Two-level DNS cache

The Worker intentionally does **not** enable the global Workers Cache feature in `wrangler.toml`. That feature can return a cached response without executing the Worker, which would put the cache in front of the `/dns-query` rate limiter. Instead, the Worker uses the Cache API after rate limiting, so every `/dns-query` request still reaches the rate-limit check.

The Cache API is data-center-local and does not replicate entries automatically between data centers. It is also generally not effective on `*.workers.dev` hostnames, so deploy on a custom domain/route to get L2 hits; on `workers.dev` the Worker still works and simply relies on L1 plus upstream resolution. That is still useful for hot DNS traffic because repeated queries at the same edge location can avoid an upstream lookup entirely.

Both DoH GET and POST requests use the same cache key: the first 128 bits of the SHA-256 of the DNS wire query, with only the transaction ID normalized (all EDNS options, flags and the question type/class remain part of the key, so clients that add a per-query EDNS cookie or variable-length padding produce different keys and get fewer cache hits). ASCII QNAME case is also normalized (question names are always uncompressed here, because queries with a compressed question name are rejected before the cache key is computed), so `example.com`, `EXAMPLE.com`, and mixed-case variants can share a cache entry. Therefore the same DNS question can share a cache entry across GET and POST. When a cached answer is served, the question section is rewritten to the exact letter case the requesting client sent, so DNS 0x20-style case randomization still validates.

Only DNS answers that are safe to reuse are cached: `NOERROR` and `NXDOMAIN` responses that are not truncated (TC) and are at most 65,535 bytes. Negative answers (`NXDOMAIN`/`NODATA`) are cached only when they carry an SOA record; the TTL is the smaller of the lowest authority-section record TTL (which includes the SOA TTL) and the SOA `MINIMUM` field, per RFC 2308. Record TTLs with the top bit set are treated as 0 (RFC 2181), so such answers are not cached; the SOA `MINIMUM` field gets the same treatment. For positive (`NOERROR`) answers the cache TTL is the minimum across all sections present in the response (answer, authority and additional, excluding OPT), not just the answer section, so a short-lived authority record cannot be over-cached. `SERVFAIL`, `REFUSED` and similar responses are relayed to the client (marked `x-dns-degraded: 1`) but never cached.

Responses cached internally use DNS TTL-derived expiration. The response transaction ID is rewritten for each client, and cached DNS record TTLs are reduced by cache age before being returned. An L2 hit also refreshes the edge entry (re-`put` with its remaining TTL), so hot keys do not lapse into avoidable re-resolutions as their TTL runs down. `Cache-Control: no-store` remains on the client-facing response so the Worker controls the DNS cache instead of creating an uncontrolled browser/HTTP cache layer.

### Rate limiting

`/dns-query` is limited to **100 requests per 60 seconds per client IP** through the native `DNS_RATE_LIMITER` binding in `wrangler.toml` (Cloudflare only accepts a period of 10 or 60 seconds). The check runs before the method, size and format checks, so rejected or malformed requests also count against the limit; `/health` and the dashboard are not rate limited. A lightweight per-isolate fallback limiter (fixed 60 s window, 100 requests per IP, at most 2048 tracked IPs, least-recently-used eviction) is used when the binding is missing, throws, or returns an invalid response (the request is then limited locally rather than rejected or allowed unconditionally). Two details matter for the fallback path: requests rejected as over-limit do **not** refresh their entry's LRU position, so a flooding client cannot keep itself hot in the table and evict legitimate IPs; and windows evicted by a table overflow are retained in a small (256-entry) penalty map, so flooding the table (e.g. by rotating IPv6 addresses within a /64) cannot hand a client a fresh 100-request window. The client IP is taken from `CF-Connecting-IP`; requests without it share one `unknown` bucket. Cloudflare documents the native Rate Limiting API as low-latency; its counters are scoped to the relevant Cloudflare location rather than being one globally exact counter.

### Request-size protection

DoH DNS messages are normally tiny, so this Worker rejects client messages larger than 4 KiB. It checks `Content-Length` before reading a POST when available and also stream-limits chunked/unknown-length bodies. Upstream resolver responses are independently capped at **65,535 bytes** (the DNS wire-format maximum) and are stream-limited before buffering. These limits avoid spending memory/CPU on oversized abuse traffic while still allowing large legitimate DNSSEC/EDNS answers.

### Query validation

Before any cache or upstream work, the Worker checks that the client message is a plausible single-question DNS query: at least 12 bytes, QR bit clear, opcode 0, `QDCOUNT` = 1 with no answer or authority records, and a complete, well-formed question name (labels of at most 63 bytes, at most 255 bytes on the wire) followed by 4 bytes of type/class. A **compression pointer in the question name is rejected with `400`**: a query's only question has nothing earlier to point to, so a pointer is never valid, and forwarding it would make all three resolvers answer `FORMERR` and lower every resolver score by 12 for a single malformed request. Compression pointers remain supported when the Worker parses *responses*.

## Deploy with Wrangler

The ZIP includes `wrangler.toml` with the service name `secure-doh-worker` and a `DNS_RATE_LIMITER` binding configured for **100 requests / 60 seconds**. With Wrangler (version 4.36.0 or later is required for the `[[ratelimits]]` binding syntax used here), deploy from the folder containing `Worker.js` and `wrangler.toml` so the binding is created/used. Keep the rate-limit namespace unique if this service must not share counters with another deployment. If the Worker is uploaded through a method that does not apply the Wrangler binding, the script falls back to an in-memory per-isolate limiter.

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
| `/dns-query` | DoH endpoint (GET and POST), rate limited |
| `/health` | JSON status: version, resolver scores, cache/in-flight/throttle counters, limits |
| `/`, `/index.html` | Setup dashboard (EN / FA / ZH). Its Tailwind utilities are pre-compiled and inlined in a `<style>` block (no external CDN dependency); the DoH endpoint itself does not depend on it. Served with a restrictive Content-Security-Policy that includes `frame-ancestors 'none'`, so the page cannot be embedded in a frame |
| anything else | `404` |

`/dns-query` status codes: `200` DNS message, `400` malformed query (including a compressed question name) or missing `dns` parameter, `405` method other than GET/POST, `413` message larger than 4 KiB (or a GET `dns` parameter longer than 5,462 characters), `415` POST without `application/dns-message`, `429` rate limit exceeded (`Retry-After: 60`), `502` all upstreams failed (the `x-upstreams` header counts the attempts made by *this* request: a request that joined another request's failed in-flight resolution reports `0`). The rate-limit check runs first, so a client over the limit receives `429` even when its request would otherwise have been a `405`, `400` or `413`.

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

The L1 cache is a per-isolate LRU (512 entries, lifetime capped at 300 s or the record's remaining TTL, whichever is shorter). Entries found in L2 are promoted to L1 using their *remaining* TTL, so hot long-TTL names are served from memory even when the L2 entry is older than 300 s. Identical concurrent cache misses within one isolate share a single upstream resolution; if that resolution fails, every waiting request receives the same `502`. L1 is checked again after an L2 miss, so a request that waited on the Cache API while another request filled L1 is answered from memory (`x-cache: L1-HIT`) instead of starting a redundant upstream query. L2 Cache API entries can honor authoritative TTLs up to 24 hours, reducing unnecessary upstream resolutions for long-lived DNS records. The per-isolate state (L1 cache, in-flight table, resolver scores, fallback limiter) is lost when the isolate is recycled. Correctness never depends on the Cache API: if L2 is unavailable, misses, or fails, requests fall through to the upstream resolvers. Expired isolate-local cache and throttle entries are swept periodically so `/health` does not retain stale bounded state indefinitely.

For a production deployment, attach the Worker to a custom domain and use:

```txt
https://dns.yourdomain.com/dns-query
```

`/health` is public and unauthenticated. It exposes resolver scores and cache counters but no client data; restrict it with a WAF rule if you prefer not to publish it.

## Testing

### Unit tests

Run the included Node.js unit tests from the project folder. Use Node.js 22 or newer: the suite imports `Worker.js` directly and relies on stable web-standard globals (`Request`/`Response` with streamed bodies, `ReadableStream`, `AbortSignal.any`) together with the `node --test` runner. The project ships a minimal `package.json` with `"type": "module"`, so the module type is explicit — no module-syntax detection (or `--experimental` flags) is needed.

```bash
npm test        # or: node --test
```

The suite (47 tests) mocks `fetch` and the Cache API, so it needs no network or Cloudflare account.

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
x-winner: <haGeZi-upstream-url>      (MISS and COALESCED only)
x-winner-lat: <latency>               (MISS and COALESCED only)
x-dns-degraded: 1   (only when the answer is SERVFAIL/REFUSED/etc.)
```

The `/health` endpoint reports the Worker version, the three resolver scores, and L1/L2 cache, in-flight and rate-limit state for the isolate that served it.

## Important limitation

This is **DNS encryption**, not a VPN. It protects DNS traffic between the client and this Worker, but it does not hide destination IP addresses or guarantee bypass of IP, SNI, TLS, QUIC, or other network-level filtering.

## 🖥️ **Live Demo For This Project :** [Secure DNS over HTTPS](https://dns.mydoh.workers.dev/).

## Credits

Based on [Secure DNS over HTTPS Cloudflare Worker](https://github.com/TheGreatAzizi/Secure-DNS-over-HTTPS-Cloudflare-Worker) by M.M.Azizi (MIT).

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
