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

No other DNS upstreams or resolver profiles are used.


### Cloudflare limits and how this build uses them

Cloudflare's current Workers Free limits are 100,000 requests/day, 10 ms CPU time/invocation, 128 MB memory, 50 subrequests/invocation, and 6 simultaneous outgoing connections per invocation. Free requests reset at midnight UTC. Cache API calls are also counted against the subrequest quota, with 50 Cache API calls/request on Free. See the Cloudflare Workers Limits documentation.

This Worker deliberately stays far below those ceilings on ordinary DNS traffic:

| Path | Cache API | HaGeZi upstreams |
|---|---:|---:|
| L1 cache hit | 0 | 0 |
| L2 cache hit | 1 | 0 |
| Cold cache miss | 1 match + 1 async put | normally 1 |
| Slow/failing recovery | 1 match + 1 async put | at most 3 |

The resolver logic never launches all three upstreams immediately. It starts with one learned/rotated HaGeZi endpoint, hedges to a backup only when latency or failure justifies it, and uses the third endpoint only as last-resort recovery. Maximum concurrent upstream connections from this Worker are therefore 3, below Cloudflare's limit of 6.

### Two-level DNS cache

The Worker intentionally does **not** enable the global Workers Cache feature in `wrangler.toml`. That feature can return a cached response without executing the Worker, which would put the cache in front of the `/dns-query` rate limiter. Instead, the Worker uses the Cache API after rate limiting, so every `/dns-query` request still reaches the rate-limit check.

The Cache API is data-center-local and does not replicate entries automatically between data centers. It is also generally not effective on `*.workers.dev` hostnames, so deploy on a custom domain/route to get L2 hits; on `workers.dev` the Worker still works and simply relies on L1 plus upstream resolution. That is still useful for hot DNS traffic because repeated queries at the same edge location can avoid an upstream lookup entirely.

Both DoH GET and POST requests use the SHA-256-derived DNS wire-query key, with only the transaction ID normalized. ASCII QNAME case is also normalized when the question name is uncompressed, so `example.com`, `EXAMPLE.com`, and mixed-case variants can share a cache entry. Therefore the same DNS question can share a cache entry across GET and POST. When a cached answer is served, the question section is rewritten to the exact letter case the requesting client sent, so DNS 0x20-style case randomization still validates.

Only DNS answers that are safe to reuse are cached: `NOERROR` and `NXDOMAIN` responses that are not truncated (TC) and are at most 65,535 bytes. Negative answers (`NXDOMAIN`/`NODATA`) are cached only when they carry an SOA record, using `min(SOA TTL, SOA MINIMUM)` per RFC 2308. `SERVFAIL`, `REFUSED` and similar responses are relayed to the client (marked `x-dns-degraded: 1`) but never cached.

Responses cached internally use DNS TTL-derived expiration. The response transaction ID is rewritten for each client, and cached DNS record TTLs are reduced by cache age before being returned. `Cache-Control: no-store` remains on the client-facing response so the Worker controls the DNS cache instead of creating an uncontrolled browser/HTTP cache layer.

### Rate limiting

`/dns-query` is limited to **100 requests per 60 seconds per client IP** through the native `DNS_RATE_LIMITER` binding in `wrangler.toml`. A lightweight per-isolate fallback limiter is used when the binding is missing, throws, or returns an invalid response (the request is then limited locally rather than rejected or allowed unconditionally). Cloudflare documents the native Rate Limiting API as low-latency; its counters are scoped to the relevant Cloudflare location rather than being one globally exact counter.

### Request-size protection

DoH DNS messages are normally tiny, so this Worker rejects client messages larger than 4 KiB. It checks `Content-Length` before reading a POST when available and also stream-limits chunked/unknown-length bodies. Upstream resolver responses are independently capped at **256 KiB** and are stream-limited before buffering. These limits avoid spending memory/CPU on oversized abuse traffic while still allowing large legitimate DNSSEC/EDNS answers.

## Deploy with Wrangler

The ZIP includes `wrangler.toml` with the service name `secure-doh-worker` and a `DNS_RATE_LIMITER` binding configured for **100 requests / 60 seconds**. With Wrangler, deploy from the folder containing `Worker.js` and `wrangler.toml` so the binding is created/used. Keep the rate-limit namespace unique if this service must not share counters with another deployment. If the Worker is uploaded through a method that does not apply the Wrangler binding, the script falls back to an in-memory per-isolate limiter.

For strict network-wide abuse protection, a Cloudflare WAF Rate Limiting Rule can also be applied to `/dns-query`. Cloudflare notes that rate-limit counters are not globally shared across its entire network, so neither the native binding nor WAF should be treated as one globally exact counter.

```bash
npx wrangler deploy
```

## Endpoint

After deployment:

```txt
https://YOUR-DOMAIN.example/dns-query
```

The Worker also serves a small dashboard at `/`.

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

The L1 cache is a per-isolate LRU (512 entries, TTL capped at 300 s). Correctness never depends on the Cache API: if L2 is unavailable, misses, or fails, requests fall through to the upstream resolvers. Expired isolate-local cache and throttle entries are swept periodically so `/health` does not retain stale bounded state indefinitely.

For a production deployment, attach the Worker to a custom domain and use:

```txt
https://dns.yourdomain.com/dns-query
```

`/health` is public and unauthenticated. It exposes resolver scores and cache counters but no client data; restrict it with a WAF rule if you prefer not to publish it.

## Testing

Run the included Node.js unit tests from the project folder:

```bash
node --test test.mjs
```

A healthy request should return:

```txt
HTTP 200
Content-Type: application/dns-message
```

Useful response headers include:

```txt
x-cache: L1-HIT / L2-HIT / COALESCED / MISS
x-edge-cache: HIT / MISS / SKIP
x-upstreams: 0 / 1 / 2 / 3
x-winner: <haGeZi-upstream-url>
x-winner-lat: <latency>
x-dns-degraded: 1   (only when the answer is SERVFAIL/REFUSED/etc.)
```

The `/health` endpoint reports the three resolver scores plus L1/L2 cache and in-flight state.


## Important limitation

This is **DNS encryption**, not a VPN. It protects DNS traffic between the client and this Worker, but it does not hide destination IP addresses or guarantee bypass of IP, SNI, TLS, QUIC, or other network-level filtering.

## 🖥️ **Live Demo For This Project :** [Secure DNS over HTTPS](https://dns.mydoh.workers.dev/).

## Credits

Based on [Secure DNS over HTTPS Cloudflare Worker](https://github.com/TheGreatAzizi/Secure-DNS-over-HTTPS-Cloudflare-Worker) by M.M.Azizi (MIT).

## 🌐 Free DNS Services

High-performance DNS utilizing HaGeZi Blocklists (Multi Pro + TIF).

| Blocklist | DNS-over-HTTPS (DoH) |
| :--- | :--- |
| Multi Pro + TIF | `https://freedns.koyeb.app/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dns-pi.vercel.app/api/doh/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dnssix.netlify.app/api/doh/dns-query` |
| Multi Pro + TIF | `https://dns-93aca.containers.snapdeploy.app/dns-query` (Recommended, but will sleep if not used in 15 minutes) |
| Multi Pro + TIF | `https://doh-93aca.containers.snapdeploy.app/dns-query` (Recommended, but will sleep if not used in 15 minutes) |

## ⚡ Bandwidth Hero Server

A lightweight image optimization proxy designed to slash bandwidth usage and accelerate web browsing.

Bandwidth Hero Server fetches remote images, compresses them on the fly, and delivers optimized versions to the client. This significantly reduces data consumption while improving page load performance.

🖥️ **Live Demo:** [Bandwidth Hero](https://bhserv.netlify.app/).

## Supporting the Project

If you find this project useful, donations are appreciated:

- **Bitcoin**: `1HntwKxyqGCfnSGvGLMUTRAqLnTvLarAQP`

## License

See [`LICENSE`](LICENSE).
