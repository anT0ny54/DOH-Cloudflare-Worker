# 🛡️ DoH — Cloudflare Worker

A lightweight Cloudflare Worker that exposes a standard **DNS-over-HTTPS** endpoint and uses three HaGeZi resolvers with intelligent staged failover:

```txt
https://root.hagezi.org/dns-query
https://wurzn.hagezi.org/dns-query
https://juuri.hagezi.org/dns-query
```

No other DNS upstreams or resolver profiles are used.


### Cloudflare limits and how this build uses them

Cloudflare's current Workers Free limits are 100,000 inbound requests/day, 10 ms CPU time/invocation, 128 MB memory, 50 subrequests/invocation, 6 simultaneous outgoing connections/invocation, and 100 MB maximum request body size on the Free plan. The daily 100,000-request limit is an account-level platform limit and cannot be raised by Worker code. See the Cloudflare Workers Limits documentation.

This Worker intentionally uses at most **3 DNS upstream subrequests** for a single cache miss and normally uses **1**, so it is far below the 50-subrequest and 6-simultaneous-connection ceilings. Cache hits use **0** upstream subrequests.

The native Rate Limiting API is designed for low-latency enforcement. Its counters are local to the Cloudflare location and are eventually consistent.

## Deploy with Wrangler

The ZIP includes `wrangler.toml` with a `DNS_RATE_LIMITER` binding configured for **100 requests / 60 seconds**. With Wrangler, deploy from the folder containing `Worker.js` and `wrangler.toml` so the binding is created/used. If the Worker is uploaded through a method that does not apply the Wrangler binding, the script falls back to an in-memory per-isolate limiter.

For strict network-wide abuse protection, a Cloudflare WAF Rate Limiting Rule can also be applied to `/dns-query`. Cloudflare notes that rate-limit counters are not globally shared across its entire network, so neither the native binding nor WAF should be treated as one globally exact counter.

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

The Worker keeps a small in-memory cache per isolate. Cloudflare's Cache API is data-center-local rather than globally replicated, so this implementation deliberately does not depend on Cache API state for correctness.

For a production deployment, attach the Worker to a custom domain and use:

```txt
https://dns.yourdomain.com/dns-query
```

## Testing

A healthy request should return:

```txt
HTTP 200
Content-Type: application/dns-message
```

Useful response headers include:

```txt
x-cache: HIT / MISS
x-upstreams: 1 / 2 / 3
x-winner: <haGeZi-upstream-url>
x-winner-lat: <latency>
```

The `/health` endpoint reports the three resolver scores and basic Worker state.

## Important limitation

This is **DNS encryption**, not a VPN. It protects DNS traffic between the client and this Worker, but it does not hide destination IP addresses or guarantee bypass of IP, SNI, TLS, QUIC, or other network-level filtering.
