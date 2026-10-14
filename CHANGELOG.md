# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.9]

### Fixed
- Cold-cache race: the inflight entry is now registered synchronously *before*
  the L2 lookup, so concurrent misses for the same key coalesce onto one
  upstream job instead of each spawning duplicate subrequests.
- Positive-answer cache TTL now uses the minimum across answer, authority and
  additional sections (excluding OPT), per RFC-correct caching, instead of the
  answer section alone.
- SOA MINIMUM values with the MSB set are treated as 0 (RFC 2181), consistent
  with record TTL handling.
- Corrupt or expired L2 entries are deleted on read instead of being re-read
  until Cloudflare evicts them.
- Local rate limiter: rejected requests no longer re-touch the LRU entry, and
  windows evicted by a table overflow survive in a small penalty map, so
  flooding the table (e.g. IPv6 /64 scanning) cannot reset a client's window.
- `upstreamFailureResponse()` fallback attempt count is `0` instead of the
  resolver count, so a pathological pre-attempt throw no longer reports phantom
  attempts.
- `validateDNSResponse()` checks the QR bit before the ID, so a non-response no
  longer reports a misleading "ID mismatch".

### Changed
- The stored cache body keeps the upstream transaction ID and is rewritten per
  request; the miss path now performs zero buffer copies (one in-place QNAME
  case restore) instead of normalize-then-patch double copies.
- `selectRacers` caches its ranking and only re-sorts when scores change.
- The dashboard loads pre-compiled Tailwind utilities inlined in a `<style>`
  block instead of the ~300KB CDN JIT compiler; the CSP no longer allows
  cdn.tailwindcss.com.
- L2 hits refresh the edge entry (`cache.put`) so hot keys do not lapse into
  re-resolution.
- `maybeSweepState()` runs only on `/dns-query` and `/health`.
- Added `package.json` with `"type": "module"`; version bumped to 0.2.9.

### Removed (dead code)
- `normalizeDNSResponseID()` (superseded by per-request ID patching).
- `INFLIGHT_STALE_MS`, the unreachable inflight stale-sweep, and the
  `job.startedAt` plumbing.
- The redundant single-chunk copy in `readCappedBody()`.
- The `try/catch` around `ctx.waitUntil()` (it never throws synchronously).

### Tests
- 47 tests (was 42). Added: concurrent cold misses coalesce into one upstream
  job; SOA MINIMUM with MSB set is not cached; positive-answer TTL is the
  minimum across sections; corrupt L2 entries are purged; L2 hits refresh the
  edge entry. The LRU flood test now asserts that an evicted client's window
  survives (penalty map) instead of relying on re-touch timing. Resolver state
  is reset between tests via `__internals.resetResolverState()`.

