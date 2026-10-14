# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.4.0] - 2026-10-15

### Fixed
- Cached negative answers no longer modify SOA `MINIMUM`. That field is signed
  RDATA, so changing it broke DNSSEC validation. The SOA record TTL is now served
  as `min(SOA TTL, SOA MINIMUM) - age`, as RFC 2308 requires.
- `NOERROR` CNAME chains ending in NODATA now honour the authority SOA
  `MINIMUM` instead of being cached for the CNAME/SOA TTL.
- IPv6 rate limiting uses one /64 key for the native binding and the local
  fallback, so rotating addresses within a /64 no longer gets fresh windows.
- The in-flight job is rejected in `finally` only when it was not already
  settled; successful requests no longer allocate an unused `Error`.
- Unexpected request-body errors return `Invalid DNS query` instead of exposing
  internal runtime messages.
- Fallback answers are chosen by usefulness: truncated `NOERROR` beats
  truncated `NXDOMAIN`, which beats `SERVFAIL` and other RCODEs.
- The 255-byte name limit is enforced across compression pointers.
- Responses with OPT outside the additional section, duplicate OPT records or a
  non-root OPT owner are rejected. Extended RCODE bits are included in usability
  and caching checks.
- Test fixture fix: the "truncated" response helper set RCODE 2 instead of the
  TC flag; it now sets TC correctly.

### Removed
- The L1 re-check after an L2 miss. Synchronous in-flight registration makes it
  unreachable in normal operation.
- The resolver-ranking cache. Every upstream result invalidated it, so the
  cached branch never ran.
- `EDGE_CACHE_MIN_TTL_SECONDS`, the redundant TTL floor/floor-rounding, and the
  `validateDNSResponse` pass-through wrapper.
- Test-only hooks from the production module. `Worker.js` now exports only the
  Worker handler; tests use `worker-harness.mjs`.
- Redundant dashboard panel-class toggling.

### Changed
- One validation pass now checks the DNS response, calculates cache TTL and
  records TTL offsets. L1 hits patch those offsets directly.
- Expired or corrupt L2 entries are purged with `ctx.waitUntil` instead of
  delaying the request.
- L1 has an 8 MiB body budget in addition to its 512-entry limit.
- Resolver scores recover by +1 per minute, up to 100. If all attempted
  resolvers return an error RCODE, none is penalised.
- EDNS Padding is removed from the cache key. EDNS Cookies stay in the key
  because cached responses echo client-specific cookies.
- Upstream timeouts use `AbortSignal.timeout`.
- Shared ASCII lower-casing and the parsed question end remove repeated
  question-name parsing.
- Dashboard HTML is split once around the endpoint placeholder; the clipboard
  fallback is feature-checked; iOS guidance no longer recommends Android-only
  Intra.
- CI uses current `actions/checkout@v7` and `actions/setup-node@v7`, checks
  syntax, and runs a Wrangler dry-run deployment.

### Tests
- 88 tests. The coalescing tests now prove that joiners attach to the leader
  (`COALESCED` and upstream call count), and new tests cover the fixes above,
  405, GET/Content-Length size guards, upstream timeouts, expired L1/L2 entries,
  native limiter exceptions, penalty eviction, the L1 byte budget and padding-
  insensitive cache keys.

