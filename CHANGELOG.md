# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Documentation
- README: added the missing request-size detail that a GET `dns` parameter
  longer than 5,462 characters is rejected before decoding; documented the
  fallback limiter's 256-entry penalty map; noted the 128-key bound on the
  in-flight coalescing table in the cache section; and mentioned that the
  dashboard template is built once and cached at module scope (a small CPU
  optimization for repeat visits to `/`).

### Verified
- Re-audit found no dead code, no redundant code, no conflicting logic, and
  no remaining defects. Every CONFIG key is used, every exported helper is
  referenced by tests, and all documentation matches implementation.

## [0.5.3] - 2026-10-17

### Fixed
- The in-flight join timeout (2.5 s) was shorter than the worst-case duration
  of the resolution a joiner waits for: three sequential upstream timeouts
  take 3 x 1200 ms = 3.6 s. When every upstream was degraded, each waiting
  request gave up at 2.5 s and started its own full three-upstream resolution,
  duplicating upstream traffic exactly when the upstreams were least able to
  absorb it. The join timeout is now 4 s, above that worst case. The comment
  that claimed a worst case of "~220 + 150 + 1200 ms" (the hedging path only)
  is corrected.

### Tests
- 113 tests (1 new): a joiner whose leader is still inside the
  three-sequential-timeout window attaches to it instead of forking a
  duplicate resolution. The new test fails against 0.5.2.

## [0.5.2] - 2026-10-15

### Fixed
- A query whose EDNS OPT record carried a malformed option list (an option
  length running past the end of the RDATA, or a dangling partial option
  header) passed `parseDNSQuestion()`, and then made `cacheKeyBytes()` throw.
  Nothing caught it, so `fetch()` threw and Cloudflare answered with an error
  page (HTTP 500, Worker exception) instead of `400`. The option framing is now
  validated with the rest of the OPT record and such a query is rejected with
  `400 Malformed EDNS options` before any cache or upstream work. A fuzz run
  over 300,000 mutated queries and 20,000 full `fetch()` round trips no longer
  produces an exception.

### Changed
- The `+`/`-` score update shared by `reward()`, `noteOvertaken()` and
  `penalize()` (clamp to `SCORE_MIN`..`SCORE_MAX`, restart the recovery clock)
  lives in one `adjustScore()` helper instead of three copies. Behaviour is
  unchanged.
- `validateDNSMessage()` no longer declares a second, shadowing `ttl` variable
  inside its record loop (renamed `recordTtl`), and the capped SOA `MINIMUM`
  is computed once instead of twice. Behaviour is unchanged.
- The `joiners` field of an in-flight entry is documented as test-harness
  bookkeeping: production code increments it but never reads it.
- The comment on `cacheKeyBytes()` no longer claims that `parseDNSQuestion()`
  validated OPT options before it actually did.
- Package and `/health` version bumped to 0.5.2.

### Tests
- 112 tests (4 new). Covers OPT option framing (exact fit, two options, overrun,
  partial header, trailing partial option), a guarantee that every query
  accepted by the parser has computable cache-key bytes, `400` instead of an
  exception for GET and POST with malformed options, and resolver scores
  staying within `SCORE_MIN`..`SCORE_MAX`. The first and third of these fail
  against 0.5.1.
