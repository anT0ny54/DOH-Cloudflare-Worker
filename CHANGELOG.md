# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.8]

### Fixed
- Malformed-query amplification: `parseDNSQuestion()` accepted a compression
  pointer inside the question name (for example a self-referencing `c0 0c`).
  Such a query was forwarded upstream, all three resolvers answered `FORMERR`,
  the Worker made 3 upstream requests and lowered every resolver score by 12 for
  one bad request, so a client could skew `/health` scores at will. A query's
  only question has nothing earlier to point to, so a pointer there is never
  valid; it is now rejected with `400` before any cache or upstream work.
  Pointers are still handled when parsing responses (`skipDNSName()` gained an
  `allowPointer` parameter, default `true`; the query parser passes `false`).
- Inconsistent `x-upstreams` on joined failures: a request that joined another
  request's failed in-flight resolution returned the leader's attempt count
  (e.g. `3`) although it sent no upstream query itself, while the success path
  (`COALESCED`) already reported `0`. It now reports `0`.

### Changed
- `upstreamFailureResponse()` takes the attempt count directly instead of an
  error object plus a fallback, which removes the `err.attempts || fallback`
  expression (it also treated a real count of `0` as "missing").
- `handleDNS()`: the two consecutive `if (!edgeHit)` / `if (edgeHit)` blocks are
  one `if / else`. Behaviour is unchanged.
- `patchDNSResponseForAge()` returns immediately for buffers shorter than a DNS
  header, before writing the transaction ID or touching the question section.
- Dashboard `Content-Security-Policy` adds `frame-ancestors 'none'` so the page
  cannot be embedded in a frame (clickjacking hardening). The DoH endpoint is
  unaffected.
- Version bumped to 0.2.8 (`VERSION` constant, reported by `/health` and shown
  in the dashboard footer).

### Removed (dead / redundant code)
- The `ttlSeconds` field in the object returned by the in-flight job in
  `handleDNS()`; nothing read it (the TTL is used locally to fill L1 and L2).
- The explicit `abortAttempts(controllers, winner)` call when a usable answer
  arrives, and its `winnerNode` parameter: the `finally` block of
  `resolveWithHedging()` runs immediately afterwards and aborts every attempt
  (the winner has already completed, so aborting it is a no-op). Observable
  behaviour, including the "aborting a slower attempt is not penalised" rule,
  is unchanged and now covered by a test.
- Trailing whitespace in `Worker.js`.

### Documentation
- README: new "Query validation" section; `400` status description mentions
  compressed question names; `502` description explains `x-upstreams` for
  joined failures; QNAME case-normalisation note updated; the scoring section
  notes that any non-`NOERROR`/`NXDOMAIN` answer (including `FORMERR`) counts as
  a failure; the dashboard row mentions the CSP; the Node.js requirement is
  stated as 22.7 or newer (module-syntax detection is on by default from 22.7);
  test count updated.

### Tests
- 42 tests (was 39). The old test "valid compressed question name is accepted
  structurally" asserted the buggy behaviour (and used a self-referencing
  pointer, which is not valid) and is replaced by "compression pointers in a
  query question name are rejected". Added: a compressed query returns `400`
  with no upstream call and no change in resolver scores; the slower attempt is
  aborted and not penalised once another resolver answers; the dashboard sends
  `frame-ancestors 'none'` and shows the new version. The joined-failure test
  now also asserts `x-upstreams` (`3` for the leader, `0` for the joiner), the
  version assertion expects 0.2.8, and a stale `262145` content-length in the
  oversized-response test (left over from an older 256 KiB limit) is now `65536`,
  the first value above the real limit. Tests 20, 22, 23, 30 and 42 fail against
  0.2.7.

### Reviewed, intentionally not changed
- The resolver-score caveats from 0.2.7 still apply: no time-based recovery, and
  `SERVFAIL`/`REFUSED` (and now documented `FORMERR`) answers lower a resolver's
  score even when the query or domain is at fault.
- The Worker still validates only the response header (length, QR, ID) and does
  not compare the echoed question section with the query. The upstreams are
  fixed HTTPS endpoints, so this is a hardening option rather than a defect.
- The rate-limit key is the full client IP. IPv6 clients can rotate addresses
  inside a /64, so a per-/64 key would be stricter; this changes limiter
  semantics and was left for the maintainer to decide.
- `/health` and `/` answer any HTTP method (only `/dns-query` checks it).
- `normalizeDNSResponseID()` copies the buffer and `patchDNSResponseForAge()`
  copies it again on a miss; both copies are at most 64 KiB and typical DNS
  answers are a few hundred bytes, so they were kept for clarity.
- `wrangler.toml`, `LICENSE` and the external Cloudflare limit figures quoted in
  the README were not modified or re-verified.

