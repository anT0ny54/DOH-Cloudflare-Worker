# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.2] - 2026-10-15

### Fixed
- Cached negative answers (`NXDOMAIN`/`NODATA`) served from L1/L2 now also age
  the SOA `MINIMUM` field in the authority section. Previously only the SOA
  record TTL was reduced, so a client computing `min(TTL, MINIMUM)` (RFC 2308)
  could keep a negative answer for up to its full original lifetime again.
- The in-flight job for a cache key is now always settled when the request
  handler exits. If anything unexpected threw before the job was resolved,
  coalesced joiners previously awaited a promise that never settled; they now
  receive `502`.
- Scheduling the L2 write with `ctx.waitUntil` can no longer fail a request:
  the call is guarded (`runInBackground`).
- Corrected a misleading comment: the buffer restored in place on the miss
  path is shared with the L1 entry and coalesced joiners (harmless, because
  every response re-applies its own client's QNAME case).

### Changed
- **Removed the L2 "refresh on hit" write-back.** It re-`put` the entry with
  its remaining TTL, which expires at the same moment as the original entry,
  so it extended nothing while costing a Cache API subrequest on every L2 hit
  (and the age rounding could add sub-second drift on repeated refreshes). An
  L2 hit now performs one Cache API `match` and no `put`, matching the table
  in the README. Hot keys are still served from L1 after the first L2 hit.
- `patchDNSResponseForAge` makes one copy of the cached body instead of two
  and accepts either an `ArrayBuffer` or a `Uint8Array`; a shared
  `writeUint32` helper replaces the inline TTL byte writes.
- `resetResolverState` is no longer exported through `__internals` (it is
  still used by `resetAppState`; no test called it directly).
- `package.json`: version `0.3.2`; `engines.node` set to `>=22` to match the
  README and CI.
- CI workflow: least-privilege `permissions: contents: read`; trailing
  whitespace removed.
- README updated to match the implementation: no L2 write-back, best-effort
  Cache API `delete` on purge, SOA `MINIMUM` ageing, upstream redirects
  rejected, truncated (TC) answers treated as unusable, question echo is
  checked on every response that carries a question (required for `NOERROR`),
  invalid base64url listed under `400`, `x-winner` header note, aborted
  in-flight jobs, test count.

### Reviewed, no change needed
- No dead functions, unused `CONFIG` keys or unused/undefined CSS classes were
  found in `Worker.js` (every helper has a caller; every inlined utility class
  is used and every used class is defined).

### Tests
- 75 tests (was 74). Removed the three L2-refresh tests (behavior removed).
  Added: L2 hit serves age-adjusted TTLs with no Cache API `put`; throwing
  `ctx.waitUntil` does not break a cache miss; SOA `MINIMUM` ageing (including
  clamping at zero and source buffer left untouched); `patchDNSResponseForAge`
  with `ArrayBuffer` and `Uint8Array` input without mutating the source.

