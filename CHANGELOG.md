# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.5]

### Changed
- Upstream abort handling uses the built-in `AbortSignal.any` instead of a hand-written `anySignal` helper (which also left abort listeners attached to the long-lived race signal).
- Hedge delays read `CONFIG.SECONDARY_HEDGE_MS` directly; the `getSecondaryHedgeDelay()` wrapper and its export are gone.
- The client IP is resolved only for `/dns-query` requests.
- Version bumped to 0.2.5 (`VERSION` constant, reported by `/health` and shown in the dashboard footer).

### Removed (dead / redundant code)
- `CONFIG.MAX_CACHEABLE_DNS_BYTES` and its check in `getDNSCacheTTL` (equal to the 65,535-byte upstream cap, so it could never trigger).
- Post-decode size check in `decodeBase64Url` (a GET `dns` value is capped at 5,462 characters, which decodes to at most 4,096 bytes) and the redundant `!input` test (the regex already rejects empty input).
- The separate empty-payload check in `handleDNS`; an empty POST body is now rejected by `parseDNSQuestion` with `400 DNS message too short` (status unchanged, message text differs).
- `ip || 'unknown'` fallbacks in `allowDNSRequest` (`getClientIP` never returns an empty value) and the redundant `Math.max(1, Math.floor(...))` clamps in `putEdgeCache` (`getDNSCacheTTL` already returns an integer >= 1).

### Tests
- Still 36 tests; the hedge-bounds test no longer exercises the removed wrapper, and the version assertion expects 0.2.5.

### Not changed (behavioural, left for a separate decision)
- Cache keys still include EDNS cookie/padding options, resolver scores still have no time-based recovery, and in-flight jobs are not wrapped in `ctx.waitUntil`.
