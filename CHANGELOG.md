# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.4]

### Fixed
- **Fallback rate limiter eviction:** `localRateLimit` used a Map that never reordered existing keys, so a flood of new IPs evicted (and reset the counter of) the busiest client first. Entries are now refreshed on every hit, giving real least-recently-used eviction.
- **RFC 2181 TTLs:** resource-record TTLs with the most significant bit set are now treated as 0 instead of being clamped to 24 h and cached.
- **Dashboard text mismatch:** the server-rendered English setup text differed from the `I18N.en` strings that replaced it on load (the Chrome tab lost its fifth step, headings changed). The static HTML now matches the English translations exactly.
- **Dashboard markup:** setup steps are now `<ul>/<li>` (previously `<li>` elements were injected into `<div>`s), and `<html lang>` follows the selected language.

### Changed
- Replaced `SECONDARY_HEDGE_MIN_MS` / `SECONDARY_HEDGE_MAX_MS` (which clamped a constant 150 ms) with a single `SECONDARY_HEDGE_MS`. Behaviour is unchanged.
- Version bumped to 0.2.4 (header comment, `VERSION`, `/health`).

### Removed (dead / redundant code)
- Unreachable `jumps` counter in `skipDNSName` (the 255-byte wire-length check already bounds the label count).
- Duplicate size and null checks on the decoded payload in `handleDNS` (both `readDNSPayload` paths already enforce the 4 KiB cap and non-empty GET input).
- Second `Math.min(ttl, EDGE_CACHE_MAX_TTL_SECONDS)` when writing to L2 (`getDNSCacheTTL` already clamps).

### Tests
- 30 -> 36 tests. New coverage: RFC 2181 TTL handling, TTL clamping, hedge-delay bounds, `selectRacers` ordering, local rate-limit window and LRU retention. Previously exported-but-untested internals (`getHedgeDelay`, `getSecondaryHedgeDelay`, `selectRacers`, `localRateLimit`) are now exercised.

### Documentation
- README now describes resolver scoring and hedging as implemented, the 128-bit cache key, RFC 2181 handling, fallback limiter details, the GET-parameter `413`, the Node.js requirement for tests, and the correct test count.
- Softened the Cache API quota statement (Cloudflare's per-request figures have changed over time).
- Clarified that the "Free DNS Services" table is unrelated to the Worker's upstreams.
