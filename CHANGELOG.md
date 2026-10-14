# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.0]

### Fixed
- Upstream response validation is now complete: successful answers are
  verified against the original query, including the echoed QNAME
  (case-insensitively, preserving 0x20 randomization tolerance), QTYPE and
  QCLASS, and the full resource-record structure is walked. Responses with a
  matching ID but a different question can no longer be accepted or cached
  under the original query's key.
- L2 cache bodies are validated as DNS messages (structure plus echoed
  question), not just cache bookkeeping: malformed bodies are purged and
  re-resolved upstream instead of being served. The stored transaction ID is
  not part of this check because it is rewritten per request.
- Single-chunk response bodies: converting a possibly-subarray `Uint8Array`
  chunk via `.buffer` could expose, validate, cache and return bytes outside
  the actual response. `toExactArrayBuffer()` now preserves the exact
  `byteOffset`/`byteLength` range.
- Upstream fetches now use `redirect: "error"` so a redirect can never
  silently forward the DNS POST body to a different host; the existing
  failover logic tries the next configured resolver instead.
- The SOA parser no longer derives the negative-cache MINIMUM from malformed
  data: it requires exactly the five 32-bit fields after the two names and
  reads MINIMUM at its fixed offset. Records with trailing or missing bytes
  no longer produce an incorrect negative-cache lifetime.
- Truncated (TC) upstream answers no longer win the resolver race: they are
  treated as unusable so a complete resolver can win. If every upstream
  truncates, the truncated fallback is still returned degraded (RFC 8484
  permits TC in DoH) and is never cached.
- Error responses that legitimately omit the question section are still
  accepted; successful answers without a question are rejected.

### Changed
- `validateDNSResponse()` is a thin wrapper over a shared
  `validateDNSMessage()` used by both the upstream path and the L2 cache path
  (header-only validation removed as redundant).
- `readCappedBody()` keeps its single-chunk fast path; callers convert chunks
  with `toExactArrayBuffer()`.
- Test isolation: `__internals.resetAppState()` clears the L1 cache,
  throttle/penalty maps, in-flight jobs, the resolver rotation cursor and the
  sweep timestamp in addition to resolver statistics.
- README: the Node.js 22 minimum-version rationale now cites the actual
  requirements (web-standard globals, `node --test`, explicit
  `"type": "module"`) instead of 22.7 module-syntax detection.
- Version bumped to 0.3.0.

### Tests
- 60 tests (was 47). Added: QNAME/QTYPE/QCLASS question-echo mismatch
  rejection; 0x20 case-reordered QNAME acceptance; missing-question handling
  (rejected for NOERROR, accepted for error RCODEs); truncated record-section
  rejection; subarray buffer-boundary preservation (`toExactArrayBuffer`);
  single-chunk subarray stream regression; upstream redirect policy pinned to
  `error`; L2 corrupt-body and question-mismatch purge with upstream fallback;
  SOA records with trailing or missing bytes are not cached; truncated
  answers lose the race to complete ones; all-truncated upstreams return a
  degraded, uncached answer. State is reset between tests via
  `__internals.resetAppState()`.

### Added
- GitHub Actions workflow (`.github/workflows/test.yml`) running `npm test`
  on Node.js 22 for pushes to `main` and all pull requests.

