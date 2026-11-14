# Changelog

All notable changes to this project are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.7] - 2026-10-28

### Fixed

- Winner-selected aborts take precedence when an upstream attempt timeout also fired, so an overtaken hedge is tracked as a slow loser rather than a resolver timeout.
- SVCB/HTTPS records with a valid `mandatory` SvcParam (key 0) are accepted, and the mandatory key list is checked against the keys present. Earlier 0.5.7 builds rejected every such record as malformed.
- Responses without a question section keep their record bytes. QNAME letter-case restoration applies only when the response echoes a question, so answer-record names are no longer rewritten.
- The dashboard looks up the stored language with an own-property check, so a stored value such as `constructor` no longer renders "undefined" labels.

### Changed

- Reduced base64url encoding overhead by avoiding spread calls for byte chunks.
- Removed unused dashboard element IDs.
- Removed dead code: an unused RDATA helper parameter, an unreachable upstream-list guard, a never-taken `Uint8Array` conversion in the query parser, and a redundant check in the body reader.
- The dashboard page is rendered once per endpoint and reused for later requests.

### Tests

- Regressions for simultaneous winner/timeout abort handling, valid SVCB mandatory lists, and questionless case preservation.
- The corrupt-L2 test checks the responses it depends on instead of accepting upstream failures.
- The Node.js suite contains 133 tests.
- Worker and package versions are 0.5.7.
