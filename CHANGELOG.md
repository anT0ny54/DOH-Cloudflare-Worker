# Changelog

All notable changes to this project are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.7] - 2026-10-28

### Fixed

- Winner-selected aborts now take precedence when an upstream attempt timeout also fired, so an overtaken hedge is tracked as a slow loser rather than a resolver timeout.
- SVCB/HTTPS RDATA now rejects reserved `SvcParamKey` 0 when it appears as a regular parameter.

### Changed

- Reduced base64url encoding overhead by avoiding spread calls for byte chunks.
- Removed unused dashboard element IDs.

### Tests

- Added regressions for simultaneous winner/timeout abort handling and reserved SVCB keys.
- The Node.js suite now contains 131 tests.
- Bumped the Worker and package versions to 0.5.7.
