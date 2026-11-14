# Changelog

All notable changes to this project are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.8] - 2026-11-14

### Fixed

- Validate SOA RDATA in client additional records before the query can reach cache or upstream handling.
- The overtaken-hedge penalty (-2, counted in `slow`) applies only to upstream attempts still running when a backup wins. An attempt whose response had already settled is not penalised as overtaken.

### Changed

- Avoid allocating a temporary section-count array during DNS response validation.
- Bump Worker and package versions to 0.5.8.

### Tests

- Added regressions for positive alias-only caching and additional-section SOA validation.
- The Node.js suite contains 136 tests.

