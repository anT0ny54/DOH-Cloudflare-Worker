# Changelog

All notable changes to this project are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Version remains 0.5.8; no version bump or DNS behaviour change is included.

### Changed

- `Worker.js` / `test.mjs`: corrected IPSECKEY Gateway Type 0 parsing per RFC 4025: the gateway field is absent on the wire (zero octets), while the zone-file `.` is presentation syntax; added regression coverage for empty gateways, key-bearing records and the no-key algorithm rule.
- `test.mjs`: added a regression test for in-flight table overflow, confirming that the oldest tracked key is evicted, the map remains bounded and the new job can complete.
- README: clarified that the 128-key in-flight table evicts its oldest tracked entry on overflow without cancelling the running job, so a later request for an evicted key can start a second resolution; updated the documented suite count to 138.
- `Worker.js` / `worker-harness.mjs`: moved the in-flight joiner counter into temporary test-only instrumentation. Production in-flight entries no longer carry test bookkeeping or perform a counter write; deterministic coalescing tests are preserved.
- `Worker.js`: corrected the dashboard-template size comment to match the approximately 21 KB figure documented in the README.
- `worker-harness.mjs`: made the test-only coalescing instrumentation require exactly one insertion point and guaranteed temporary-directory cleanup if writing or importing the test copy fails. No deployed Worker behavior changes.

- README: corrected the Cloudflare simultaneous-connection limit. Cloudflare relaxed it on 2026-04-09 so that the six-connection limit only counts connections waiting for response headers; the resolver's cap of three active attempts is unchanged and remains within the limit.
- `wrangler.toml`: enabled `minify = true`. The uploaded bundle shrinks from 80.02 KiB to 51.51 KiB (gzip 22.04 KiB to 17.83 KiB), so less code is loaded per isolate. The minified build was compared with the source build over a representative request set (GET, POST, error and cache-hit paths): the dashboard HTML and every DNS response (status, headers and body) matched.
- README: corrected the size of the dashboard template from about 15 KB to about 21 KB, and documented the minified deploy bundle.
