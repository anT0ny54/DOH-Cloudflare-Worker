# Changelog

All notable changes to this project are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Version remains 0.5.8. This update tightens structural validation of legacy SIG records without changing resolver selection, cache behavior, or rate limiting.

### Fixed

- `Worker.js`: reject legacy SIG (type 24) records whose DNSSEC algorithm is zero or explicitly reserved, matching the algorithm checks already applied to RRSIG. Historical signer-name compression remains accepted for receiver compatibility. Unassigned and private-use algorithm values remain supported.

### Tests

- `test.mjs`: add regression coverage for reserved and non-reserved legacy SIG algorithms, and update the compressed legacy SIG fixture to use a valid algorithm. The suite now contains 146 tests.

### Documentation

- `README.md`: document legacy SIG algorithm validation, clarify that the Worker performs structural DNSSEC-related checks but does not cryptographically verify signatures or trust chains, and update the test count to 146.
