# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed
- Upstream DNS response validation checks that EDNS OPT option headers and
  payloads exactly fill the OPT RDATA, so malformed options trigger resolver
  failover and cannot enter either cache.
- DNS compression-pointer targets must have their entire encoded name before
  the referring pointer. Previously, a target could start before the pointer
  but consume its bytes or later bytes, allowing a malformed response to pass.
- Malformed SOA RDATA is rejected instead of being accepted in a positive
  response when it cannot safely be interpreted for cache-TTL handling.
- Questionless response validation now checks the final RCODE after EDNS OPT
  contributes its extended RCODE bits, so a valid questionless BADVERS response
  is not misclassified as NOERROR.
- Upstream response validation checks common typed RDATA framing, including
  A/AAAA lengths, name-bearing RDATA, TXT/SPF/HINFO strings, protocol-specific
  name-compression rules (including uncompressed DNAME, KX, TALINK, LP,
  NSAP-PTR and IPSECKEY names), and legacy SIG/NXT/PX compression compatibility.
- CAA tags must contain only ASCII letters and digits. SVCB/HTTPS validation
  checks selected defined SvcParam layouts and mandatory-key consistency while
  preserving unknown parameter keys as opaque values.

### Performance
- Shared the RDATA framing helpers across records instead of allocating several
  closures for every resource record.

### Changed
- Removed redundant code: the constant-only `sanitizeHeaderValue()` on the
  `x-winner` header, the single-use `validateMethod()` wrapper, an unreachable
  short-message guard in `patchDNSResponseForAge()`, and header presence checks
  in the L2 reader that the numeric checks already covered (an entry with a
  missing `x-doh-stored-at` or `x-doh-ttl` is still purged before its body is
  read). Identical RDATA validator cases (AAAA/LOC, NSAP-PTR/DNAME,
  DNSKEY/DHCID/TLSA-family) were merged. Behaviour is unchanged.
- The in-flight join-timeout comment now describes 3 x upstream timeout as a
  conservative bound, since hedged attempts overlap.

### Documentation
- README test count corrected (121 -> 123) and the dashboard-template caching
  description now matches the code (built lazily on first request, then cached).
- README reflects the 123-test suite, documents typed RDATA checks and the
  remaining compression-target boundary limitation, and keeps the current official
  Workers limits documentation linked directly.

### Tests
- 123 tests (10 added since 0.5.3): malformed upstream OPT option lengths,
  partial option headers and trailing partial headers are rejected; malformed
  responses trigger failover and are not cached; questionless extended-RCODE
  errors are checked correctly; compression targets that overlap their source
  pointer, malformed SOA RDATA and malformed common RDATA layouts are rejected;
  valid compressed CNAME/MX and legacy SIG/PX/NXT RDATA remain accepted;
  prohibited NSAP-PTR/DNAME/KX/TALINK/LP/IPSECKEY compression, invalid CAA
  tags and malformed selected SvcParams are rejected; valid uncompressed SIG,
  SPF and SVCB RDATA are accepted.

