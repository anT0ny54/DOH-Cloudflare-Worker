# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed
- Client queries and upstream DNS responses with the reserved DNS header Z bit
  set are rejected before caching or relaying.
- L2 cache entries are now purged when their headers or body cannot be read,
  avoiding repeated failed reads of the same corrupt entry.
- L2 cache bodies are stream-capped at the 65,535-byte DNS wire maximum
  before buffering; oversized entries are purged and resolved upstream. The shared
  DNS validator also rejects oversized messages directly.
- The local fallback rate limiter checks evicted penalty entries before moving
  them back into the LRU, so blocked clients cannot churn legitimate entries.
- Upstream DNS response validation checks that EDNS OPT option headers and
  payloads exactly fill the OPT RDATA, so malformed options trigger resolver
  failover and cannot enter either cache.
- DNS compression pointers must target a previously verified DNS-name label
  boundary as well as encode the complete target before the referring pointer.
  Pointers into label payload bytes or opaque, unverified RDATA are rejected.
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
  checks selected defined ServiceMode SvcParam layouts and mandatory-key consistency,
  while AliasMode ignores SvcParams as required by RFC 9460; unknown keys stay opaque.

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
- README test count now reflects the 130-test suite; dashboard-template caching
  documentation matches the code (built lazily on first request, then cached).
- README documents typed RDATA checks and verified compression-target boundaries,
  and links the current official Workers limits documentation directly.

### Tests
- 130 tests (17 added since 0.5.3): malformed upstream OPT option lengths,
  partial option headers and trailing partial headers are rejected; malformed
  responses trigger failover and are not cached; questionless extended-RCODE
  errors are checked correctly; compression targets that overlap their source
  pointer or land inside a label payload (including query additional records),
  while targets in prior validated RDATA names remain accepted; malformed SOA
  RDATA and malformed common RDATA layouts are rejected;
  valid compressed CNAME/MX and legacy SIG/PX/NXT RDATA remain accepted;
  prohibited NSAP-PTR/DNAME/KX/TALINK/LP/IPSECKEY compression, invalid CAA
  tags and malformed selected SvcParams are rejected; valid uncompressed SIG,
  SPF and SVCB RDATA are accepted. New regressions cover reserved DNS Z flags,
  L2 body-read failures, oversized-cache streaming caps, AliasMode SvcParam handling
  and penalty-map LRU churn.

