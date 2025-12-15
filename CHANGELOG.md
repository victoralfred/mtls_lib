# Changelog

All notable changes to the mTLS Library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

#### Critical Buffer Overflow Fixes (2024-12-15)

- **FIXED:** Heap-buffer-overflow in constant-time string comparison
  - When comparing strings of different lengths, the comparison loop would read past the shorter string's allocated memory
  - Affected all platform implementations (Linux, macOS, Windows)
  - Detected by AddressSanitizer during CI testing
  - [Commit: 17a3b9c]

- **FIXED:** Global-buffer-overflow in constant-time string comparison
  - When comparing empty strings or strings against global literals, would read past buffer boundaries
  - Same fix as heap-buffer-overflow (bounded iteration with virtual padding)
  - [Commit: 17a3b9c]

- **FIXED:** Silent truncation authentication bypass vulnerability
  - Constant-time comparison silently truncated strings at 10,000 characters without error
  - Allowed attackers to craft oversized SANs to bypass identity validation
  - Violated fail-closed security principles and CERT C/MISRA C standards
  - Now explicitly rejects oversized identities with `MTLS_ERR_IDENTITY_TOO_LONG` error
  - [Commit: bd45ff3]

### Added

#### New Security Features (2024-12-15)

- **NEW:** `MTLS_MAX_IDENTITY_LEN` constant (10,000 characters)
  - Enforces hard upper bound on identity string length
  - Prevents resource exhaustion attacks
  - Prevents comparison bypass attacks
  - [Commit: bd45ff3]

- **NEW:** `MTLS_ERR_IDENTITY_TOO_LONG` error code (405)
  - Explicit error for oversized identity rejection
  - Part of identity/verification error category (4xx)
  - [Commit: bd45ff3]

- **NEW:** Comprehensive fuzz test suite for oversized SANs
  - 10 test suites with 1,500+ fuzz iterations
  - Tests boundary conditions (exact limit, over by 1, far over)
  - Random content generation and DNS-like pattern testing
  - SAN validation integration tests
  - Stress tests with maximum-length strings
  - [Commit: 1870f04]

- **NEW:** Extended Phase 4 feature tests
  - Added 3 new tests for oversized identity handling
  - Tests for strings at exact limit, oversized strings, asymmetric cases
  - Now 23 total tests in Phase 4 test suite
  - [Commit: bd45ff3]

### Changed

#### Security Improvements (2024-12-15)

- **IMPROVED:** Constant-time string comparison now fail-closed
  - Pre-validates string lengths using `strnlen()`
  - Returns `-1` error for strings exceeding `MTLS_MAX_IDENTITY_LEN`
  - Uses bounded `for` loop instead of unbounded `while(1)`
  - Virtually pads shorter strings with zeros to prevent buffer overruns
  - Maintains timing-attack resistance
  - [Commits: bd45ff3, 17a3b9c]

- **IMPROVED:** SAN validation rejects oversized identities
  - Explicitly checks for `-1` error from `platform_consttime_strcmp()`
  - Rejects oversized SANs before comparison (fail-closed)
  - Prevents bypass attacks using oversized identity strings
  - [Commit: bd45ff3]

### Compliance

#### Security Standards Achieved (2024-12-15)

- **CERT C Secure Coding Standard:**
  - ✅ STR31-C: Guarantee string termination
  - ✅ ERR33-C: Detect and handle standard library errors
  - ✅ MSC24-C: Avoid magic numbers

- **MISRA C Safety Standard:**
  - ✅ Rule 15.x: Explicit and provable loop termination
  - ✅ Rule 17.x: No hidden control flow side effects

- **AddressSanitizer:**
  - ✅ No heap-buffer-overflow errors
  - ✅ No global-buffer-overflow errors
  - ✅ Clean execution on all test suites

### Testing

- **5 test suites** now passing (100% pass rate):
  - `test_security_fixes` - Security vulnerability validation
  - `test_identity` - Identity extraction and validation
  - `test_san_validation` - 21 SAN matching tests
  - `test_phase4_features` - 23 constant-time comparison tests
  - `fuzz_oversized_sans` - 10 fuzz test suites (1,500+ iterations)

## [0.1.0] - 2024-12

### Security

#### Critical Security Fixes

- **FIXED:** Certificate verification bypass - SSL_get_verify_result() check added
- **FIXED:** Identity/SAN validation bypass - peer certificate validation implemented
- **FIXED:** Hostname verification bypass - SSL_set1_host() integration added
- **FIXED:** Integer overflow vulnerabilities in SAN count and PEM length handling
- **FIXED:** Buffer overflow in URI SAN extraction (GEN_URI vs GEN_DNS)
- **FIXED:** Certificate chain DoS - limited chain depth to 10

#### Thread Safety Fixes

- **FIXED:** Kill switch race conditions - converted to atomic_bool

#### Memory Safety Fixes

- **FIXED:** Memory leaks in identity extraction on allocation failure
- **FIXED:** Null termination guarantees for X509_NAME_get_text_by_NID()

#### Correctness Fixes

- **FIXED:** Incomplete write handling - now loops until all data written
- **FIXED:** Local address never populated - added getsockname() calls
- **FIXED:** Address family validation before socket creation

#### Compatibility Fixes

- **FIXED:** Deprecated OpenSSL 1.0.x initialization functions

### Added

- Phase 4 feature implementation: constant-time comparison, certificate reload
- Identity verification tests
- SAN validation test suite (21 tests)
- Security fixes test suite

### Files Modified

- `src/mtls_conn.c` - Certificate verification, identity validation, write handling
- `src/mtls_listener.c` - Certificate verification, identity validation
- `src/mtls_identity.c` - Integer overflow protection, memory leak fixes
- `src/mtls_ctx.c` - Thread-safe kill switch
- `src/mtls_tls.c` - Certificate chain depth, compatibility fixes
- `src/internal/platform_*.c` - Constant-time comparison implementation

---

## Notes

### Version 0.1.0

This version represents the initial security-hardened release with all critical vulnerabilities addressed:

- 9 Critical severity fixes
- 3 High severity fixes
- 4 Medium severity fixes
- **16 total security fixes**

The library is now:
- ✅ Memory safe (AddressSanitizer clean)
- ✅ Thread safe (atomic operations for shared state)
- ✅ Compliant with CERT C and MISRA C security standards
- ✅ Protected against timing attacks (constant-time comparison)
- ✅ Fail-closed (explicit error handling, no silent failures)

### Upgrading

All security fixes maintain API compatibility. No changes required in existing code.

### Security Contact

For security vulnerabilities, please report to the project maintainers.
