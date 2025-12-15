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

### Fixed

#### Windows/MSVC Compatibility (2024-12-15)

- **FIXED:** MSVC build error from unknown GCC pragmas
  - Made `#pragma GCC diagnostic` conditionally compiled for GCC/Clang only
  - MSVC was treating unknown pragma warnings (C4068) as errors (C2220)
  - Fixed in `mtls_err_set()` and `mtls_err_set_internal()` functions
  - All platforms (Linux/GCC, macOS/Clang, Windows/MSVC) now build cleanly
  - [Commit: b41e467]

- **FIXED:** Windows missing POSIX headers in example programs
  - Added platform-specific includes and function wrappers
  - Replaced `unistd.h` with Windows.h on Windows
  - Created portable `sleep_ms()` and `get_process_id()` macros
  - Made signal handlers conditional (POSIX only)
  - [Commit: b6e7138]

- **FIXED:** Format truncation warnings in demo programs
  - Pre-calculated safe buffer sizes before snprintf
  - Truncated oversized inputs to prevent buffer overflow
  - Fixed in `cert_reload_demo.c` and `kill_switch_demo.c`
  - [Commits: 34109b7, b6e7138]

- **FIXED:** Windows localtime deprecation warnings
  - Used `localtime_s()` on Windows instead of deprecated `localtime()`
  - Maintained POSIX `localtime()` for Linux/macOS
  - Fixed in `advanced_client.c`
  - [Commit: e3976f7]

### Added

#### New Example Programs (2024-12-15)

- **NEW:** Kill switch demonstration program (`kill_switch_demo.c`)
  - Shows emergency kill switch functionality with signal-based control
  - Demonstrates blocking new connections without stopping the process
  - SIGUSR1/SIGUSR2 signal handling for POSIX systems
  - 280 lines with comprehensive error handling
  - [Commit: 31bc28b]

- **NEW:** Certificate reload demonstration program (`cert_reload_demo.c`)
  - Shows hot certificate reloading without downtime
  - Demonstrates zero-downtime certificate rotation
  - SIGUSR1 signal handling for reload trigger (POSIX)
  - 320 lines with certificate validity monitoring
  - [Commit: 31bc28b]

#### Enhanced Example Programs (2024-12-15)

- **ENHANCED:** All existing examples now demonstrate unused API methods
  - `simple_client.c` and `simple_server.c` - Added `mtls_version()` and `mtls_config_validate()`
  - `advanced_client.c` - Added `mtls_err_code_name()`, `mtls_err_category_name()`, `mtls_validate_peer_sans()`
  - `echo_server.c` - Added config validation and built-in SAN validation
  - All 6 example programs now provide complete API coverage
  - [Commits: 31bc28b, e3976f7]

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

- **6 test suites** now passing (100% pass rate):
  - `test_security_fixes` - Security vulnerability validation
  - `test_identity` - Identity extraction and validation
  - `test_san_validation` - 21 SAN matching tests
  - `test_phase4_features` - 23 constant-time comparison tests
  - `test_memory_safety` - Memory leak and bounds checking
  - `fuzz_oversized_sans` - 10 fuzz test suites (1,500+ iterations)

- **6 example programs** demonstrating complete API coverage:
  - `simple_client` and `simple_server` - Basic mTLS client/server
  - `advanced_client` - Identity validation with SAN/SPIFFE
  - `echo_server` - Multi-client server with SAN validation
  - `kill_switch_demo` - Emergency connection blocking
  - `cert_reload_demo` - Zero-downtime certificate rotation

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
- 4 Compatibility/Build fixes
- **20 total security and compatibility fixes**

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
