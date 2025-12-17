# mTLS Library Test Suite

This directory contains comprehensive test suites to verify security fixes, functional correctness, and compliance with security standards.

## Running the Tests

```bash
cd build
cmake ..
make
ctest --output-on-failure
```

Or run individual test suites:
```bash
./build/tests/test_security_fixes
./build/tests/test_identity
./build/tests/test_san_validation
./build/tests/test_phase4_features
./build/tests/fuzz_oversized_sans
```

## Test Suites

### 1. test_security_fixes (30 tests)
Basic security vulnerability validation and edge case testing.

### 2. test_identity (tests)
Identity extraction and validation from X.509 certificates.

### 3. test_san_validation (21 tests)
Subject Alternative Name (SAN) matching and validation logic.

### 4. test_phase4_features (23 tests)
Constant-time comparison, certificate reload, and Phase 4 security features.

### 5. fuzz_oversized_sans (10 test suites, 1,500+ iterations)
**NEW:** Comprehensive fuzz testing for oversized identity handling.

## Test Coverage

### Basic Security Tests (13 tests)

### 1. Buffer Overflow Protection
- **test_hostname_extraction_overflow**: Verifies that hostname extraction properly handles boundary conditions and rejects overly long hostnames
- **test_address_string_validation**: Tests that address strings are validated for length before parsing

### 2. Input Validation
- **test_port_number_validation**: Verifies port numbers are validated (0-65535 range, numeric only)
- **test_file_path_validation**: Tests file path length limits (max 4096 bytes)
- **test_pem_data_validation**: Verifies PEM data length validation (max 1MB, non-zero)
- **test_allowed_sans_validation**: Tests allowed SANs array validation (no NULL entries, length limits)

### 3. Thread Safety
- **test_thread_safety_connection_state**: Verifies atomic operations on connection state prevent race conditions
- **test_thread_safety_kill_switch**: Tests concurrent access to kill switch using atomic operations

### 4. Integer Overflow Protection
- **test_integer_overflow_protection**: Verifies that PEM lengths that would overflow INT_MAX are rejected

### 5. Buffer Size Limits
- **test_buffer_size_limits**: Verifies that read/write buffer size constants are properly defined

### 6. Wildcard Matching Security
- **test_wildcard_matching_security**: Tests that wildcard patterns are validated (format checking)

### 7. Error Handling
- **test_error_message_null_termination**: Verifies error messages are always null-terminated

### 8. Use-After-Free Protection
- **test_use_after_free_protection**: Tests that state checks prevent use-after-free scenarios

### Edge Case Tests (17 additional tests)

### 9. Empty String Handling
- **test_edge_case_empty_strings**: Tests handling of empty input strings

### 10. NULL Pointer Handling
- **test_edge_case_null_pointers**: Comprehensive NULL pointer testing for all API functions

### 11. Boundary Conditions
- **test_edge_case_buffer_boundaries**: Tests exactly at limit, one over, one under
- **test_edge_case_port_boundaries**: Port numbers at boundaries (1, 65535, 65536, 0)
- **test_edge_case_file_path_boundaries**: Path length at boundaries (4096, 4097)
- **test_edge_case_pem_boundaries**: PEM size at boundaries (1MB, INT_MAX)
- **test_edge_case_san_boundaries**: SAN length at boundaries (512, 513)
- **test_edge_case_int_max_boundary**: INT_MAX boundary for integer overflow protection

### 12. Format Edge Cases
- **test_edge_case_ipv6_format**: IPv6 address format variations
- **test_edge_case_multiple_colons**: Handling of multiple colons in addresses

### 13. Input Edge Cases
- **test_edge_case_zero_length_inputs**: Zero-length input handling
- **test_edge_case_max_allowed_sans**: Maximum allowed SAN count (64, 65)
- **test_edge_case_special_characters**: Special character injection attempts

### 14. Concurrency Edge Cases
- **test_edge_case_concurrent_state_changes**: Rapid concurrent state changes with many threads

### 15. Buffer Size Edge Cases
- **test_edge_case_write_buffer_limits**: Write buffer size limit testing
- **test_edge_case_read_buffer_limits**: Read buffer size limit testing

### 16. Error Handling Edge Cases
- **test_edge_case_error_truncation**: Error message truncation at boundaries

## Test Limitations

Some tests cannot fully verify behavior without actual TLS connections:
- Connection state tests are simplified (no actual connection established)
- Read/write buffer limit tests verify constants but not runtime behavior
- Some tests verify validation logic but not full end-to-end behavior

For full integration testing, see the examples directory (when implemented).

## Fuzz Testing for Oversized SANs

### Overview

The `fuzz_oversized_sans` test suite performs comprehensive fuzz testing of the security fix for oversized identity handling. This addresses the critical vulnerability where attackers could craft oversized Subject Alternative Names (SANs) to bypass identity validation.

### Test Categories

**Boundary Tests (4 tests):**
- Strings exactly at `MTLS_MAX_IDENTITY_LEN` (10,000 chars) - should be accepted
- Strings over limit by 1 (10,001 chars) - should return -1 error
- Strings far over limit (11,000 chars) - should return -1 error
- Asymmetric cases (one at limit, one over) - should return -1 error

**Random Fuzz Tests (2 suites, 1,500 iterations):**
- 1,000 iterations with random lengths (90% valid, 10% oversized)
- 500 iterations with DNS-like patterns
- Random content generation (printable ASCII, not just repeated chars)

**SAN Validation Integration (3 tests):**
- Reject oversized peer SANs in validation
- Reject when both peer and allowed patterns are oversized
- Mixed-size SANs (valid + oversized) - should match valid ones

**Stress Tests (1 test):**
- 100 repeated comparisons at maximum length

### Expected Results

All 10 fuzz test suites should pass:
- ✅ Strings at limit are accepted (return 0 or non-zero, but not -1)
- ✅ Strings over limit return -1 error (fail-closed)
- ✅ No buffer overflows with any string size
- ✅ SAN validation rejects oversized identities
- ✅ 1,500+ iterations complete without crashes

### Reproducibility

The fuzz test uses a fixed seed (`0x12345678`) for reproducibility. The same inputs will generate the same results across runs.

### Security Objectives

1. **Prevent bypass attacks** - Oversized SANs cannot be used to bypass identity validation
2. **Prevent resource exhaustion** - Bounded length prevents DoS via extremely long strings
3. **Prevent buffer overflows** - No reads past allocated memory boundaries
4. **Maintain constant-time** - Timing-attack resistance preserved even with virtual padding
5. **Fail-closed** - All oversized inputs are explicitly rejected with error

## Expected Results

All tests should pass (94 total across 5 test suites). The test suite verifies:
- ✅ No buffer overflows
- ✅ Input validation works correctly
- ✅ Thread safety is maintained
- ✅ Integer overflows are prevented
- ✅ Error messages are safe
- ✅ Edge cases are handled correctly
- ✅ Boundary conditions are properly validated
- ✅ NULL pointers are handled safely
- ✅ Empty inputs are rejected appropriately
- ✅ Maximum values are handled correctly

## Building with Sanitizers

For additional security verification, build with sanitizers:

```bash
cd build
cmake -DMTLS_ENABLE_ASAN=ON -DMTLS_ENABLE_UBSAN=ON ..
make
ctest
```

This will help detect:
- Memory leaks
- Use-after-free
- Buffer overflows
- Undefined behavior

