# Security Fixes Test Suite

This test suite verifies all the security fixes applied to the mTLS library.

## Running the Tests

```bash
cd build
cmake ..
make
ctest --output-on-failure
```

Or run directly:
```bash
./build/tests/test_security_fixes
```

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

## Expected Results

All 30 tests should pass. The test suite verifies:
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

