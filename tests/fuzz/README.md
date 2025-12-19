# Fuzzing Documentation

This directory contains fuzzing infrastructure for the mTLS library, including libFuzzer and AFL++ support for continuous security testing.

## Table of Contents

- [Overview](#overview)
- [Fuzzing Targets](#fuzzing-targets)
- [Quick Start](#quick-start)
- [LibFuzzer Usage](#libfuzzer-usage)
- [AFL++ Usage](#afl-usage)
- [Corpus Management](#corpus-management)
- [Continuous Integration](#continuous-integration)
- [Findings and Triage](#findings-and-triage)
- [Performance](#performance)
- [Troubleshooting](#troubleshooting)

## Overview

Fuzzing is a critical security testing technique that automatically discovers bugs by feeding pseudo-random inputs to target functions. This directory provides:

- **4 LibFuzzer targets** with AddressSanitizer for memory safety testing
- **AFL++ integration** for parallel coverage-guided fuzzing
- **Automated CI workflows** for continuous fuzzing (nightly)
- **Corpus management** utilities for seed optimization
- **Issue tracking** for discovered vulnerabilities

### Why Fuzzing?

Fuzzing has discovered **PERF-001** (DNS timeout DoS) and continues to provide:
- Memory safety verification (buffer overflows, use-after-free, etc.)
- Input validation testing (malformed certificates, oversized SANs, etc.)
- Performance regression detection (slow paths, timeouts)
- Edge case discovery (boundary conditions, error paths)

## Fuzzing Targets

### 1. fuzz_san_validation.c

**Purpose**: Test Subject Alternative Name (SAN) validation and constant-time operations.

**Focus areas**:
- SAN string comparison (constant-time guarantees)
- Wildcard matching (`*.example.com`)
- SPIFFE ID validation (`spiffe://trust-domain/service`)
- Oversized identity strings (> `MTLS_MAX_IDENTITY_LEN`)
- Special characters and encoding edge cases

**Key functions tested**:
- `platform_consttime_strcmp()`
- `mtls_validate_peer_sans()`

### 2. fuzz_pem_parsing.c

**Purpose**: Test PEM certificate and private key parsing.

**Focus areas**:
- PEM header/footer validation
- Base64 decoding edge cases
- Truncated or malformed PEM data
- Multiple PEM blocks in single input
- Maximum size enforcement (`MTLS_MAX_PEM_SIZE`)

**Key functions tested**:
- `is_valid_pem_format()`
- `mtls_config_set_cert_pem()`
- OpenSSL PEM parsing (via `PEM_read_bio_X509`)

### 3. fuzz_certificate_validation.c

**Purpose**: Test X.509 certificate chain validation and SAN extraction.

**Focus areas**:
- Certificate chain building
- SPIFFE ID extraction from SANs
- Untrusted/self-signed certificates
- Expired or not-yet-valid certificates
- Malformed X.509 structures

**Key functions tested**:
- `mtls_listener_set_cert_pem()`
- Certificate chain validation logic
- OpenSSL X.509 parsing

### 4. fuzz_address_parsing.c

**Purpose**: Test network address parsing (IPv4, IPv6, hostnames).

**Focus areas**:
- IPv4 address parsing (`192.0.2.1:8080`)
- IPv6 address parsing (`[2001:db8::1]:8080`)
- Hostname resolution and validation
- Port number validation (0-65535)
- Control characters and invalid TLDs (`.local`)

**Key functions tested**:
- `platform_parse_addr()`
- `validate_hostname()` (internal)

**Security note**: This fuzzer discovered **PERF-001** (`.local` TLD causing 25-second DNS timeouts).

## Quick Start

### Prerequisites

- **Clang**: Required for libFuzzer (`CC=clang`)
- **AFL++**: Optional for AFL++ fuzzing (`afl-clang-fast`)
- **CMake**: Build system (>= 3.10)
- **OpenSSL**: TLS/certificate dependencies

```bash
# Ubuntu/Debian
sudo apt-get install clang cmake libssl-dev

# macOS
brew install llvm cmake openssl
```

### Build and Run (LibFuzzer)

```bash
# 1. Configure with fuzzing enabled
mkdir -p build_fuzz
cd build_fuzz
CC=clang cmake -DMTLS_ENABLE_FUZZING=ON ..

# 2. Build all fuzzing targets
cmake --build . --parallel $(nproc)

# 3. Run a fuzzer (1 hour)
cd tests
./fuzz_san_validation -max_total_time=3600 corpus/fuzz_san_validation/

# 4. Check for crashes
ls -la crash-* timeout-* leak-* 2>/dev/null || echo "No crashes found"
```

### Quick Test (30 seconds)

```bash
cd build_fuzz/tests
./fuzz_address_parsing -max_total_time=30 corpus/fuzz_address_parsing/
```

Expected output:
```
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3456789123
INFO: Loaded 1 modules   (1234 inline 8-bit counters): ...
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 123 ft: 456 corp: 1/1b exec/s: 0 rss: 45Mb
#8192   pulse  cov: 234 ft: 789 corp: 23/456b lim: 128 exec/s: 4096 rss: 52Mb
...
Done 15426 runs in 31 second(s)
```

## LibFuzzer Usage

### Basic Commands

```bash
# Run for 1 hour
./fuzz_san_validation -max_total_time=3600 corpus/

# Limit memory usage (512 MB)
./fuzz_san_validation -rss_limit_mb=512 corpus/

# Timeout for slow inputs (10 seconds)
./fuzz_san_validation -timeout=10 corpus/

# Reproduce a crash
./fuzz_san_validation crash-abc123def456
```

### Advanced Options

```bash
# Use multiple workers (parallel fuzzing)
./fuzz_san_validation -workers=8 -jobs=100 corpus/

# Minimize a crashing input
./fuzz_san_validation -minimize_crash=1 crash-abc123def456

# Merge corpuses from multiple runs
./fuzz_san_validation -merge=1 corpus_merged/ corpus1/ corpus2/

# Print coverage information
./fuzz_san_validation -print_coverage=1 corpus/
```

### Interpreting Output

```
#12345  NEW    cov: 456 ft: 789 corp: 23/1234b lim: 256 exec/s: 2000 rss: 67Mb L: 42/128 MS: 2 InsertByte-EraseBytes-
```

- `#12345`: Iteration number
- `NEW`: New coverage discovered
- `cov: 456`: Edge coverage (code paths)
- `ft: 789`: Feature count (unique behaviors)
- `corp: 23/1234b`: Corpus size (23 files, 1234 bytes total)
- `exec/s: 2000`: Executions per second
- `L: 42/128`: Input length (42 bytes, max 128)

### Crash Artifacts

When a crash is found, libFuzzer creates files:

- **`crash-<hash>`**: Input that triggered crash
- **`timeout-<hash>`**: Input that caused timeout
- **`leak-<hash>`**: Input that caused memory leak

Reproduce crashes:
```bash
# Run under debugger
gdb --args ./fuzz_san_validation crash-abc123def456

# Get detailed AddressSanitizer output
ASAN_OPTIONS=verbosity=2 ./fuzz_san_validation crash-abc123def456
```

## AFL++ Usage

AFL++ provides parallel fuzzing with multiple power schedules for better coverage.

### Installation

```bash
# From source
cd /tmp
wget https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/4.21c.tar.gz
tar -xzf 4.21c.tar.gz
cd AFLplusplus-4.21c
make distrib
sudo make install
```

### Build with AFL++

```bash
./tests/fuzz/scripts/build_afl.sh
```

Output:
```
[+] Building mTLS library with AFL++ instrumentation
    Build directory: build_afl
[+] Using afl-clang-fast
[+] Configuring CMake with AFL++ instrumentation
[+] Building library and fuzzing harnesses
[+] Verifying AFL++ instrumentation
  ✓ tests/fuzz_oversized_sans is instrumented
  ✓ tests/test_identity is instrumented
[+] Build complete!
    Instrumented: 2 binaries
```

### Run AFL++ Fuzzing

```bash
# Fuzz with 4 workers for 1 hour
./tests/fuzz/scripts/run_afl.sh -t fuzz_oversized_sans -w 4 -d 3600

# Fuzz with 8 workers (no time limit)
./tests/fuzz/scripts/run_afl.sh -t fuzz_oversized_sans -w 8

# Monitor progress
watch -n 5 'afl-whatsup -s build_afl/afl_output/fuzz_oversized_sans'
```

Output:
```
========================================
  AFL++ Fuzzing Configuration
========================================
  Target:       fuzz_oversized_sans
  Binary:       /path/to/build_afl/tests/fuzz_oversized_sans
  Workers:      4
  Input Dir:    /path/to/tests/fuzz/corpus/fuzz_oversized_sans
  Output Dir:   /path/to/build_afl/afl_output/fuzz_oversized_sans
  Memory Limit: none
========================================

[+] Found 3 corpus files
[+] Starting 4 AFL++ fuzzing workers...

[Worker 0 - Main] afl-fuzz -M fuzzer00 -i ... -p fast -- ...
[Worker 1] afl-fuzz -S fuzzer01 -i ... -p explore -- ...
[Worker 2] afl-fuzz -S fuzzer02 -i ... -p exploit -- ...
[Worker 3] afl-fuzz -S fuzzer03 -i ... -p coe -- ...

[+] All workers started

Monitor progress:
  - Status:      afl-whatsup -s build_afl/afl_output/fuzz_oversized_sans
  - Live view:   watch -n 5 'afl-whatsup -s build_afl/afl_output/fuzz_oversized_sans'
  - Worker logs: tail -f build_afl/afl_output/fuzz_oversized_sans/worker_*.log

Press Ctrl+C to stop fuzzing
```

### AFL++ Power Schedules

Different workers use different strategies:
- **fast**: Prioritize quick paths
- **explore**: Explore new coverage
- **exploit**: Exploit known interesting paths
- **coe**: Cut-Off Exponential schedule

## Corpus Management

### Minimize Corpus

Remove redundant inputs while preserving coverage:

```bash
./tests/fuzz/scripts/manage_corpus.sh minimize \
  -t fuzz_san_validation \
  -i build_afl/afl_output/fuzz_san_validation \
  -o build_afl/afl_minimized/fuzz_san_validation
```

Output:
```
[+] Minimizing corpus for fuzz_san_validation
    Input:  build_afl/afl_output/fuzz_san_validation
    Output: build_afl/afl_minimized/fuzz_san_validation

[*] Input corpus: 1234 files
[*] Running: afl-cmin -i ... -o ... -- ...

[+] Corpus minimization complete
    Before: 1234 files
    After:  123 files
    Saved:  1111 files (90% reduction)
```

### Minimize Test Case

Reduce individual input size:

```bash
./tests/fuzz/scripts/manage_corpus.sh tmin \
  -t fuzz_address_parsing \
  -i crash-abc123def456 \
  -o crash-abc123def456.min
```

Output:
```
[+] Minimizing test case for fuzz_address_parsing
    Input:  crash-abc123def456 (512 bytes)
    Output: crash-abc123def456.min

[*] Running: afl-tmin -i ... -o ... -- ...

[+] Test case minimization complete
    Before: 512 bytes
    After:  8 bytes
    Saved:  504 bytes (98% reduction)
```

### Merge Corpuses

Combine corpuses from multiple AFL++ workers:

```bash
./tests/fuzz/scripts/manage_corpus.sh merge \
  -t fuzz_san_validation \
  -o build_afl/afl_merged/fuzz_san_validation
```

### Analyze Corpus

Get coverage statistics:

```bash
./tests/fuzz/scripts/manage_corpus.sh analyze \
  -t fuzz_san_validation \
  -i build_afl/afl_output/fuzz_san_validation
```

Output:
```
[+] Analyzing corpus for fuzz_san_validation
    Input:  build_afl/afl_output/fuzz_san_validation

Corpus Statistics:
  Queue files:  1234
  Crashes:      2
  Hangs:        0

Coverage Analysis:
  Analyzing 1234 files...
  Edge coverage: 456 edges

Crashes found:
  - id:000000,sig:06,src:000123,op:havoc,rep:2 (8 bytes)
  - id:000001,sig:11,src:000456,op:splice,rep:4 (42 bytes)
```

### Export/Import Corpus

```bash
# Export corpus to tarball
./tests/fuzz/scripts/manage_corpus.sh export \
  -t fuzz_san_validation \
  -o fuzz_san_validation_corpus_20231219.tar.gz

# Import corpus from tarball
./tests/fuzz/scripts/manage_corpus.sh import \
  -t fuzz_san_validation \
  -i fuzz_san_validation_corpus_20231219.tar.gz
```

## Continuous Integration

### GitHub Actions Workflow

The `.github/workflows/fuzzing.yml` workflow runs:
- **Nightly**: Every day at 2 AM UTC
- **Manual**: Via workflow_dispatch
- **Matrix**: All 4 fuzzing targets in parallel
- **Duration**: 1 hour per target (configurable)

### Workflow Features

1. **Crash Detection**: Automatically detects crashes, timeouts, and leaks
2. **Artifact Upload**: Saves crash inputs for 90 days
3. **Issue Creation**: Creates GitHub issues for discovered crashes
4. **Statistics**: Reports coverage and execution stats

### Manual Trigger

```bash
# Trigger via GitHub CLI
gh workflow run fuzzing.yml

# Trigger specific target with custom duration
gh workflow run fuzzing.yml \
  -f target=fuzz_address_parsing \
  -f duration=7200
```

### Viewing Results

1. Navigate to **Actions** tab
2. Select **Fuzzing** workflow
3. View run results and download artifacts
4. Check **Issues** for auto-created bug reports

## Findings and Triage

### FUZZING_FINDINGS.md

All fuzzing discoveries are tracked in `tests/fuzz/FUZZING_FINDINGS.md`:

- **PERF-001**: Slow address parsing (`.local` TLD) - **RESOLVED**
- **FALSE-001**: False positive leak detection - **RESOLVED**

### Triage Process

When a crash is found:

1. **Reproduce locally**:
   ```bash
   ./fuzz_target crash-abc123def456
   ```

2. **Get stack trace**:
   ```bash
   gdb --args ./fuzz_target crash-abc123def456
   (gdb) run
   (gdb) bt
   ```

3. **Analyze with AddressSanitizer**:
   ```bash
   ASAN_OPTIONS=verbosity=2:symbolize=1 ./fuzz_target crash-abc123def456
   ```

4. **Minimize input**:
   ```bash
   ./tests/fuzz/scripts/manage_corpus.sh tmin -t <target> -i crash-abc123def456
   ```

5. **Create bug report** in `FUZZING_FINDINGS.md`

6. **Fix issue** and add regression test

7. **Verify fix**:
   ```bash
   ./fuzz_target -runs=1000000 crash-abc123def456
   ```

### Severity Classification

- **CRITICAL**: Memory corruption (buffer overflow, use-after-free)
- **HIGH**: DoS potential (infinite loop, excessive memory)
- **MEDIUM**: Logic errors (incorrect validation)
- **LOW**: Performance regression
- **FALSE**: Tool false positive

## Performance

### PERF-001: DNS Timeout Fix

Fuzzing discovered that `.local` TLD caused 25-second timeouts:

**Before fix**:
```
#2659   DONE   cov: 123 ft: 456 corp: 45/678b lim: 29 exec/s: 94 rss: 67Mb
       SLOW UNIT: 1
```
- **Execution rate**: 94 exec/s
- **Total runs**: 2,659 in 28 seconds

**After fix**:
```
#15426  DONE   cov: 134 ft: 489 corp: 52/734b lim: 29 exec/s: 1402 rss: 68Mb
```
- **Execution rate**: 1,402 exec/s
- **Total runs**: 15,426 in 11 seconds
- **Improvement**: **15x faster**

**Solution**: Added `validate_hostname()` to reject `.local` TLD before DNS resolution.

### Expected Performance

| Target | Exec/s (typical) | Corpus Size | Coverage |
|--------|------------------|-------------|----------|
| fuzz_san_validation | 1,000-2,000 | 20-50 files | ~150 edges |
| fuzz_pem_parsing | 500-1,000 | 10-30 files | ~200 edges |
| fuzz_certificate_validation | 200-500 | 15-40 files | ~250 edges |
| fuzz_address_parsing | 1,000-1,500 | 15-35 files | ~100 edges |

**Note**: Execution rate depends on CPU, corpus size, and input complexity.

## Troubleshooting

### Build Issues

**Error**: `Fuzzing requires Clang compiler`
```bash
# Solution: Use Clang
CC=clang cmake -DMTLS_ENABLE_FUZZING=ON ..
```

**Error**: `Target binary is not AFL++ instrumented`
```bash
# Solution: Rebuild with AFL++ compiler
./tests/fuzz/scripts/build_afl.sh
```

### Runtime Issues

**Error**: `ERROR: libFuzzer: out-of-memory`
```bash
# Solution: Limit memory usage
./fuzz_target -rss_limit_mb=512 corpus/
```

**Error**: `ALARM: working on the last Unit for 25 seconds`
```bash
# Solution: Reduce timeout
./fuzz_target -timeout=10 corpus/
```

**Error**: `ERROR: libFuzzer: deadly signal`
```bash
# Solution: This is a real crash! Investigate with:
ASAN_OPTIONS=verbosity=2 ./fuzz_target crash-<hash>
```

### Slow Performance

If fuzzing is slow (<100 exec/s):
1. Check for slow units: Look for `SLOW UNIT` in output
2. Reduce timeout: Use `-timeout=5`
3. Check corpus: Large inputs slow fuzzing
4. Profile target: Use `perf` to find bottlenecks

### CI Failures

**Issue**: Fuzzing workflow times out
- **Solution**: Reduce duration in workflow_dispatch input

**Issue**: No crashes found but workflow fails
- **Solution**: Check workflow logs for build errors

## Best Practices

1. **Run fuzzing regularly**: Enable nightly CI runs
2. **Monitor crashes**: Check GitHub issues for auto-created bugs
3. **Minimize crashes**: Always minimize before investigating
4. **Update corpus**: Add interesting inputs to seed corpus
5. **Fix promptly**: Treat fuzzing crashes as security vulnerabilities
6. **Regression tests**: Add fixed crashes as regression tests
7. **Document findings**: Update FUZZING_FINDINGS.md

## References

- **libFuzzer**: https://llvm.org/docs/LibFuzzer.html
- **AFL++**: https://github.com/AFLplusplus/AFLplusplus
- **AddressSanitizer**: https://github.com/google/sanitizers
- **OSS-Fuzz**: https://google.github.io/oss-fuzz/

## Contact

For questions or issues:
- Create GitHub issue with label `fuzzing`
- Check existing issues: https://github.com/your-repo/issues?q=label%3Afuzzing
